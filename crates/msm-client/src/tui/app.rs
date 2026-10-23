//! Panel state: what is on screen, what is selected, and what a key press does.
//!
//! Nothing here touches the terminal, so every screen can be driven headlessly.

use std::collections::{BTreeSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::{Duration, Instant};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use msm_protocol::commands::Command;

use super::worker::{self, HISTORY, Msg, Sample};
use crate::mdns::Discovered;
use crate::sshkey::SshKey;
use crate::store::{self, NodeRecord};

/// How often the detail screen refreshes its node.
const REFRESH: Duration = Duration::from_secs(2);

/// Which screen is showing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Nodes,
    Pair,
    Detail,
    Logs,
}

/// The state of one node as the panel knows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Unknown,
    Running,
    Ok,
    Failed,
}

impl Status {
    pub fn text(self) -> &'static str {
        match self {
            Self::Unknown => "-",
            Self::Running => "running",
            Self::Ok => "ok",
            Self::Failed => "failed",
        }
    }
}

/// One row of the node list.
pub struct NodeView {
    pub record: NodeRecord,
    pub status: Status,
    pub history: VecDeque<Sample>,
    pub last: String,
    pub updated: Option<Instant>,
    /// What the node is doing right now, e.g. `installing htop`.
    pub doing: Option<String>,
}

impl NodeView {
    pub(crate) fn new(record: NodeRecord) -> Self {
        Self {
            record,
            status: Status::Unknown,
            history: VecDeque::new(),
            last: String::new(),
            updated: None,
            doing: None,
        }
    }

    /// Label, or the node id when the node was paired without a name.
    pub fn name(&self) -> &str {
        if self.record.label.is_empty() {
            &self.record.node_id
        } else {
            &self.record.label
        }
    }
}

/// The pairing screen's inputs.
#[derive(Debug, Default)]
pub struct PairForm {
    pub address: String,
    pub code: String,
    pub focus: Focus,
    pub discovered: Vec<Discovered>,
    pub chosen: usize,
    pub busy: bool,
    /// What the busy work is: `browsing for nodes`, `pairing with host:port`.
    pub working: String,
    /// When it started, for the elapsed clock next to the bar.
    pub since: Option<Instant>,
    /// Set when Enter arrives while discovery is still running. The answer then
    /// picks the first result instead of making the operator press it again.
    pub pick_when_found: bool,
}

/// One user command in flight, across every target it was sent to.
pub struct Busy {
    pub id: u64,
    /// Protocol name, printed with the result: `pkg.update`.
    pub what: String,
    /// Present participle, printed while it runs: `updating packages`.
    pub label: String,
    pub started: Instant,
    pub total: usize,
    pub remaining: usize,
}

impl Busy {
    pub fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }

    pub fn done(&self) -> usize {
        self.total.saturating_sub(self.remaining)
    }
}

/// Present participle for a request, shown while it runs.
pub fn progress_label(request: &Command) -> String {
    match request {
        Command::PkgUpdate => "updating packages".to_string(),
        Command::PkgInstall(name) => format!("installing {name}"),
        Command::SvcRestart(unit) if unit.is_empty() || unit == "self" || unit == "msm-node" => {
            "restarting the agent".to_string()
        }
        Command::SvcRestart(unit) => format!("restarting {unit}"),
        Command::HostReboot(_) => "rebooting".to_string(),
        Command::MetricsSample => "reading metrics".to_string(),
        Command::LogsTail(_) => "reading logs".to_string(),
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum Focus {
    #[default]
    Address,
    Code,
}

/// The log screen's content.
#[derive(Debug, Default)]
pub struct LogsView {
    pub node: Option<String>,
    pub lines: Vec<String>,
    pub waiting: bool,
}

/// A one-line prompt, used for the install name.
pub struct Prompt {
    pub title: String,
    pub value: String,
}

/// A program to run with the terminal handed over.
#[derive(Debug)]
pub struct Shell {
    pub program: String,
    pub args: Vec<String>,
}

/// The whole panel.
pub struct App {
    pub state_dir: PathBuf,
    pub screen: Screen,
    pub nodes: Vec<NodeView>,
    pub selected: usize,
    pub marked: BTreeSet<String>,
    pub status: String,
    pub pair: PairForm,
    pub logs: LogsView,
    pub prompt: Option<Prompt>,
    pub shell: Option<Shell>,
    pub should_quit: bool,
    pub detail_refreshed: Option<Instant>,
    pub busy: Option<Busy>,
    next_action: u64,
    tx: Sender<Msg>,
    rx: Receiver<Msg>,
}

impl App {
    /// Build the panel from the state directory.
    pub fn new(state_dir: &Path) -> msm_protocol::Result<Self> {
        let (tx, rx) = channel();
        let records = store::load_nodes(state_dir)?;

        Ok(Self {
            state_dir: state_dir.to_path_buf(),
            screen: Screen::Nodes,
            nodes: records.into_iter().map(NodeView::new).collect(),
            selected: 0,
            marked: BTreeSet::new(),
            status: String::new(),
            pair: PairForm::default(),
            logs: LogsView::default(),
            prompt: None,
            shell: None,
            should_quit: false,
            detail_refreshed: None,
            busy: None,
            next_action: 1,
            tx,
            rx,
        })
    }

    /// Drain finished work and refresh the detail screen when it is due.
    pub fn tick(&mut self) {
        while let Ok(message) = self.rx.try_recv() {
            self.apply(message);
        }

        if self.screen == Screen::Detail {
            let due = self
                .detail_refreshed
                .map(|at| at.elapsed() >= REFRESH)
                .unwrap_or(true);
            if due
                && let Some(record) = self.current().map(|view| view.record.clone())
            {
                self.detail_refreshed = Some(Instant::now());
                worker::metrics(self.state_dir.clone(), record, self.tx.clone());
            }
        }
    }

    /// Apply one finished piece of work. Public in the crate so the tests can
    /// feed answers without a network.
    pub(crate) fn apply(&mut self, message: Msg) {
        match message {
            Msg::Started { node, id } => {
                self.mark(&node, Status::Running);
                let doing = self
                    .busy
                    .as_ref()
                    .filter(|busy| busy.id == id)
                    .map(|busy| busy.label.clone());
                if let Some(view) = self.nodes.iter_mut().find(|v| v.record.node_id == node) {
                    view.doing = doing;
                }
            }
            Msg::Finished {
                node,
                id,
                ok,
                summary,
            } => {
                // `busy` means another command held the node, not that the node
                // is unhealthy; the earlier status stands.
                let busy = !ok && summary.starts_with("busy");
                if ok {
                    self.mark(&node, Status::Ok);
                } else if !busy {
                    self.mark(&node, Status::Failed);
                }
                if let Some(view) = self.nodes.iter_mut().find(|v| v.record.node_id == node) {
                    view.last = summary.clone();
                    view.updated = Some(Instant::now());
                    view.doing = None;
                }

                // A metrics or log refresh must not wipe the last thing the
                // operator did; it only speaks up when it fails.
                if id == worker::BACKGROUND {
                    if !ok {
                        self.status = format!("error: {summary}");
                    }
                    return;
                }

                let mut what = None;
                if let Some(current) = self.busy.as_mut()
                    && current.id == id
                {
                    current.remaining = current.remaining.saturating_sub(1);
                    what = Some(current.what.clone());
                    if current.remaining == 0 {
                        self.busy = None;
                    }
                }

                self.status = match what {
                    Some(what) if ok => format!("{what}: {summary}"),
                    Some(what) => format!("{what}: error: {summary}"),
                    None if ok => summary,
                    None => format!("error: {summary}"),
                };
            }
            Msg::Sample { node, sample } => {
                if let Some(view) = self.nodes.iter_mut().find(|v| v.record.node_id == node) {
                    if view.history.len() == HISTORY {
                        view.history.pop_front();
                    }
                    view.history.push_back(sample);
                    view.updated = Some(Instant::now());
                    if view.status != Status::Running {
                        view.status = Status::Ok;
                    }
                }
            }
            Msg::Logs { node, lines } => {
                if self.logs.node.as_deref() == Some(node.as_str()) {
                    self.logs.lines = lines;
                    self.logs.waiting = false;
                }
            }
            Msg::Paired { record, warning } => {
                self.pair.busy = false;
                self.pair.since = None;
                self.pair.address.clear();
                self.pair.code.clear();
                self.pair.focus = Focus::Address;
                let name = if record.label.is_empty() {
                    record.node_id.clone()
                } else {
                    record.label.clone()
                };
                self.nodes.push(NodeView::new(*record));
                self.selected = self.nodes.len() - 1;
                self.screen = Screen::Nodes;
                self.status = match warning {
                    Some(warning) => format!("paired with {name}; {warning}"),
                    None => format!("paired with {name}, SSH key installed"),
                };
            }
            Msg::Discovered(found) => {
                self.pair.busy = false;
                self.pair.since = None;
                self.pair.chosen = 0;
                self.status = if found.is_empty() {
                    "no nodes answered on the LAN or tailnet; is msm-node running?".to_string()
                } else {
                    format!("{} node(s) discovered", found.len())
                };
                self.pair.discovered = found;
                if self.pair.pick_when_found {
                    self.pair.pick_when_found = false;
                    if self.pair.focus == Focus::Address {
                        self.on_pair_enter();
                    }
                }
            }
            Msg::Failed(reason) => {
                self.pair.busy = false;
                self.pair.since = None;
                self.logs.waiting = false;
                self.status = format!("error: {reason}");
            }
        }
    }

    fn mark(&mut self, node_id: &str, status: Status) {
        if let Some(view) = self.nodes.iter_mut().find(|v| v.record.node_id == node_id) {
            view.status = status;
        }
    }

    /// The highlighted node.
    pub fn current(&self) -> Option<&NodeView> {
        self.nodes.get(self.selected)
    }

    /// Nodes an action applies to: the marked set, or the highlighted node.
    pub fn targets(&self) -> Vec<NodeRecord> {
        if self.marked.is_empty() {
            return self
                .current()
                .map(|view| vec![view.record.clone()])
                .unwrap_or_default();
        }
        self.nodes
            .iter()
            .filter(|view| self.marked.contains(&view.record.node_id))
            .map(|view| view.record.clone())
            .collect()
    }

    fn move_by(&mut self, delta: isize) {
        if self.nodes.is_empty() {
            return;
        }
        let next = self.selected as isize + delta;
        self.selected = next.clamp(0, self.nodes.len() as isize - 1) as usize;
    }

    fn toggle_mark(&mut self) {
        if let Some(view) = self.current() {
            let id = view.record.node_id.clone();
            if !self.marked.remove(&id) {
                self.marked.insert(id);
            }
        }
    }

    /// Run one request against every target, in its own thread.
    pub(crate) fn start(&mut self, request: Command) {
        let what = request.describe();
        let label = progress_label(&request);
        let targets = self.targets();
        if targets.is_empty() {
            self.status = "no node selected".to_string();
            return;
        }

        let id = self.next_action;
        self.next_action += 1;
        self.busy = Some(Busy {
            id,
            what,
            label,
            started: Instant::now(),
            total: targets.len(),
            remaining: targets.len(),
        });

        for record in targets {
            worker::action(
                self.state_dir.clone(),
                record,
                request.clone(),
                id,
                self.tx.clone(),
            );
        }
    }

    /// Open the log screen for the highlighted node and fetch its tail.
    pub fn open_logs(&mut self) {
        let Some(view) = self.current() else {
            return;
        };
        let record = view.record.clone();
        let name = view.name().to_string();
        self.logs = LogsView {
            node: Some(record.node_id.clone()),
            lines: Vec::new(),
            waiting: true,
        };
        self.screen = Screen::Logs;
        self.status = format!("logs from {name}");
        worker::logs(self.state_dir.clone(), record, 200, self.tx.clone());
    }

    /// Build the SSH or SFTP hand-over for the highlighted node.
    fn open_shell(&mut self, sftp: bool) {
        let Some(view) = self.current() else {
            return;
        };
        let record = view.record.clone();
        let key = SshKey::path(&self.state_dir);
        let known_hosts = self.state_dir.join("ssh").join("known_hosts");

        let mut args = vec![
            "-i".to_string(),
            key.display().to_string(),
            "-o".to_string(),
            "IdentitiesOnly=yes".to_string(),
            "-o".to_string(),
            "StrictHostKeyChecking=accept-new".to_string(),
            "-o".to_string(),
            format!("UserKnownHostsFile={}", known_hosts.display()),
        ];
        // sftp and ssh disagree on the port flag.
        args.push(if sftp { "-P" } else { "-p" }.to_string());
        args.push(record.ssh_port.to_string());
        args.push(format!("{}@{}", record.ssh_user, record.host));

        self.shell = Some(Shell {
            program: if sftp { "sftp" } else { "ssh" }.to_string(),
            args,
        });
        self.status = format!(
            "{} {}@{}",
            if sftp { "sftp" } else { "ssh" },
            record.ssh_user,
            record.host
        );
    }

    /// Apply one key press.
    pub fn on_key(&mut self, key: KeyEvent) {
        if key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('c'))
        {
            self.should_quit = true;
            return;
        }

        if self.prompt.is_some() {
            self.on_prompt_key(key);
            return;
        }

        if key.code == KeyCode::Char('q') {
            self.should_quit = true;
            return;
        }

        match self.screen {
            Screen::Nodes => self.on_nodes_key(key),
            Screen::Pair => self.on_pair_key(key),
            Screen::Detail => self.on_detail_key(key),
            Screen::Logs => self.on_logs_key(key),
        }
    }

    fn on_nodes_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('j') | KeyCode::Down => self.move_by(1),
            KeyCode::Char('k') | KeyCode::Up => self.move_by(-1),
            KeyCode::Char(' ') => self.toggle_mark(),
            KeyCode::Char('a') => {
                if self.marked.len() == self.nodes.len() {
                    self.marked.clear();
                } else {
                    self.marked = self.nodes.iter().map(|v| v.record.node_id.clone()).collect();
                }
            }
            KeyCode::Char('p') => {
                self.screen = Screen::Pair;
                self.pair.focus = Focus::Address;
                self.status = "press d to discover, or type an address".to_string();
            }
            KeyCode::Enter => {
                if self.current().is_some() {
                    self.detail_refreshed = None;
                    self.screen = Screen::Detail;
                } else {
                    self.status = "no paired nodes; press p to pair with one".to_string();
                }
            }
            KeyCode::Char('u') => self.start(Command::PkgUpdate),
            KeyCode::Char('i') => self.prompt = Some(Prompt {
                title: "install package".to_string(),
                value: String::new(),
            }),
            KeyCode::Char('r') => self.start(Command::SvcRestart(String::new())),
            KeyCode::Char('l') => self.open_logs(),
            KeyCode::Char('s') => self.open_shell(false),
            KeyCode::Char('f') => self.open_shell(true),
            KeyCode::Char('g') => {
                for record in self.targets() {
                    worker::metrics(self.state_dir.clone(), record, self.tx.clone());
                }
            }
            _ => {}
        }
    }

    fn on_detail_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc | KeyCode::Char('h') | KeyCode::Left => {
                self.screen = Screen::Nodes;
                self.detail_refreshed = None;
            }
            KeyCode::Char('u') => self.start(Command::PkgUpdate),
            KeyCode::Char('i') => self.prompt = Some(Prompt {
                title: "install package".to_string(),
                value: String::new(),
            }),
            KeyCode::Char('r') => self.start(Command::SvcRestart(String::new())),
            KeyCode::Char('l') => self.open_logs(),
            KeyCode::Char('s') => self.open_shell(false),
            KeyCode::Char('f') => self.open_shell(true),
            KeyCode::Char('g') => {
                self.detail_refreshed = None;
            }
            _ => {}
        }
    }

    fn on_logs_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc | KeyCode::Left | KeyCode::Char('h') => {
                self.screen = if self.nodes.is_empty() {
                    Screen::Nodes
                } else {
                    Screen::Detail
                };
            }
            KeyCode::Char('r') => {
                if let Some(node) = self.logs.node.clone()
                    && let Some(view) = self.nodes.iter().find(|v| v.record.node_id == node)
                {
                    self.logs.waiting = true;
                    worker::logs(
                        self.state_dir.clone(),
                        view.record.clone(),
                        200,
                        self.tx.clone(),
                    );
                }
            }
            _ => {}
        }
    }

    fn on_pair_key(&mut self, key: KeyEvent) {
        let focused = self.pair.focus;
        match key.code {
            KeyCode::Esc => {
                self.screen = Screen::Nodes;
                self.pair.pick_when_found = false;
                self.pair.busy = false;
                self.pair.since = None;
            }
            KeyCode::Tab | KeyCode::BackTab => {
                self.pair.focus = match focused {
                    Focus::Address => Focus::Code,
                    Focus::Code => Focus::Address,
                };
            }
            KeyCode::Char('d') if self.pair.address.is_empty() && focused == Focus::Address => {
                self.pair.busy = true;
                self.pair.working = "browsing the LAN and tailnet".to_string();
                self.pair.since = Some(Instant::now());
                self.status = "browsing mDNS and the tailnet for nodes".to_string();
                worker::discover(self.state_dir.clone(), self.tx.clone());
            }
            // Enter always has an effect: while discovery is still running it
            // is remembered and applied to the first answer, so a fast Enter
            // after `d` no longer disappears.
            KeyCode::Enter if self.pair.busy && focused == Focus::Address => {
                self.pair.pick_when_found = true;
                self.status = "discovering; the first node found will be chosen".to_string();
            }
            KeyCode::Up if focused == Focus::Address && !self.pair.discovered.is_empty() => {
                let count = self.pair.discovered.len();
                self.pair.chosen = (self.pair.chosen + count - 1) % count;
            }
            KeyCode::Down if focused == Focus::Address && !self.pair.discovered.is_empty() => {
                self.pair.chosen = (self.pair.chosen + 1) % self.pair.discovered.len();
            }
            KeyCode::Backspace => match focused {
                Focus::Address => {
                    self.pair.address.pop();
                }
                Focus::Code => {
                    self.pair.code.pop();
                }
            },
            KeyCode::Enter => self.on_pair_enter(),
            KeyCode::Char(c) => match focused {
                Focus::Address => self.pair.address.push(c),
                Focus::Code => self.pair.code.push(c),
            },
            _ => {}
        }
    }

    fn on_pair_enter(&mut self) {
        match self.pair.focus {
            Focus::Address => {
                if self.pair.address.is_empty() {
                    if self.pair.busy {
                        self.pair.pick_when_found = true;
                        self.status = "discovering; the first node found will be chosen".to_string();
                        return;
                    }
                    if let Some(found) = self.pair.discovered.get(self.pair.chosen) {
                        self.pair.address = found.endpoint();
                        self.pair.focus = Focus::Code;
                        self.status = format!("address set to {}", self.pair.address);
                    } else {
                        self.status = "type host:port or press d to discover".to_string();
                    }
                } else {
                    self.pair.focus = Focus::Code;
                }
            }
            Focus::Code => {
                if self.pair.address.is_empty() || self.pair.code.is_empty() || self.pair.busy {
                    return;
                }
                let address = self.pair.address.clone();
                let code = self.pair.code.clone();
                self.pair.busy = true;
                self.pair.working = format!("pairing with {address}");
                self.pair.since = Some(Instant::now());
                self.status = "pairing".to_string();

                // A discovered node carries its own label and pin; use the label
                // so the list is readable after pairing.
                let label = self
                    .pair
                    .discovered
                    .iter()
                    .find(|found| found.endpoint() == address)
                    .map(|found| found.label.clone())
                    .unwrap_or_default();

                worker::pair(
                    self.state_dir.clone(),
                    address,
                    code,
                    label,
                    self.tx.clone(),
                );
            }
        }
    }

    fn on_prompt_key(&mut self, key: KeyEvent) {
        let Some(prompt) = self.prompt.as_mut() else {
            return;
        };
        match key.code {
            KeyCode::Esc => self.prompt = None,
            KeyCode::Backspace => {
                prompt.value.pop();
            }
            KeyCode::Char(c) => prompt.value.push(c),
            KeyCode::Enter => {
                let name = prompt.value.trim().to_string();
                self.prompt = None;
                if name.is_empty() {
                    self.status = "no package name".to_string();
                    return;
                }
                self.start(Command::PkgInstall(name.clone()));
            }
            _ => {}
        }
    }

}
