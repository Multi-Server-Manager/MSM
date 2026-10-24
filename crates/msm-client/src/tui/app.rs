//! Panel state: what is on screen, what is selected, and what a key press does.
//!
//! Nothing here touches the terminal, so every screen can be driven headlessly.

use std::collections::{BTreeSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::{Duration, Instant};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use msm_protocol::commands::{Command, valid_account};
use msm_protocol::messages::Setup;

use super::worker::{self, HISTORY, Msg, Sample};
use crate::mdns::Discovered;
use crate::session::{self, Event as SessionEvent, Input as SessionInput, Session as SshSession};
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
    /// A live SSH session drawn inside the panel.
    Session,
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
#[derive(Debug)]
pub struct PairForm {
    pub address: String,
    pub code: String,
    /// Name to store for the node; the discovered label is offered first.
    pub label: String,
    /// Account the console's key is installed for.
    pub ssh_user: String,
    /// Port the console dials for SSH.
    pub ssh_port: String,
    /// Account the node runs its commands as.
    pub run_as: String,
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
        Command::NodeSetup(_) => "changing the node's setup".to_string(),
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum Focus {
    #[default]
    Address,
    Code,
    Label,
    SshUser,
    SshPort,
    RunAs,
}

impl Focus {
    /// The field Tab moves to, in the order the questions are asked.
    pub fn next(self) -> Self {
        match self {
            Self::Address => Self::Code,
            Self::Code => Self::Label,
            Self::Label => Self::SshUser,
            Self::SshUser => Self::SshPort,
            Self::SshPort => Self::RunAs,
            Self::RunAs => Self::Address,
        }
    }
}

/// One field of the edit dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EditField {
    Label,
    Host,
    SshUser,
    SshPort,
    RunAs,
}

impl EditField {
    pub const ALL: [Self; 5] = [
        Self::Label,
        Self::Host,
        Self::SshUser,
        Self::SshPort,
        Self::RunAs,
    ];

    fn next(self) -> Self {
        let index = Self::ALL.iter().position(|field| *field == self).unwrap_or(0);
        Self::ALL[(index + 1) % Self::ALL.len()]
    }
}

/// The edit dialog: everything about a node a human might rename or repoint.
#[derive(Debug)]
pub struct EditForm {
    /// The record as it was when the dialog opened.
    pub original: NodeRecord,
    pub label: String,
    pub host: String,
    pub ssh_user: String,
    pub ssh_port: String,
    pub run_as: String,
    pub focus: EditField,
}

impl EditForm {
    pub fn for_record(record: NodeRecord) -> Self {
        Self {
            label: record.label.clone(),
            host: record.host.clone(),
            ssh_user: record.ssh_user.clone(),
            ssh_port: record.ssh_port.to_string(),
            run_as: record.run_as.clone(),
            original: record,
            focus: EditField::Label,
        }
    }

    pub fn value(&self, field: EditField) -> &str {
        match field {
            EditField::Label => &self.label,
            EditField::Host => &self.host,
            EditField::SshUser => &self.ssh_user,
            EditField::SshPort => &self.ssh_port,
            EditField::RunAs => &self.run_as,
        }
    }

    fn value_mut(&mut self, field: EditField) -> &mut String {
        match field {
            EditField::Label => &mut self.label,
            EditField::Host => &mut self.host,
            EditField::SshUser => &mut self.ssh_user,
            EditField::SshPort => &mut self.ssh_port,
            EditField::RunAs => &mut self.run_as,
        }
    }
}

/// A live SSH session and the emulator that draws it.
pub struct SessionView {
    pub ssh: SshSession,
    pub parser: vt100::Parser,
    pub title: String,
    /// Where Esc returns to when the session ends.
    pub origin: Screen,
    /// The size the remote was last told about.
    pub size: (u16, u16),
    /// Set once the remote hung up; the screen keeps its last frame.
    pub closed: Option<String>,
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

impl Default for PairForm {
    fn default() -> Self {
        Self {
            address: String::new(),
            code: String::new(),
            label: String::new(),
            // Blank means "the node's own answer": the node knows which
            // account it can command as, the console does not.
            ssh_user: String::new(),
            ssh_port: String::new(),
            run_as: String::new(),
            focus: Focus::Address,
            discovered: Vec::new(),
            chosen: 0,
            busy: false,
            working: String::new(),
            since: None,
            pick_when_found: false,
        }
    }
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
    /// The live SSH session, when one is open.
    pub session: Option<SessionView>,
    /// The edit dialog, when it is open.
    pub edit: Option<EditForm>,
    /// Last drawn size, so a new session and a resize both start correct.
    pub panel: (u16, u16),
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
            session: None,
            edit: None,
            panel: (80, 24),
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

        self.drain_session();

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
            Msg::Configured { record, warning } => {
                if let Some(view) = self
                    .nodes
                    .iter_mut()
                    .find(|v| v.record.node_id == record.node_id)
                {
                    view.record = *record; // the answers the node confirmed
                }
                self.status = match warning {
                    Some(warning) => format!("saved; {warning}"),
                    None => "saved; the node uses the new settings".to_string(),
                };
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

    /// Move bytes from the SSH worker into the emulator, and notice a hangup.
    fn drain_session(&mut self) {
        let mut closed = None;
        if let Some(view) = self.session.as_mut() {
            loop {
                match view.ssh.events.try_recv() {
                    Ok(SessionEvent::Opened) => {}
                    Ok(SessionEvent::Data(bytes)) => view.parser.process(&bytes),
                    Ok(SessionEvent::Closed(reason)) => {
                        closed = Some(reason);
                        break;
                    }
                    Err(_) => break,
                }
            }
        }
        if let Some(reason) = closed {
            if let Some(view) = self.session.as_mut() {
                view.closed = Some(reason.clone());
            }
            self.status = reason;
        }
    }

    /// Tell the session how big the screen is; a resize reaches the remote.
    pub fn set_panel_size(&mut self, width: u16, height: u16) {
        self.panel = (width, height);
        let (cols, rows) = session_size(self.panel);
        if let Some(view) = self.session.as_mut()
            && view.size != (cols, rows)
        {
            view.size = (cols, rows);
            view.parser.set_size(nonzero(rows), nonzero(cols));
            let _ = view.ssh.input.send(SessionInput::Resize(cols, rows));
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

    /// Open an SSH login inside the panel, authenticated with the MSM key.
    ///
    /// Nothing is handed over: the session draws in the same screen and the
    /// keys are forwarded to the remote, except Ctrl-\ which closes it.
    fn open_ssh(&mut self) {
        let Some(view) = self.current() else {
            return;
        };
        let record = view.record.clone();
        let name = view.name().to_string();

        // The key must exist before the thread reads it.
        if let Err(err) = SshKey::load_or_create(&self.state_dir) {
            self.status = format!("error: cannot prepare the SSH key: {err}");
            return;
        }

        let (cols, rows) = session_size(self.panel);
        let ssh = session::start(session::Start {
            host: record.host.clone(),
            port: record.ssh_port,
            user: record.ssh_user.clone(),
            key: SshKey::path(&self.state_dir),
            known_hosts: session::Start::known_hosts_for(&self.state_dir),
            cols,
            rows,
            label: name.clone(),
        });

        self.session = Some(SessionView {
            ssh,
            parser: vt100::Parser::new(nonzero(rows), nonzero(cols), 2000),
            title: format!("{}@{}", record.ssh_user, record.host),
            origin: self.screen,
            size: (cols, rows),
            closed: None,
        });
        self.screen = Screen::Session;
        self.status = format!("ssh {}@{}:{}", record.ssh_user, record.host, record.ssh_port);
    }

    /// Close the session and return to where it was opened from.
    fn close_session(&mut self) {
        if let Some(view) = self.session.take() {
            let _ = view.ssh.input.send(SessionInput::Close);
            self.screen = view.origin;
        } else {
            self.screen = Screen::Nodes;
        }
        self.status = "session closed".to_string();
    }

    /// Open SFTP, which is a file browser rather than a shell: it keeps using
    /// the system client, with the key that pairing installed.
    fn open_sftp(&mut self) {
        let Some(view) = self.current() else {
            return;
        };
        let record = view.record.clone();
        let key = SshKey::path(&self.state_dir);
        let known_hosts = self.state_dir.join("ssh").join("known_hosts");

        let args = vec![
            "-i".to_string(),
            key.display().to_string(),
            "-o".to_string(),
            "IdentitiesOnly=yes".to_string(),
            "-o".to_string(),
            "StrictHostKeyChecking=accept-new".to_string(),
            "-o".to_string(),
            format!("UserKnownHostsFile={}", known_hosts.display()),
            "-P".to_string(),
            record.ssh_port.to_string(),
            format!("{}@{}", record.ssh_user, record.host),
        ];

        self.shell = Some(Shell {
            program: "sftp".to_string(),
            args,
        });
        self.status = format!("sftp {}@{}", record.ssh_user, record.host);
    }

    /// Open the edit dialog for the highlighted node.
    fn open_edit(&mut self) {
        let Some(view) = self.current() else {
            return;
        };
        self.edit = Some(EditForm::for_record(view.record.clone()));
        self.status = "tab next field  enter save  esc cancel".to_string();
    }

    /// Apply the edit dialog: store locally, then tell the node.
    fn save_edit(&mut self) {
        let Some(form) = self.edit.take() else {
            return;
        };

        let host = form.host.trim().to_string();
        if host.is_empty() {
            self.status = "the address cannot be empty".to_string();
            self.edit = Some(form);
            return;
        }
        let ssh_port: u16 = match form.ssh_port.trim().parse() {
            Ok(port) if port > 0 => port,
            _ => {
                self.status = "the ssh port must be 1-65535".to_string();
                self.edit = Some(form);
                return;
            }
        };
        let ssh_user_value = form.ssh_user.trim().to_string();
        let run_as_value = form.run_as.trim().to_string();
        for account in [ssh_user_value.as_str(), run_as_value.as_str()] {
            if !valid_account(account) {
                self.status = format!(
                    "{account:?} is not an account name (lowercase letters, digits, . _ -, starting with a letter or _)"
                );
                self.edit = Some(form);
                return;
            }
        }

        let setup = Setup {
            run_as: run_as_value,
            ssh_user: ssh_user_value,
            ssh_port,
        };
        let before = Setup {
            run_as: form.original.run_as.clone(),
            ssh_user: form.original.ssh_user.clone(),
            ssh_port: form.original.ssh_port,
        };

        let mut record = form.original.clone();
        record.label = form.label.trim().to_string();
        record.host = host;
        record.ssh_user = setup.ssh_user.clone();
        record.ssh_port = setup.ssh_port;
        record.run_as = setup.run_as.clone();

        if let Err(err) = store::save_node(&self.state_dir, record.clone()) {
            self.status = format!("error: cannot save the node: {err}");
            return;
        }
        if let Some(view) = self
            .nodes
            .iter_mut()
            .find(|v| v.record.node_id == record.node_id)
        {
            view.record = record.clone();
        }

        if setup == before {
            self.status = "saved".to_string();
            return;
        }
        self.status = "saved; telling the node".to_string();
        worker::configure(self.state_dir.clone(), record, setup, self.tx.clone());
    }

    /// Apply one key press.
    pub fn on_key(&mut self, key: KeyEvent) {
        // A live session owns the keyboard: Ctrl-C belongs to the remote, and
        // only the detach key comes back here.
        if self.screen == Screen::Session {
            self.on_session_key(key);
            return;
        }

        if self.edit.is_some() {
            self.on_edit_key(key);
            return;
        }

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

        // `q` quits every browsing screen, but it is a letter in the pairing
        // form: a label or an address may contain it.
        if key.code == KeyCode::Char('q') && self.screen != Screen::Pair {
            self.should_quit = true;
            return;
        }

        match self.screen {
            Screen::Nodes => self.on_nodes_key(key),
            Screen::Pair => self.on_pair_key(key),
            Screen::Detail => self.on_detail_key(key),
            Screen::Logs => self.on_logs_key(key),
            Screen::Session => {}
        }
    }

    /// Keys inside the session: everything goes to the remote, except Ctrl-\\
    /// (detach) and Esc after the remote hung up.
    fn on_session_key(&mut self, key: KeyEvent) {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('\\') {
            self.close_session();
            return;
        }

        let Some(view) = self.session.as_mut() else {
            self.screen = Screen::Nodes;
            return;
        };
        if view.closed.is_some() {
            if key.code == KeyCode::Esc {
                self.close_session();
            }
            return;
        }

        let bytes = session::key_bytes(key);
        if !bytes.is_empty() {
            let _ = view.ssh.input.send(SessionInput::Data(bytes));
        }
    }

    /// Keys inside the edit dialog.
    fn on_edit_key(&mut self, key: KeyEvent) {
        enum Action {
            Cancel,
            Save,
            Focus(EditField),
            Pop,
            Push(char),
            None,
        }

        let action = match self.edit.as_ref() {
            None => return,
            Some(form) => match key.code {
                KeyCode::Esc => Action::Cancel,
                KeyCode::Enter => Action::Save,
                KeyCode::Tab | KeyCode::Down => Action::Focus(form.focus.next()),
                KeyCode::BackTab | KeyCode::Up => {
                    let index = EditField::ALL
                        .iter()
                        .position(|field| *field == form.focus)
                        .unwrap_or(0);
                    Action::Focus(
                        EditField::ALL[(index + EditField::ALL.len() - 1) % EditField::ALL.len()],
                    )
                }
                KeyCode::Backspace => Action::Pop,
                KeyCode::Char(character) => Action::Push(character),
                _ => Action::None,
            },
        };

        match action {
            Action::Cancel => {
                self.edit = None;
                self.status = "edit cancelled".to_string();
            }
            Action::Save => self.save_edit(),
            Action::Focus(field) => {
                if let Some(form) = self.edit.as_mut() {
                    form.focus = field;
                }
            }
            Action::Pop => {
                if let Some(form) = self.edit.as_mut() {
                    let field = form.focus;
                    form.value_mut(field).pop();
                }
            }
            Action::Push(character) => {
                if let Some(form) = self.edit.as_mut() {
                    let field = form.focus;
                    form.value_mut(field).push(character);
                }
            }
            Action::None => {}
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
            KeyCode::Char('s') => self.open_ssh(),
            KeyCode::Char('f') => self.open_sftp(),
            KeyCode::Char('e') => self.open_edit(),
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
            KeyCode::Char('s') => self.open_ssh(),
            KeyCode::Char('f') => self.open_sftp(),
            KeyCode::Char('e') => self.open_edit(),
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
            KeyCode::Tab => self.pair.focus = focused.next(),
            KeyCode::BackTab => {
                let ring = [
                    Focus::Address,
                    Focus::Code,
                    Focus::Label,
                    Focus::SshUser,
                    Focus::SshPort,
                    Focus::RunAs,
                ];
                let index = ring.iter().position(|field| *field == focused).unwrap_or(0);
                self.pair.focus = ring[(index + ring.len() - 1) % ring.len()];
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
                Focus::Label => {
                    self.pair.label.pop();
                }
                Focus::SshUser => {
                    self.pair.ssh_user.pop();
                }
                Focus::SshPort => {
                    self.pair.ssh_port.pop();
                }
                Focus::RunAs => {
                    self.pair.run_as.pop();
                }
            },
            KeyCode::Enter => self.on_pair_enter(),
            KeyCode::Char(c) => match focused {
                Focus::Address => self.pair.address.push(c),
                Focus::Code => self.pair.code.push(c),
                Focus::Label => self.pair.label.push(c),
                Focus::SshUser => self.pair.ssh_user.push(c),
                Focus::SshPort => {
                    if c.is_ascii_digit() || c == ' ' {
                        self.pair.ssh_port.push(c);
                    }
                }
                Focus::RunAs => self.pair.run_as.push(c),
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
                        if self.pair.label.is_empty() {
                            self.pair.label = found.label.clone();
                        }
                        self.pair.focus = Focus::Code;
                        self.status = format!("address set to {}", self.pair.address);
                    } else {
                        self.status = "type host:port or press d to discover".to_string();
                    }
                } else {
                    if self.pair.label.is_empty()
                        && let Some(found) = self
                            .pair
                            .discovered
                            .iter()
                            .find(|found| found.endpoint() == self.pair.address)
                    {
                        self.pair.label = found.label.clone();
                    }
                    self.pair.focus = Focus::Code;
                }
            }
            Focus::Code => {
                if self.pair.address.is_empty() || self.pair.code.is_empty() || self.pair.busy {
                    return;
                }
                // The two answers that decide where things run come next.
                self.pair.focus = Focus::Label;
                self.status = "name the node, then say where commands run".to_string();
            }
            Focus::Label => self.pair.focus = Focus::SshUser,
            Focus::SshUser => self.pair.focus = Focus::SshPort,
            Focus::SshPort => {
                let typed = self.pair.ssh_port.trim();
                if !typed.is_empty() {
                    match typed.parse::<u16>() {
                        Ok(port) if port > 0 => {}
                        _ => {
                            self.status = "the ssh port must be 1-65535".to_string();
                            return;
                        }
                    }
                }
                self.pair.focus = Focus::RunAs;
            }
            Focus::RunAs => self.start_pairing(),
        }
    }

    /// Send the pairing request, with the answers to the setup questions.
    fn start_pairing(&mut self) {
        if self.pair.address.is_empty() || self.pair.code.is_empty() || self.pair.busy {
            return;
        }
        // Blank answers are passed through as blank: the node fills them from
        // its own setup, which is the only side that knows its accounts.
        let ssh_port: u16 = self.pair.ssh_port.trim().parse().unwrap_or(0);
        let setup = Setup {
            run_as: self.pair.run_as.trim().to_string(),
            ssh_user: self.pair.ssh_user.trim().to_string(),
            ssh_port,
        };
        for account in [&setup.run_as, &setup.ssh_user] {
            if !account.is_empty() && !valid_account(account) {
                self.status = "account names are lowercase letters, digits, . _ - and start with a letter or _".to_string();
                return;
            }
        }

        let address = self.pair.address.clone();
        let code = self.pair.code.clone();
        let label = self.pair.label.trim().to_string();
        self.pair.busy = true;
        self.pair.working = format!("pairing with {address}");
        self.pair.since = Some(Instant::now());
        self.status = "pairing".to_string();

        worker::pair(
            self.state_dir.clone(),
            address,
            code,
            label,
            setup,
            self.tx.clone(),
        );
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

/// The text area a session gets: the header, the rule and the help line belong
/// to the panel.
fn nonzero(value: u16) -> std::num::NonZeroU16 {
    std::num::NonZeroU16::new(value.max(1)).expect("1 is not zero")
}

pub fn session_size(panel: (u16, u16)) -> (u16, u16) {
    let cols = panel.0.max(20);
    // Header, rule, the session's own rows, another rule, then the help line.
    let rows = panel.1.saturating_sub(4).max(4);
    (cols, rows)
}

