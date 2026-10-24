//! Panel state: what is on screen, what is selected, and what a key press does.
//!
//! `App` is the one owner of that state. The screens it can show are here with
//! their rows and their key handlers; the dialogs and the SSH registry are
//! their own modules beside this one, each adding methods to the same `App`:
//!
//! - `pairing` — the pairing form and the questions it asks,
//! - `edit` — the edit dialog and the change it pushes to the node,
//! - `ssh` — every login the panel holds, and the keys that leave or end one.
//!
//! Nothing here touches the terminal, so every screen can be driven headlessly.

mod edit;
mod pairing;
mod ssh;

pub use edit::{EditField, EditForm};
pub use pairing::{Focus, PairForm};
pub use ssh::SessionView;

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::{Duration, Instant};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use msm_protocol::commands::Command;

use super::worker::{self, HISTORY, Msg, Sample};
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

/// How a status line reads. The footer's colour comes from this, never from
/// the words: no message is classified by matching English in a string.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    #[default]
    Info,
    Warn,
    Error,
}

/// The footer's one line: what just happened, and how it went.
#[derive(Debug, Default)]
pub struct Notice {
    text: String,
    severity: Severity,
}

impl Notice {
    /// The words shown.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// How they are coloured.
    pub fn severity(&self) -> Severity {
        self.severity
    }

    pub fn is_empty(&self) -> bool {
        self.text.is_empty()
    }
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

/// The log screen's content.
#[derive(Debug, Default)]
pub struct LogsView {
    pub node: Option<String>,
    pub lines: Vec<String>,
    pub waiting: bool,
    /// First line on screen; ignored while `follow` is set.
    pub first: usize,
    /// Stay pinned to the newest line, which is what a tail does.
    pub follow: bool,
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
    /// What the footer says last; `report` is the only way to set it.
    notice: Notice,
    pub pair: PairForm,
    pub logs: LogsView,
    pub prompt: Option<Prompt>,
    pub shell: Option<Shell>,
    /// Every SSH login this panel holds, keyed by node id. A detached session
    /// stays here: its thread, its screen and its scrollback keep running.
    pub sessions: BTreeMap<String, SessionView>,
    /// The session on screen, when the panel is showing one.
    pub active_session: Option<String>,
    /// Whether the terminal reports Ctrl-M apart from Enter (the kitty
    /// keyboard protocol). Only then can Ctrl-M detach; Ctrl-\ and Esc always
    /// can, and Enter always belongs to the shell.
    pub ctrl_m: bool,
    /// The edit dialog, when it is open.
    pub edit: Option<EditForm>,
    /// First row of a body that is taller than the terminal (detail, pair).
    pub scroll: usize,
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
            notice: Notice::default(),
            pair: PairForm::default(),
            logs: LogsView::default(),
            prompt: None,
            shell: None,
            sessions: BTreeMap::new(),
            active_session: None,
            ctrl_m: false,
            edit: None,
            scroll: 0,
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
            if due && let Some(record) = self.current().map(|view| view.record.clone()) {
                self.detail_refreshed = Some(Instant::now());
                worker::metrics(self.state_dir.clone(), record, self.tx.clone());
            }
        }
    }

    /// Put a line in the footer. The kind decides its colour.
    pub fn report(&mut self, severity: Severity, text: impl Into<String>) {
        self.notice = Notice {
            text: text.into(),
            severity,
        };
    }

    /// What the footer currently says.
    pub fn notice(&self) -> &Notice {
        &self.notice
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
                        self.report(Severity::Error, format!("error: {summary}"));
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

                let (severity, text) = match what {
                    Some(what) if ok => (Severity::Info, format!("{what}: {summary}")),
                    Some(what) => (Severity::Error, format!("{what}: error: {summary}")),
                    None if ok => (Severity::Info, summary),
                    None => (Severity::Error, format!("error: {summary}")),
                };
                self.report(severity, text);
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
                let (severity, text) = match warning {
                    Some(warning) => (Severity::Warn, format!("paired with {name}; {warning}")),
                    None => (
                        Severity::Info,
                        format!("paired with {name}, SSH key installed"),
                    ),
                };
                self.report(severity, text);
            }
            Msg::Discovered(found) => {
                self.pair.busy = false;
                self.pair.since = None;
                self.pair.chosen = 0;
                let (severity, text) = if found.is_empty() {
                    (
                        Severity::Warn,
                        "no nodes answered on the LAN or tailnet; is msm-node running?".to_string(),
                    )
                } else {
                    (
                        Severity::Info,
                        format!("{} node(s) discovered", found.len()),
                    )
                };
                self.report(severity, text);
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
                let (severity, text) = match warning {
                    Some(warning) => (Severity::Warn, format!("saved; {warning}")),
                    None => (
                        Severity::Info,
                        "saved; the node uses the new settings".to_string(),
                    ),
                };
                self.report(severity, text);
            }
            Msg::Failed(reason) => {
                self.pair.busy = false;
                self.pair.since = None;
                self.logs.waiting = false;
                self.report(Severity::Error, format!("error: {reason}"));
            }
        }
    }

    fn mark(&mut self, node_id: &str, status: Status) {
        if let Some(view) = self.nodes.iter_mut().find(|v| v.record.node_id == node_id) {
            view.status = status;
        }
    }

    /// Rows the body has now, measured the way the draw measures them.
    pub fn view_rows(&self) -> usize {
        super::ui::body_rows(self, self.panel.0 as usize, self.panel.1 as usize)
    }

    /// First log line on screen; the tail while following.
    pub fn logs_first(&self, rows: usize) -> usize {
        super::ui::log_window(&self.logs, rows).0
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

    /// Walk the log tail; the last page stops on the newest line.
    fn scroll_logs(&mut self, delta: isize) {
        let body = self.view_rows().max(1);
        // The same window the screen draws, so the first key after the tail is
        // pinned moves the view instead of being swallowed by the clamp.
        let (_, room) = super::ui::log_window(&self.logs, body);
        let len = self.logs.lines.len();
        let max = len.saturating_sub(room);
        let current = self.logs_first(body);
        let next = (current as isize)
            .saturating_add(delta)
            .clamp(0, max as isize) as usize;
        self.logs.first = next;
        self.logs.follow = next + room >= len;
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
            self.report(Severity::Warn, "no node selected");
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
            first: 0,
            follow: true,
        };
        self.scroll = 0;
        self.screen = Screen::Logs;
        self.report(Severity::Info, format!("logs from {name}"));
        worker::logs(self.state_dir.clone(), record, 200, self.tx.clone());
    }

    /// Apply one key press. `true` when a binding on the current screen took
    /// it; the help line only advertises keys for which this is true.
    pub fn on_key(&mut self, key: KeyEvent) -> bool {
        // A live session owns the keyboard: Ctrl-C belongs to the remote, and
        // only the detach keys come back here.
        if self.screen == Screen::Session {
            return self.on_session_key(key);
        }

        if self.edit.is_some() {
            return self.on_edit_key(key);
        }

        if key.modifiers.contains(KeyModifiers::CONTROL) && matches!(key.code, KeyCode::Char('c')) {
            self.should_quit = true;
            return true;
        }

        if self.prompt.is_some() {
            return self.on_prompt_key(key);
        }

        // `q` quits every browsing screen, but it is a letter in the pairing
        // form: a label or an address may contain it.
        if key.code == KeyCode::Char('q') && self.screen != Screen::Pair {
            self.should_quit = true;
            return true;
        }

        match self.screen {
            Screen::Nodes => self.on_nodes_key(key),
            Screen::Pair => self.on_pair_key(key),
            Screen::Detail => self.on_detail_key(key),
            Screen::Logs => self.on_logs_key(key),
            Screen::Session => false,
        }
    }

    fn on_nodes_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Char('j') | KeyCode::Down => self.move_by(1),
            KeyCode::Char('k') | KeyCode::Up => self.move_by(-1),
            KeyCode::Char(' ') => self.toggle_mark(),
            KeyCode::Char('a') => {
                if self.marked.len() == self.nodes.len() {
                    self.marked.clear();
                } else {
                    self.marked = self
                        .nodes
                        .iter()
                        .map(|v| v.record.node_id.clone())
                        .collect();
                }
            }
            KeyCode::Char('p') => {
                self.scroll = 0;
                self.screen = Screen::Pair;
                self.pair.focus = Focus::Address;
                self.report(Severity::Info, "press d to discover, or type an address");
            }
            KeyCode::Enter => {
                if self.current().is_some() {
                    self.detail_refreshed = None;
                    self.scroll = 0;
                    self.screen = Screen::Detail;
                } else {
                    self.report(Severity::Warn, "no paired nodes; press p to pair with one");
                }
            }
            // Refresh every target's gauges now, rather than waiting for the
            // detail screen's clock.
            KeyCode::Char('g') => {
                for record in self.targets() {
                    worker::metrics(self.state_dir.clone(), record, self.tx.clone());
                }
            }
            _ => return self.on_command_key(key),
        }
        true
    }

    fn on_detail_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Esc | KeyCode::Char('h') | KeyCode::Left => {
                self.scroll = 0;
                self.screen = Screen::Nodes;
                self.detail_refreshed = None;
            }
            KeyCode::Char('g') => {
                self.detail_refreshed = None;
            }
            // The gauges do not fit every terminal; walk them instead of
            // letting the last lines fall off the bottom.
            KeyCode::Char('j') | KeyCode::Down => self.scroll_body(1),
            KeyCode::Char('k') | KeyCode::Up => self.scroll_body(-1),
            KeyCode::PageDown => {
                let rows = self.view_rows();
                self.scroll_body(rows as isize);
            }
            KeyCode::PageUp => {
                let rows = self.view_rows();
                self.scroll_body(-(rows as isize));
            }
            KeyCode::Home => self.scroll_body(isize::MIN / 2),
            KeyCode::End => self.scroll_body(isize::MAX / 2),
            _ => return self.on_command_key(key),
        }
        true
    }

    /// The command keys the node list and the detail screen share, so a new
    /// one is added once. `false` leaves the key to the screen's navigation.
    fn on_command_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Char('u') => self.start(Command::PkgUpdate),
            KeyCode::Char('i') => {
                self.prompt = Some(Prompt {
                    title: "install package".to_string(),
                    value: String::new(),
                })
            }
            KeyCode::Char('r') => self.start(Command::SvcRestart(String::new())),
            KeyCode::Char('l') => self.open_logs(),
            KeyCode::Char('s') => self.open_ssh(),
            KeyCode::Char('f') => self.open_sftp(),
            KeyCode::Char('e') => self.open_edit(),
            KeyCode::Char('x') | KeyCode::Char('X') => self.terminate_ssh(),
            _ => return false,
        }
        true
    }

    fn on_logs_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Esc | KeyCode::Left | KeyCode::Char('h') => {
                self.scroll = 0;
                self.screen = if self.nodes.is_empty() {
                    Screen::Nodes
                } else {
                    Screen::Detail
                };
            }
            KeyCode::Char('j') | KeyCode::Down => self.scroll_logs(1),
            KeyCode::Char('k') | KeyCode::Up => self.scroll_logs(-1),
            KeyCode::PageDown => {
                let rows = self.view_rows();
                self.scroll_logs(rows as isize);
            }
            KeyCode::PageUp => {
                let rows = self.view_rows();
                self.scroll_logs(-(rows as isize));
            }
            // `g` goes to the oldest line and stops following; `G` jumps back
            // to the tail, which is where a fresh refresh starts.
            KeyCode::Char('g') => self.scroll_logs(isize::MIN / 2),
            KeyCode::Char('G') => {
                self.logs.follow = true;
                self.logs.first = 0;
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
            _ => return false,
        }
        true
    }

    fn on_prompt_key(&mut self, key: KeyEvent) -> bool {
        let Some(prompt) = self.prompt.as_mut() else {
            return false;
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
                    self.report(Severity::Error, "no package name");
                    return true;
                }
                self.start(Command::PkgInstall(name.clone()));
            }
            _ => return false,
        }
        true
    }

    /// Walk a static screen whose body is taller than the terminal.
    pub(super) fn scroll_body(&mut self, delta: isize) {
        let (width, height) = (self.panel.0 as usize, self.panel.1 as usize);
        let rows = super::ui::body_rows(self, width, height);
        let len = match self.screen {
            Screen::Detail => super::ui::detail_body_len(self, width),
            Screen::Pair => super::ui::pair_body_len(self, width, height),
            _ => return,
        };
        let max = len.saturating_sub(rows);
        self.scroll = (self.scroll as isize)
            .saturating_add(delta)
            .clamp(0, max as isize) as usize;
    }
}
