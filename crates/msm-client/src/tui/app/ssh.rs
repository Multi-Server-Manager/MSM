//! The SSH registry: every login the panel holds, on screen or detached.
//!
//! A login is a thread, an emulator and a PTY. Detaching only changes which
//! screen the panel draws; the thread keeps running and `tick` keeps draining
//! it, so resuming shows the same scrollback and the same running job. Only
//! `terminate` ends the connection.
//!
//! `session_grid` in `ui` owns the size of the remote's grid; this module asks
//! for it when it opens a login and whenever the panel is resized.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::session::{self, Event as SessionEvent, Input as SessionInput, Session as SshSession};
use crate::sshkey::SshKey;

use super::super::ui;
use super::{App, Screen, Severity, Shell};

/// One SSH login inside the panel: the connection, the emulator that draws it,
/// and where leaving the screen returns to.
pub struct SessionView {
    /// The node it belongs to, so `s` resumes this login instead of opening a
    /// second one on the same node.
    pub node_id: String,
    pub ssh: SshSession,
    pub parser: vt100::Parser,
    pub title: String,
    /// Where detaching with Ctrl-M returns to.
    pub origin: Screen,
    /// The size the remote was last told about.
    pub size: (u16, u16),
    /// Set once the remote hung up; the screen keeps its last frame.
    pub closed: Option<String>,
}

impl SessionView {
    /// What the node's row and the session header call this session.
    pub fn state(&self, on_screen: bool) -> &'static str {
        match (&self.closed, on_screen) {
            (Some(_), _) => "closed",
            (None, true) => "live",
            (None, false) => "detached",
        }
    }
}

impl App {
    /// Move bytes from every SSH worker into its emulator, and notice a hangup.
    ///
    /// Detached sessions are drained too, so resuming one shows everything that
    /// happened while the panel was somewhere else. A hangup is reported in the
    /// status line wherever the operator is looking.
    pub(super) fn drain_session(&mut self) {
        let mut closed = Vec::new();
        for view in self.sessions.values_mut() {
            loop {
                match view.ssh.events.try_recv() {
                    Ok(SessionEvent::Opened) => {}
                    Ok(SessionEvent::Data(bytes)) => view.parser.process(&bytes),
                    Ok(SessionEvent::Closed(reason)) => {
                        view.closed = Some(reason.clone());
                        closed.push((view.node_id.clone(), reason));
                        break;
                    }
                    Err(_) => break,
                }
            }
        }

        // A login that just ended gains a reason line, so its grid loses a
        // row: reflow before the next frame draws one row too many.
        if !closed.is_empty() {
            self.reflow_session();
        }

        for (node_id, reason) in closed {
            let name = self
                .nodes
                .iter()
                .find(|view| view.record.node_id == node_id)
                .map(|view| view.name().to_string())
                .unwrap_or_else(|| node_id.clone());
            // On screen the header says closed already; anywhere else the
            // status line is the only place this will be seen at all.
            if self.active_session.as_deref() == Some(node_id.as_str()) {
                self.report(Severity::Error, reason);
            } else {
                self.report(Severity::Warn, format!("{name}: ssh closed ({reason})"));
            }
        }
    }

    /// The session the panel is showing, if any.
    pub fn shown_session(&self) -> Option<&SessionView> {
        self.active_session
            .as_ref()
            .and_then(|node_id| self.sessions.get(node_id))
    }

    /// What a node's row says about its SSH login: `live`, `detached`, `closed`.
    pub fn session_label(&self, node_id: &str) -> Option<&'static str> {
        let view = self.sessions.get(node_id)?;
        Some(view.state(self.active_session.as_deref() == Some(node_id)))
    }

    /// The columns and rows the SSH grid can have at this terminal size.
    ///
    /// The screen owns this arithmetic: the footer is measured first, then the
    /// SSH screen's own chrome, and the grid gets what is left. The PTY and the
    /// frame are therefore the same size by construction, not by convention.
    pub fn session_area(&self, width: u16, height: u16) -> (u16, u16) {
        let body = ui::body_rows(self, width as usize, height as usize);
        ui::session_grid(self, width as usize, body)
    }

    /// Tell the session on screen how big the screen is; a resize reaches the
    /// remote. A detached session keeps its size and is told on resume.
    pub fn set_panel_size(&mut self, width: u16, height: u16) {
        self.panel = (width, height);
        self.reflow_session();
    }

    /// Resize the login on screen to the rows the panel actually has. Called on
    /// a terminal resize and whenever the chrome changes size (a login that
    /// closed gains a reason line, a narrower terminal wraps the help).
    pub(super) fn reflow_session(&mut self) {
        let (width, height) = self.panel;
        let (cols, rows) = self.session_area(width, height);
        let Some(node_id) = self.active_session.clone() else {
            return;
        };
        if let Some(view) = self.sessions.get_mut(&node_id)
            && view.size != (cols, rows)
        {
            view.size = (cols, rows);
            view.parser.set_size(nonzero(rows), nonzero(cols));
            let _ = view.ssh.input.send(SessionInput::Resize(cols, rows));
        }
    }

    /// Open an SSH login inside the panel, authenticated with the MSM key, or
    /// resume the one this node already has.
    ///
    /// Nothing is handed over: the session draws in the same screen and the
    /// keys are forwarded to the remote, except the detach keys.
    pub(super) fn open_ssh(&mut self) {
        let Some(view) = self.current() else {
            return;
        };
        let record = view.record.clone();
        let name = view.name().to_string();

        // A detached session is still running. Resume it rather than logging in
        // again: the scrollback and whatever the shell is doing survive.
        if self.sessions.contains_key(&record.node_id) {
            let (cols, rows) = self.session_area(self.panel.0, self.panel.1);
            let closed = {
                let session = self
                    .sessions
                    .get_mut(&record.node_id)
                    .expect("the session was just found");
                session.size = (cols, rows);
                session.parser.set_size(nonzero(rows), nonzero(cols));
                let _ = session.ssh.input.send(SessionInput::Resize(cols, rows));
                session.closed.clone()
            };
            self.active_session = Some(record.node_id.clone());
            self.screen = Screen::Session;
            match closed {
                Some(reason) => self.report(Severity::Warn, reason),
                None => self.report(Severity::Info, format!("resumed ssh {name}")),
            }
            return;
        }

        // The key must exist before the thread reads it.
        if let Err(err) = SshKey::load_or_create(&self.state_dir) {
            self.report(
                Severity::Error,
                format!("error: cannot prepare the SSH key: {err}"),
            );
            return;
        }

        let (cols, rows) = self.session_area(self.panel.0, self.panel.1);
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

        self.sessions.insert(
            record.node_id.clone(),
            SessionView {
                node_id: record.node_id.clone(),
                ssh,
                parser: vt100::Parser::new(nonzero(rows), nonzero(cols), 2000),
                title: format!("{}@{}", record.ssh_user, record.host),
                origin: self.screen,
                size: (cols, rows),
                closed: None,
            },
        );
        self.active_session = Some(record.node_id.clone());
        self.screen = Screen::Session;
        self.report(
            Severity::Info,
            format!(
                "ssh {}@{}:{}",
                record.ssh_user, record.host, record.ssh_port
            ),
        );
    }

    /// Leave the session on screen without touching the connection.
    ///
    /// `full` is the Esc variant: it lands on the node list. Ctrl-M returns to
    /// the screen the login was opened from. Either way the thread keeps
    /// running, the scrollback is kept, and `s` resumes it.
    pub(super) fn detach_session(&mut self, full: bool) {
        let Some(node_id) = self.active_session.take() else {
            self.screen = Screen::Nodes;
            return;
        };
        let Some(view) = self.sessions.get(&node_id) else {
            self.screen = Screen::Nodes;
            return;
        };
        let origin = view.origin;
        let name = self
            .nodes
            .iter()
            .find(|view| view.record.node_id == node_id)
            .map(|view| view.name().to_string())
            .unwrap_or_else(|| node_id.clone());

        self.screen = if full { Screen::Nodes } else { origin };
        self.report(
            Severity::Warn,
            format!("ssh {name} detached; s resumes it, x ends it"),
        );
    }

    /// Replace a login that ended with a new one, on the same node, without
    /// making the operator go back to the list first.
    pub(super) fn reconnect_session(&mut self, node_id: &str) {
        self.terminate_session(node_id);
        if let Some(index) = self
            .nodes
            .iter()
            .position(|view| view.record.node_id == node_id)
        {
            self.selected = index;
            self.open_ssh();
        }
    }

    /// End one login for good and forget its screen.
    pub(super) fn terminate_session(&mut self, node_id: &str) -> bool {
        let Some(view) = self.sessions.remove(node_id) else {
            return false;
        };
        let _ = view.ssh.input.send(SessionInput::Close);
        if self.active_session.as_deref() == Some(node_id) {
            self.active_session = None;
            self.screen = Screen::Nodes;
        }
        true
    }

    /// `x`: end the SSH login of the highlighted node, detached or not.
    pub(super) fn terminate_ssh(&mut self) {
        let Some(view) = self.current() else {
            return;
        };
        let node_id = view.record.node_id.clone();
        let name = view.name().to_string();
        if self.terminate_session(&node_id) {
            self.report(Severity::Info, format!("ssh {name} terminated"));
        } else {
            self.report(
                Severity::Warn,
                format!("no ssh session on {name}; press s to open one"),
            );
        }
    }

    /// Keys inside a session: everything goes to the remote, except the detach
    /// keys. Enter is never one of them — a shell needs it.
    ///
    /// Esc detaches; a login that is inside a full-screen program also gets the
    /// escape on the way out (see below). Ctrl-M and Ctrl-\\ detach silently.
    pub(super) fn on_session_key(&mut self, key: KeyEvent) -> bool {
        if is_detach_chord(key) {
            self.detach_session(false);
            return true;
        }
        if key.code == KeyCode::Esc && key.modifiers == KeyModifiers::NONE {
            // A full-screen program (vim, less: the alternate screen) gets the
            // escape it cannot work without. A prompt gets nothing: readline
            // would hold the ESC and turn the next key into a Meta chord, which
            // looks exactly like a swallowed keystroke.
            if let Some(view) = self
                .active_session
                .clone()
                .and_then(|id| self.sessions.get_mut(&id))
                && view.closed.is_none()
                && view.parser.screen().alternate_screen()
            {
                let _ = view.ssh.input.send(SessionInput::Data(vec![0x1b]));
            }
            self.detach_session(true);
            return true;
        }

        let Some(node_id) = self.active_session.clone() else {
            self.screen = Screen::Nodes;
            return false;
        };
        // A login that already hung up has no thread to type at. `s` opens a
        // fresh one instead of the key being swallowed by a dead connection.
        if self
            .sessions
            .get(&node_id)
            .is_some_and(|view| view.closed.is_some())
        {
            if matches!(key.code, KeyCode::Char('s')) {
                self.reconnect_session(&node_id);
                return true;
            }
            return false;
        }

        let Some(view) = self.sessions.get_mut(&node_id) else {
            self.screen = Screen::Nodes;
            return false;
        };
        let bytes = session::key_bytes(key);
        if bytes.is_empty() {
            return false;
        }
        let _ = view.ssh.input.send(SessionInput::Data(bytes));
        true
    }

    /// Open SFTP, which is a file browser rather than a shell: it keeps using
    /// the system client, with the key that pairing installed.
    pub(super) fn open_sftp(&mut self) {
        let Some(view) = self.current() else {
            return;
        };
        let record = view.record.clone();
        let key = SshKey::path(&self.state_dir);
        let known_hosts = session::Start::known_hosts_for(&self.state_dir);

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
        self.report(
            Severity::Info,
            format!("sftp {}@{}", record.ssh_user, record.host),
        );
    }
}

/// `Ctrl-M` (where the terminal can tell it from Enter) and `Ctrl-\\` (every
/// terminal) detach a session without touching the connection.
fn is_detach_chord(key: KeyEvent) -> bool {
    if !key.modifiers.contains(KeyModifiers::CONTROL) {
        return false;
    }
    // A kitty-protocol terminal reports Ctrl-M as Enter with CONTROL (the byte
    // is the same CR); older ones report plain Enter, which must never detach.
    //
    // Ctrl-\ is the byte 0x1c, and crossterm names it two ways: `Char('\\')`
    // when the terminal speaks the kitty protocol, `Char('4')` when it does
    // not (0x1c..0x1f are reported as ctrl-4..ctrl-7). Both spell the same
    // keypress, so both must detach — that is what makes this chord work on a
    // terminal with no keyboard enhancements at all.
    matches!(
        key.code,
        KeyCode::Char('m') | KeyCode::Char('\\') | KeyCode::Char('4') | KeyCode::Enter
    )
}

/// A size the vt100 parser and the PTY can take: never zero.
fn nonzero(value: u16) -> std::num::NonZeroU16 {
    std::num::NonZeroU16::new(value.max(1)).expect("1 is not zero")
}
