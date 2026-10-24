//! The pairing form: the address, the code, and where things run.
//!
//! The form is a small state machine — Tab walks the questions, Enter advances
//! or sends — and it is the only screen where a letter key cannot also be a
//! command. The answers are handed to the node, which fills any blank from its
//! own setup.

use std::time::Instant;

use crossterm::event::{KeyCode, KeyEvent};
use msm_protocol::commands::valid_account;
use msm_protocol::messages::Setup;

use super::worker;
use super::{App, Screen, Severity};
use crate::mdns::Discovered;

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

impl App {
    pub(super) fn on_pair_key(&mut self, key: KeyEvent) -> bool {
        let focused = self.pair.focus;
        match key.code {
            KeyCode::Esc => {
                self.scroll = 0;
                self.screen = Screen::Nodes;
                self.pair.pick_when_found = false;
                self.pair.busy = false;
                self.pair.since = None;
            }
            KeyCode::PageDown => {
                let rows = self.view_rows();
                self.scroll_body(rows as isize);
            }
            KeyCode::PageUp => {
                let rows = self.view_rows();
                self.scroll_body(-(rows as isize));
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
                self.report(Severity::Info, "browsing mDNS and the tailnet for nodes");
                worker::discover(self.state_dir.clone(), self.tx.clone());
            }
            // Enter always has an effect: while discovery is still running it
            // is remembered and applied to the first answer, so a fast Enter
            // after `d` no longer disappears.
            KeyCode::Enter if self.pair.busy && focused == Focus::Address => {
                self.pair.pick_when_found = true;
                self.report(
                    Severity::Info,
                    "discovering; the first node found will be chosen",
                );
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
            _ => return false,
        }
        true
    }

    pub(super) fn on_pair_enter(&mut self) {
        match self.pair.focus {
            Focus::Address => {
                if self.pair.address.is_empty() {
                    if self.pair.busy {
                        self.pair.pick_when_found = true;
                        self.report(
                            Severity::Info,
                            "discovering; the first node found will be chosen",
                        );
                        return;
                    }
                    if let Some(found) = self.pair.discovered.get(self.pair.chosen) {
                        self.pair.address = found.endpoint();
                        if self.pair.label.is_empty() {
                            self.pair.label = found.label.clone();
                        }
                        self.pair.focus = Focus::Code;
                        self.report(
                            Severity::Info,
                            format!("address set to {}", self.pair.address),
                        );
                    } else {
                        self.report(Severity::Info, "type host:port or press d to discover");
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
                self.report(Severity::Info, "name the node, then say where commands run");
            }
            Focus::Label => self.pair.focus = Focus::SshUser,
            Focus::SshUser => self.pair.focus = Focus::SshPort,
            Focus::SshPort => {
                let typed = self.pair.ssh_port.trim();
                if !typed.is_empty() {
                    match typed.parse::<u16>() {
                        Ok(port) if port > 0 => {}
                        _ => {
                            self.report(Severity::Error, "the ssh port must be 1-65535");
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
    pub(super) fn start_pairing(&mut self) {
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
                self.report(
                    Severity::Error,
                    "account names are lowercase letters, digits, . _ - and start with a letter or _",
                );
                return;
            }
        }

        let address = self.pair.address.clone();
        let code = self.pair.code.clone();
        let label = self.pair.label.trim().to_string();
        self.pair.busy = true;
        self.pair.working = format!("pairing with {address}");
        self.pair.since = Some(Instant::now());
        self.report(Severity::Info, "pairing");

        worker::pair(
            self.state_dir.clone(),
            address,
            code,
            label,
            setup,
            self.tx.clone(),
        );
    }
}
