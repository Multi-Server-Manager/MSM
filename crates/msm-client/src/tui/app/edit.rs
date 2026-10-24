//! The edit dialog: what a node is called, where it is, and who it runs as.
//!
//! Saving writes the record locally first and only then tells the node, so a
//! failed push leaves the console with what the operator typed and the status
//! line with the reason.

use crossterm::event::{KeyCode, KeyEvent};
use msm_protocol::commands::valid_account;
use msm_protocol::messages::Setup;

use super::worker;
use super::{App, Severity};
use crate::store::{self, NodeRecord};

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
        let index = Self::ALL
            .iter()
            .position(|field| *field == self)
            .unwrap_or(0);
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

impl App {
    /// Keys inside the edit dialog.
    pub(super) fn on_edit_key(&mut self, key: KeyEvent) -> bool {
        enum Action {
            Cancel,
            Save,
            Focus(EditField),
            Pop,
            Push(char),
            None,
        }

        let action = match self.edit.as_ref() {
            None => return false,
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
                self.report(Severity::Info, "edit cancelled");
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
            Action::None => return false,
        }
        true
    }

    /// Open the edit dialog for the highlighted node.
    pub(super) fn open_edit(&mut self) {
        let Some(view) = self.current() else {
            return;
        };
        self.edit = Some(EditForm::for_record(view.record.clone()));
        // The footer now carries the dialog's own keys (`ui::hints`), so the
        // old notice would print the same line twice; and an older message
        // left underneath a modal is worse than saying nothing.
        self.report(Severity::Info, String::new());
    }

    /// Apply the edit dialog: store locally, then tell the node.
    pub(super) fn save_edit(&mut self) {
        let Some(form) = self.edit.take() else {
            return;
        };

        let host = form.host.trim().to_string();
        if host.is_empty() {
            self.report(Severity::Error, "the address cannot be empty");
            self.edit = Some(form);
            return;
        }
        let ssh_port: u16 = match form.ssh_port.trim().parse() {
            Ok(port) if port > 0 => port,
            _ => {
                self.report(Severity::Error, "the ssh port must be 1-65535");
                self.edit = Some(form);
                return;
            }
        };
        let ssh_user_value = form.ssh_user.trim().to_string();
        let run_as_value = form.run_as.trim().to_string();
        for account in [ssh_user_value.as_str(), run_as_value.as_str()] {
            if !valid_account(account) {
                self.report(
                    Severity::Error,
                    format!(
                        "{account:?} is not an account name (lowercase letters, digits, . _ -, starting with a letter or _)"
                    ),
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
            self.report(
                Severity::Error,
                format!("error: cannot save the node: {err}"),
            );
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
            self.report(Severity::Info, "saved");
            return;
        }
        self.report(Severity::Info, "saved; telling the node");
        worker::configure(self.state_dir.clone(), record, setup, self.tx.clone());
    }
}
