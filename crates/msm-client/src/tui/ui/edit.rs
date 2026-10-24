//! The edit dialog: label, address, accounts and port, over whatever is behind.

use ratatui::style::Style;
use ratatui::text::{Line, Span};

use super::super::app::{EditField, EditForm};
use super::super::theme;
use super::widgets::rule;

/// The edit dialog. It replaces the screen under it, so its fields are never
/// pushed off the bottom by the table or detail block behind them.
pub(super) fn edit_form(form: &EditForm, width: usize) -> Vec<Line<'static>> {
    let mut out = Vec::new();
    out.push(rule(width));
    out.push(Line::from(vec![
        Span::styled("edit node", theme::title()),
        Span::raw("   "),
        Span::styled("tab next   enter save   esc cancel", theme::dim()),
    ]));
    for field in EditField::ALL {
        let focused = form.focus == field;
        let name = match field {
            EditField::Label => "name",
            EditField::Host => "address",
            EditField::SshUser => "ssh user",
            EditField::SshPort => "ssh port",
            EditField::RunAs => "commands as",
        };
        let cursor = if focused { "_" } else { " " };
        let style = if focused {
            theme::selected()
        } else {
            Style::default()
        };
        out.push(Line::from(vec![
            Span::styled(format!("  {name:<11} "), theme::label()),
            Span::styled(format!("[{}{cursor}]", form.value(field)), style),
        ]));
    }
    out
}
