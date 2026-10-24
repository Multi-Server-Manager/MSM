//! The pairing screen: address, code, and where commands run.

use ratatui::style::Style;
use ratatui::text::{Line, Span};

use super::super::app::{App, Focus};
use super::super::theme;
use super::widgets::{field, fit, header, rule, window_start};

pub(super) fn pair(app: &App, width: usize, height: usize, out: &mut Vec<Line<'static>>) {
    out.push(header(
        "msm  pair",
        "address, code, then where things run",
        width,
    ));
    out.push(rule(width));

    // The form is the point of the screen, so it is laid out first and the
    // decorations are added only when the terminal can spare the rows. That
    // keeps every field on screen at 40x15 instead of clipping the last ones.
    let roomy = height >= 18;
    let tall = height >= 21;
    let mut form: Vec<Line<'static>> = Vec::new();
    if roomy {
        form.push(Line::from(""));
        form.push(Line::from(Span::styled("manual", theme::label())));
    }
    form.push(field(
        "address",
        &app.pair.address,
        app.pair.focus == Focus::Address,
        "10.89.0.3:41234",
    ));
    form.push(field(
        "code",
        &app.pair.code,
        app.pair.focus == Focus::Code,
        "7K3M9QXA",
    ));
    if tall {
        form.push(Line::from(""));
        form.push(Line::from(Span::styled(
            "setup (blank = the node's own answer)",
            theme::label(),
        )));
    }
    form.push(field(
        "name",
        &app.pair.label,
        app.pair.focus == Focus::Label,
        "sanas",
    ));
    form.push(field(
        "ssh user",
        &app.pair.ssh_user,
        app.pair.focus == Focus::SshUser,
        "node's answer",
    ));
    form.push(field(
        "ssh port",
        &app.pair.ssh_port,
        app.pair.focus == Focus::SshPort,
        "node's",
    ));
    form.push(field(
        "commands as",
        &app.pair.run_as,
        app.pair.focus == Focus::RunAs,
        "node's answer",
    ));

    // Two header lines, the section label, then the form: the discovered list
    // gets the rows that remain, with the chosen entry always in view.
    let room = height.saturating_sub(3 + form.len()).max(1);
    let found = app.pair.discovered.len();
    let label = if found > room {
        format!("discovered  _msm-node._tcp  ({} of {found})", room)
    } else {
        "discovered  _msm-node._tcp".to_string()
    };
    out.push(Line::from(Span::styled(label, theme::label())));

    if app.pair.discovered.is_empty() {
        out.push(Line::from(Span::styled(
            "  none yet; press d to browse",
            theme::dim(),
        )));
    } else {
        let start = window_start(found, app.pair.chosen, room);
        for (index, found) in app
            .pair
            .discovered
            .iter()
            .enumerate()
            .skip(start)
            .take(room)
        {
            let chosen = index == app.pair.chosen && app.pair.focus == Focus::Address;
            let cursor = if chosen { ">" } else { " " };
            let name_style = if chosen {
                theme::selected()
            } else {
                Style::default()
            };
            let id = found.node_id.clone().unwrap_or_else(|| "-".to_string());
            // Narrow terminals drop the id first, then shrink the endpoint.
            let name_width = if width >= 70 {
                24
            } else {
                width.saturating_sub(24).clamp(8, 24)
            };
            let endpoint_width = width.saturating_sub(name_width + 4).clamp(8, 22);
            let mut spans = vec![
                Span::styled(format!("{cursor} "), theme::key()),
                Span::styled(
                    format!("{:<name_width$}", fit(&found.label, name_width)),
                    name_style,
                ),
                Span::raw(" "),
                Span::styled(
                    format!(
                        "{:<endpoint_width$}",
                        fit(&found.endpoint(), endpoint_width)
                    ),
                    theme::dim(),
                ),
            ];
            if width >= name_width + endpoint_width + 18 {
                spans.push(Span::styled(format!("id={id}"), theme::dim()));
            }
            out.push(Line::from(spans));
        }
    }
    out.extend(form);
}

/// Rows the pairing screen's body has at this size.
pub fn pair_body_len(app: &App, width: usize, height: usize) -> usize {
    let mut lines = Vec::new();
    pair(app, width, height, &mut lines);
    lines.len()
}
