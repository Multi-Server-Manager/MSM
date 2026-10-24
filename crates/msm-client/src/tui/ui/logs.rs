//! The node's log tail, and the one policy for which lines are on screen.

use ratatui::style::Style;
use ratatui::text::{Line, Span};

use super::super::app::{App, LogsView};
use super::super::theme;
use super::widgets::{fit, header, rule};

pub(super) fn logs(app: &App, width: usize, height: usize) -> Vec<Line<'static>> {
    let mut out = Vec::new();
    let name = app
        .nodes
        .iter()
        .find(|view| Some(&view.record.node_id) == app.logs.node.as_ref())
        .map(|view| view.name().to_string())
        .unwrap_or_else(|| "-".to_string());

    let total = app.logs.lines.len();
    let (first, room) = log_window(&app.logs, height);
    let range = if total > room {
        format!(
            "{} lines  {}-{}",
            total,
            first + 1,
            (first + room).min(total)
        )
    } else {
        format!("{total} lines")
    };
    out.push(header(&format!("msm  logs  {name}"), &range, width));
    out.push(rule(width));

    if app.logs.waiting && total == 0 {
        out.push(Line::from(Span::styled(
            "reading the node's log",
            theme::dim(),
        )));
        return out;
    }
    if total == 0 {
        out.push(Line::from(Span::styled("no lines yet", theme::dim())));
        return out;
    }

    // Newest at the bottom, which is what a tail means; `j`/`k` and the page
    // keys walk back through everything the node sent.
    for line in app.logs.lines.iter().skip(first).take(room) {
        // A log line can be arbitrarily long; the tail is what matters, and a
        // visible `..` says the rest is there rather than pretending it fit.
        out.push(Line::from(Span::styled(fit(line, width), log_style(line))));
    }
    out
}

/// Colour a node log line by what it is, so failures stand out of a tail.
fn log_style(line: &str) -> Style {
    if line.contains("failed=") || line.contains("error") || line.contains("ERROR") {
        theme::failed()
    } else if line.contains("warn") || line.contains("WARN") || line.contains("refused=") {
        theme::warn()
    } else if line.starts_with("COMMAND") || line.starts_with("SSH") {
        Style::default()
    } else if line.starts_with("PAIRED")
        || line.starts_with("SETUP")
        || line.starts_with("UPGRADE")
        || line.starts_with("BACKGROUND")
    {
        theme::label()
    } else if line.starts_with("MSM-NODE") || line.starts_with("LISTEN") || line.starts_with("PAIR")
    {
        theme::strong()
    } else {
        Style::default()
    }
}

/// The slice of the tail that fits in a body `height` rows tall: the first line
/// on screen and how many lines there is room for.
///
/// One owner: the screen draws this slice and the scroll keys move within it,
/// so the number of lines read back is exactly the number drawn.
pub fn log_window(view: &LogsView, height: usize) -> (usize, usize) {
    let total = view.lines.len();
    let room = height.saturating_sub(2).max(1);
    let first = if view.follow {
        total.saturating_sub(room)
    } else {
        view.first.min(total.saturating_sub(room))
    };
    (first, room)
}
