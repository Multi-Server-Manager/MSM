//! Drawing the panel.
//!
//! This module owns the frame: the footer is measured first, the body gets
//! exactly what is left, and every screen draws into that body. A screen never
//! knows the terminal size — only the rows it was given — which is what keeps
//! the last row on the terminal at any size.
//!
//! Colour is emphasis only (see `theme`): every state is always spelled out, so
//! the screen still reads without it. The SSH screen keeps the colours the
//! remote itself asked for.
//!
//! Screens live one per file beside this one. Two sizes have one owner so the
//! PTY and the frame cannot drift: `session::session_grid` is the remote's grid
//! and `logs::log_window` is which log lines are on screen.

mod detail;
mod edit;
pub(crate) mod hints;
mod logs;
mod nodes;
mod pair;
mod session;
pub(super) mod widgets;

pub use detail::detail_body_len;
pub use logs::log_window;
pub use pair::pair_body_len;
pub use session::session_grid;
use widgets::wrap;

use ratatui::Frame;
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use ratatui::buffer::Buffer;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use super::app::{App, Screen, Severity};
use super::theme;

use edit::edit_form;
use hints::help;
use widgets::{activity, rule};

/// Draw the current screen.
pub fn draw(frame: &mut Frame, app: &App) {
    let area = frame.size();
    let lines = screen_lines(app, area.width as usize, area.height as usize);
    frame.render_widget(Paragraph::new(lines), area);
}

/// Render one screen into a plain string, for `--render` and the tests.
pub fn render_to_string(app: &App, width: u16, height: u16) -> String {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("test backend");
    terminal
        .draw(|frame| draw(frame, app))
        .expect("draw a test frame");
    buffer_text(terminal.backend().buffer(), width, height)
}

fn buffer_text(buffer: &Buffer, width: u16, height: u16) -> String {
    let mut out = String::new();
    for y in 0..height {
        let mut row = String::new();
        for x in 0..width {
            row.push_str(buffer.get(x, y).symbol());
        }
        out.push_str(row.trim_end());
        out.push('\n');
    }
    out
}

/// The whole screen, fitted into exactly `height` rows.
///
/// The footer is measured first — the rule, the wrapped help line, a prompt and
/// the status or activity line — and the body gets exactly what is left, so a
/// help line that wraps to two rows shrinks the body instead of pushing the
/// last row off the bottom of the terminal.
pub fn screen_lines(app: &App, width: usize, height: usize) -> Vec<Line<'static>> {
    if height == 0 {
        return Vec::new();
    }
    let mut footer = footer(app, width);
    if footer.len() >= height {
        // A terminal too short even for the footer: keep the rule and as much
        // help as fits, and draw nothing past the last row.
        footer.truncate(height);
        return footer;
    }
    let body_height = height - footer.len();
    let mut lines = body(app, width, body_height);
    lines.truncate(body_height);
    while lines.len() < body_height {
        lines.push(Line::from(""));
    }
    lines.extend(footer);
    lines
}

/// Rows the footer takes at this width: the rule, the help line(s), a prompt and
/// the status or activity line. The body gets `height - chrome_rows`.
pub fn chrome_rows(app: &App, width: usize) -> usize {
    footer(app, width).len()
}

/// Rows left for the screen's own content.
pub fn body_rows(app: &App, width: usize, height: usize) -> usize {
    height.saturating_sub(chrome_rows(app, width)).max(1)
}

fn footer(app: &App, width: usize) -> Vec<Line<'static>> {
    let mut lines = vec![rule(width)];
    lines.extend(help(app, width));
    if let Some(prompt) = &app.prompt {
        lines.push(Line::from(vec![
            Span::styled(format!("{}: ", prompt.title), theme::label()),
            Span::styled(format!("{}_", prompt.value), theme::selected()),
        ]));
    }
    match &app.busy {
        Some(busy) => lines.push(activity(
            &busy.label,
            busy.elapsed(),
            Some((busy.done(), busy.total)),
            width,
        )),
        // An error is the one line that must not be clipped: it carries the
        // address and the thing to try next, which is often longer than the
        // terminal is wide.
        None if !app.notice().is_empty() => {
            let style = notice_style(app.notice().severity());
            for line in wrap(app.notice().text(), width) {
                lines.push(Line::from(Span::styled(line, style)));
            }
        }
        None => {}
    }
    lines
}

/// The one place a status line's colour is chosen: from the message's kind,
/// never from its words.
pub(super) fn notice_style(severity: Severity) -> Style {
    match severity {
        Severity::Error => theme::failed(),
        Severity::Warn => theme::warn(),
        Severity::Info => Style::default(),
    }
}

fn body(app: &App, width: usize, height: usize) -> Vec<Line<'static>> {
    // A dialog is modal: it replaces the screen under it, so no field can be
    // pushed off the bottom by whatever was behind it.
    if let Some(edit) = &app.edit {
        return edit_form(edit, width);
    }
    match app.screen {
        Screen::Nodes => nodes::nodes(app, width, height),
        Screen::Pair => {
            let mut lines = Vec::new();
            pair::pair(app, width, height, &mut lines);
            widgets::window(lines, app.scroll, height)
        }
        Screen::Detail => {
            let mut lines = Vec::new();
            detail::detail(app, width, &mut lines);
            widgets::window(lines, app.scroll, height)
        }
        Screen::Logs => logs::logs(app, width, height),
        Screen::Session => session::session(app, width, height),
    }
}

/// Render a screen name, used by `--render`.
pub fn screen_by_name(name: &str) -> Option<Screen> {
    match name {
        "nodes" => Some(Screen::Nodes),
        "pair" => Some(Screen::Pair),
        "detail" => Some(Screen::Detail),
        "logs" => Some(Screen::Logs),
        _ => None,
    }
}

/// Render one screen at a fixed size without a terminal.
pub fn render_screen(app: &mut App, screen: Screen, width: u16, height: u16) -> String {
    app.screen = screen;
    render_to_string(app, width, height)
}
