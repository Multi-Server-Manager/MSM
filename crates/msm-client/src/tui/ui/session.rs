//! A live SSH login: the remote's own screen, drawn inside the panel.

use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};

use super::super::app::{App, SessionView};
use super::super::theme;
use super::widgets::{header_with, rule};

/// Rows the SSH screen spends inside the body on its header, its rule and the
/// reason line of a closed login.
const SESSION_CHROME: usize = 2;

/// A live SSH session: its screen, exactly as the remote painted it, then the
/// panel's own header and help line.
pub(super) fn session(app: &App, width: usize, height: usize) -> Vec<Line<'static>> {
    let mut out = Vec::new();
    let Some(view) = app.shown_session() else {
        out.push(Line::from(Span::styled("no session", theme::dim())));
        return out;
    };
    let on_screen = app.active_session.is_some();
    let state = view.state(on_screen);
    let badge = Span::styled(
        state.to_string(),
        match state {
            "live" => theme::live(),
            "closed" => theme::closed(),
            _ => theme::detached(),
        },
    );

    out.push(header_with(
        &format!("msm  ssh  {}", view.title),
        badge,
        width,
    ));
    out.push(rule(width));

    if let Some(reason) = &view.closed {
        out.push(Line::from(Span::styled(reason.clone(), theme::closed())));
    }
    // The grid is sized by `session_grid` — the same call that sizes the
    // remote's PTY — so what the remote draws is what fits here.
    let (cols, rows) = session_grid(app, width, height);
    out.extend(session_rows(view, rows as usize, cols as usize));
    out
}

/// The remote's own screen, with its colours, its cursor and its attributes.
fn session_rows(view: &SessionView, rows: usize, width: usize) -> Vec<Line<'static>> {
    let screen = view.parser.screen();
    let (cursor_row, cursor_col) = screen.cursor_position();
    let cursor_visible = !screen.hide_cursor();
    // Draw the smaller of what the parser holds and what the panel has room
    // for; a frame between a resize and the remote's redraw can be either.
    let rows = rows.min(view.size.1 as usize);
    let cols = width.min(view.size.0 as usize);
    let mut lines = Vec::with_capacity(rows);

    for row in 0..rows as u16 {
        let mut spans: Vec<Span<'static>> = Vec::new();
        let mut current = String::new();
        let mut style = Style::default();

        for col in 0..cols as u16 {
            let Some(cell) = screen.cell(row, col) else {
                continue;
            };
            // The second half of a wide character is not drawn again: the
            // character itself already occupies both cells.
            if cell.is_wide_continuation() {
                continue;
            }
            let mut cell_style = session_style(cell);
            if cursor_visible && row == cursor_row && col == cursor_col {
                cell_style = cell_style.add_modifier(Modifier::REVERSED);
            }
            if cell_style != style {
                if !current.is_empty() {
                    spans.push(Span::styled(std::mem::take(&mut current), style));
                }
                style = cell_style;
            }
            if cell.has_contents() {
                current.push_str(cell.contents());
            } else {
                current.push(' ');
            }
        }
        if !current.is_empty() {
            spans.push(Span::styled(current, style));
        }
        lines.push(Line::from(spans));
    }
    lines
}

fn session_style(cell: &vt100::Cell) -> Style {
    let mut style = Style::default();
    if theme::enabled() {
        style = style
            .fg(vt100_colour(cell.fgcolor()))
            .bg(vt100_colour(cell.bgcolor()));
    }
    for (on, modifier) in [
        (cell.bold(), Modifier::BOLD),
        (cell.dim(), Modifier::DIM),
        (cell.italic(), Modifier::ITALIC),
        (cell.underline(), Modifier::UNDERLINED),
        (cell.inverse(), Modifier::REVERSED),
    ] {
        if on {
            style = style.add_modifier(modifier);
        }
    }
    style
}

fn vt100_colour(colour: vt100::Color) -> Color {
    match colour {
        vt100::Color::Default => Color::Reset,
        vt100::Color::Idx(index) => Color::Indexed(index),
        vt100::Color::Rgb(red, green, blue) => Color::Rgb(red, green, blue),
    }
}

/// The columns and rows of the remote's grid inside a body `height` rows tall.
///
/// This is the single owner of that size: `App::session_area` asks for it when
/// it sizes the remote's PTY and the SSH screen draws exactly this many rows.
/// A line of chrome added above the grid moves here once, not in two places.
pub fn session_grid(app: &App, width: usize, body_height: usize) -> (u16, u16) {
    let reason = usize::from(
        app.shown_session()
            .is_some_and(|view| view.closed.is_some()),
    );
    let rows = body_height
        .saturating_sub(SESSION_CHROME + reason)
        .max(1)
        .min(u16::MAX as usize);
    (width.max(8).min(u16::MAX as usize) as u16, rows as u16)
}
