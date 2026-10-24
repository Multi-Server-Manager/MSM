//! One palette for the whole panel.
//!
//! Colour is emphasis, never information: every state still says its name in
//! words, so the panel reads on a monochrome terminal and stays usable when
//! `NO_COLOR` is set. Only sixteen-colour ANSI values are used, so the panel
//! follows the operator's own terminal theme instead of fighting it.

use std::sync::OnceLock;

use ratatui::style::{Color, Modifier, Style};

use super::app::Status;

static COLOUR: OnceLock<bool> = OnceLock::new();

/// Colour is on unless the environment says otherwise.
///
/// `NO_COLOR` (any non-empty value) and `TERM=dumb` are the two conventions a
/// terminal user expects to be obeyed.
pub fn enabled() -> bool {
    *COLOUR.get_or_init(|| {
        let no_color = std::env::var_os("NO_COLOR").is_some_and(|value| !value.is_empty());
        let dumb = std::env::var("TERM").is_ok_and(|term| term == "dumb");
        !no_color && !dumb
    })
}

fn fg(colour: Color) -> Style {
    if enabled() {
        Style::default().fg(colour)
    } else {
        Style::default()
    }
}

fn fg_bold(colour: Color) -> Style {
    if enabled() {
        Style::default().fg(colour).add_modifier(Modifier::BOLD)
    } else {
        Style::default().add_modifier(Modifier::BOLD)
    }
}

/// The screen title in the top-left corner.
pub fn title() -> Style {
    fg_bold(Color::Cyan)
}

/// The right-hand side of a title: counts, live/closed, an endpoint.
pub fn subtitle() -> Style {
    fg(Color::DarkGray)
}

/// The rule under a title and between the session and its help line.
pub fn rule() -> Style {
    fg(Color::DarkGray)
}

/// Column headings in the node table.
pub fn column() -> Style {
    fg_bold(Color::Blue)
}

/// A name worth finding first: a node label, a field value.
pub fn strong() -> Style {
    Style::default().add_modifier(Modifier::BOLD)
}

/// Addresses, ids, timestamps: true, but not what you are looking for.
pub fn dim() -> Style {
    fg(Color::DarkGray)
}

/// A section label: `load`, `memory`, `disk`, `node`, `last`.
pub fn label() -> Style {
    fg(Color::Cyan)
}

/// The one selected thing: a row in a list, the focused form field, the
/// discovered node about to be paired. Reversed works on every theme, so it
/// stays when colour is off; per-column colours simply invert with it.
pub fn selected() -> Style {
    Style::default().add_modifier(Modifier::REVERSED | Modifier::BOLD)
}

/// A healthy node or a finished command.
pub fn ok() -> Style {
    fg(Color::Green)
}

/// A refused or failed command.
pub fn failed() -> Style {
    fg_bold(Color::Red)
}

/// Work in flight.
pub fn running() -> Style {
    fg(Color::Yellow)
}

/// Nothing known yet.
pub fn unknown() -> Style {
    fg(Color::DarkGray)
}

/// A warning that did not stop anything.
pub fn warn() -> Style {
    fg(Color::Yellow)
}

/// The colour of a node's state word.
pub fn status(status: Status) -> Style {
    match status {
        Status::Ok => ok(),
        Status::Failed => failed(),
        Status::Running => running(),
        Status::Unknown => unknown(),
    }
}

/// A bound key in the help line.
pub fn key() -> Style {
    fg_bold(Color::Cyan)
}

/// What the key does.
pub fn hint() -> Style {
    fg(Color::DarkGray)
}

/// `live` and `detached` in the session column.
pub fn live() -> Style {
    fg_bold(Color::Green)
}

/// A session that is running but not on screen.
pub fn detached() -> Style {
    fg(Color::Yellow)
}

/// A login that ended on its own.
pub fn closed() -> Style {
    fg(Color::Red)
}

/// A percentage, coloured by how close to the edge it is.
pub fn gauge(percent: f64) -> Style {
    if percent >= 90.0 {
        failed()
    } else if percent >= 70.0 {
        warn()
    } else {
        ok()
    }
}
