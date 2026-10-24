//! The help line: which keys exist on the screen being shown.
//!
//! A hint is only listed when the key does something on that screen. `q` is
//! the clearest case: it quits the browsing screens, but the pairing form is
//! text, a dialog is a form too, and the SSH screen's keyboard belongs to the
//! remote, so none of them can also quit — and none advertises it.
//!
//! A dialog owns the keyboard while it is open, so it also owns the help line:
//! the screen underneath takes nothing, and its keys are not offered. The test
//! suite presses every key this table advertises, in every state that has its
//! own table, and requires `App::on_key` to take it.

use super::super::app::{App, Focus, Screen};
use super::super::theme;
use ratatui::style::Style;
use ratatui::text::{Line, Span};

/// Keys and what they do, one pair at a time, wrapped with their colours.
pub(super) fn help(app: &App, width: usize) -> Vec<Line<'static>> {
    let mut words: Vec<(String, Style)> = Vec::new();
    for (key, label) in hints(app) {
        words.push((key.to_string(), theme::key()));
        for word in label.split(' ') {
            words.push((word.to_string(), theme::hint()));
        }
    }

    let width = width.max(20);
    let mut lines = Vec::new();
    let mut spans: Vec<Span<'static>> = Vec::new();
    let mut used = 0usize;
    for (word, style) in words {
        let extra = if spans.is_empty() {
            word.len()
        } else {
            1 + word.len()
        };
        if !spans.is_empty() && used + extra > width {
            lines.push(Line::from(std::mem::take(&mut spans)));
            used = 0;
        }
        if !spans.is_empty() {
            spans.push(Span::raw(" "));
            used += 1;
        }
        used += word.len();
        spans.push(Span::styled(word, style));
    }
    if !spans.is_empty() {
        lines.push(Line::from(spans));
    }
    lines
}

pub(crate) fn hints(app: &App) -> Vec<(&'static str, &'static str)> {
    // The edit dialog replaces the screen under it, and `on_key` sends every
    // press here: `q` types a `q` into the focused field, so advertising
    // `q quit` (or any of the keys behind the dialog) would be a lie.
    if app.edit.is_some() {
        return vec![("tab", "field"), ("enter", "save"), ("esc", "cancel")];
    }
    // The install prompt is a text field for the same reason.
    if app.prompt.is_some() {
        return vec![("enter", "install"), ("esc", "cancel")];
    }

    match app.screen {
        // With nothing paired, a command key has no target and `l`, `s`, `e`,
        // `x` and `f` are ignored outright. Only what works is offered.
        Screen::Nodes if app.nodes.is_empty() => vec![("p", "pair"), ("q", "quit")],
        Screen::Nodes => vec![
            ("j/k", "move"),
            ("space", "mark"),
            ("a", "all"),
            ("enter", "detail"),
            ("u", "update"),
            ("i", "install"),
            ("r", "restart"),
            ("l", "logs"),
            ("s", "ssh"),
            ("x", "end ssh"),
            ("e", "edit"),
            ("f", "sftp"),
            ("p", "pair"),
            ("q", "quit"),
        ],
        Screen::Pair => {
            let mut pairs = Vec::new();
            // `d` only discovers while the address field is empty; once there
            // is text it is a letter in that text. `up/down` needs a result to
            // choose, and only the address field takes it.
            if app.pair.focus == Focus::Address && app.pair.address.is_empty() {
                pairs.push(("d", "discover"));
                if !app.pair.discovered.is_empty() {
                    pairs.push(("up/down", "choose"));
                }
            }
            pairs.extend([("tab", "field"), ("enter", "next/pair"), ("esc", "back")]);
            pairs
        }
        Screen::Detail => vec![
            ("u", "update"),
            ("i", "install"),
            ("r", "restart"),
            ("l", "logs"),
            ("s", "ssh"),
            ("x", "end ssh"),
            ("e", "edit"),
            ("f", "sftp"),
            ("j/k", "scroll"),
            ("PgUp/PgDn", "page"),
            ("g", "refresh"),
            ("esc", "back"),
            ("q", "quit"),
        ],
        Screen::Logs => vec![
            ("j/k", "scroll"),
            ("PgUp/PgDn", "page"),
            ("g/G", "oldest/newest"),
            ("r", "refresh"),
            ("esc", "back"),
            ("q", "quit"),
        ],
        Screen::Session => {
            let closed = app
                .shown_session()
                .map(|view| view.closed.is_some())
                .unwrap_or(false);
            if closed {
                let mut pairs = vec![("esc", "back")];
                if app.ctrl_m {
                    pairs.push(("ctrl-m", "back"));
                }
                // A closed login still owns the keyboard: `q` is not a
                // binding here, so it is not advertised.
                pairs.push(("s", "ssh again"));
                pairs
            } else {
                let mut pairs = Vec::new();
                // Ctrl-M is only a chord when the terminal reports it apart
                // from Enter; saying so on a terminal that cannot is a lie.
                if app.ctrl_m {
                    pairs.push(("ctrl-m", "detach, stays open"));
                    pairs.push(("ctrl-\\", "detach too"));
                } else {
                    // The one byte (0x1c) every terminal can send: no keyboard
                    // protocol asked for, works through tmux and screen.
                    pairs.push(("ctrl-\\", "detach, stays open"));
                }
                // Esc is not forwarded at a prompt, so it can never do the
                // remote's own work: it always leaves the screen.
                //
                // Ctrl-[ is the way to send the remote an escape *and stay*,
                // but only where the terminal reports it apart from Esc: the
                // two are the same 0x1b byte otherwise, and that byte detaches.
                // Promising it on a terminal that cannot tell them apart would
                // be the same mistake as promising Ctrl-M in front of Enter.
                // `x` ends a login from the node list, not here: on this
                // screen it is just a letter the remote receives.
                pairs.push(("esc", "detach to the list"));
                if app.ctrl_m {
                    pairs.push(("ctrl-[", "sends esc"));
                }
                pairs
            }
        }
    }
}
