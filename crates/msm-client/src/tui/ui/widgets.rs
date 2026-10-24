//! Shared drawing pieces: headers, rules, fields, bars and text fitting.
//!
//! Nothing here knows which screen it is on; every widget takes the width it
//! has and never writes past it.

use ratatui::style::Style;
use ratatui::text::{Line, Span};
use std::time::Duration;

use super::super::theme;

const RAMP: [char; 9] = [' ', '.', ':', '-', '=', '+', '*', '#', '@'];

/// Cells inside the activity bar's brackets.
const BAR_WIDTH: usize = 16;

/// A moving band, not a percentage: package managers report nothing until they
/// finish, so a filled bar would be a lie. The band and the clock say "alive"
/// and the clock says how long.
pub fn progress_bar(elapsed: Duration, width: usize) -> String {
    let width = width.max(6);
    let span = width - 4;
    let period = span * 2;
    let phase = (elapsed.as_millis() / 90) as usize % period;
    let start = if phase <= span { phase } else { period - phase };

    let mut cells = vec![' '; width];
    for cell in cells.iter_mut().skip(start).take(4) {
        *cell = '=';
    }
    format!("[{}]", cells.into_iter().collect::<String>())
}

/// `14s`, or `1m 04s` once a minute has gone by.
pub fn clock(elapsed: Duration) -> String {
    let seconds = elapsed.as_secs();
    if seconds < 60 {
        format!("{seconds}s")
    } else {
        format!("{}m {:02}s", seconds / 60, seconds % 60)
    }
}

/// One line: what is happening, how long it has been happening, and how many of
/// the selected nodes have answered.
pub fn activity_line(
    label: &str,
    elapsed: Duration,
    done: Option<(usize, usize)>,
    width: usize,
) -> String {
    let suffix = format!(" {} {}", progress_bar(elapsed, BAR_WIDTH), clock(elapsed));
    let count = match done {
        Some((done, total)) if total > 1 => format!("  ({done}/{total} nodes)"),
        _ => String::new(),
    };
    let room = width.saturating_sub(suffix.len() + count.len() + 3).max(1);
    let label: String = label.chars().take(room).collect();
    format!("{label}...{suffix}{count}")
}

/// The activity line, with its bar in the accent colour.
pub(super) fn activity(
    label: &str,
    elapsed: Duration,
    done: Option<(usize, usize)>,
    width: usize,
) -> Line<'static> {
    let text = activity_line(label, elapsed, done, width);
    let (head, tail) = match text.find("...") {
        Some(at) => text.split_at(at + 3),
        None => (text.as_str(), ""),
    };
    Line::from(vec![
        Span::styled(head.to_string(), theme::running()),
        Span::styled(tail.to_string(), theme::subtitle()),
    ])
}

/// Break one help line into width-sized pieces, so nothing is ever clipped.
pub fn wrap(text: &str, width: usize) -> Vec<String> {
    let width = width.max(20);
    let mut out = Vec::new();
    let mut current = String::new();

    for word in text.split(' ') {
        if !current.is_empty() && current.len() + 1 + word.len() > width {
            out.push(current);
            current = String::new();
        }
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(word);
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

pub(super) fn header(left: &str, right: &str, width: usize) -> Line<'static> {
    header_with(
        left,
        Span::styled(right.to_string(), theme::subtitle()),
        width,
    )
}

/// A title on the left, something quiet on the right, and the gap between.
///
/// Both sides are fitted to the width: a long node name or a count with a
/// window range cannot push the header past the last column.
pub(super) fn header_with(left: &str, right: Span<'static>, width: usize) -> Line<'static> {
    let left = fit(left, width.max(1));
    let room = width.saturating_sub(left.chars().count() + 1).max(1);
    let text = fit(&right.content, room);
    let padding = width
        .saturating_sub(left.chars().count() + text.chars().count())
        .max(1);
    Line::from(vec![
        Span::styled(left, theme::title()),
        Span::raw(" ".repeat(padding)),
        Span::styled(text, right.style),
    ])
}

pub(super) fn rule(width: usize) -> Line<'static> {
    Line::from(Span::styled("-".repeat(width.max(1)), theme::rule()))
}

pub(super) fn field(label: &str, value: &str, focused: bool, placeholder: &str) -> Line<'static> {
    let cursor = if focused { "_" } else { " " };
    let (shown, value_style) = if value.is_empty() {
        (placeholder.to_string(), theme::dim())
    } else {
        (value.to_string(), Style::default())
    };
    let style = if focused {
        theme::selected().patch(value_style)
    } else {
        value_style
    };
    Line::from(vec![
        Span::styled(format!("  {label:<11} "), theme::label()),
        Span::styled(format!("[{shown}{cursor}]"), style),
    ])
}

pub(super) fn count_label(count: usize) -> String {
    match count {
        0 => "no nodes".to_string(),
        1 => "1 node".to_string(),
        other => format!("{other} nodes"),
    }
}

/// Fit text into a column, with two dots when it does not.
pub(super) fn fit(text: &str, width: usize) -> String {
    let length = text.chars().count();
    if length <= width {
        return text.to_string();
    }
    let keep = width.saturating_sub(2);
    let mut out: String = text.chars().take(keep).collect();
    out.push_str("..");
    out
}

/// Map a series onto the ASCII ramp, normalised to its own maximum.
pub fn sparkline(values: &[f64], width: usize) -> String {
    if values.is_empty() {
        return String::new();
    }
    let max = values.iter().copied().fold(0.0f64, f64::max).max(0.001);
    let start = values.len().saturating_sub(width.max(1));
    values[start..]
        .iter()
        .map(|value| {
            let index = ((value / max) * (RAMP.len() - 1) as f64).round() as usize;
            RAMP[index.min(RAMP.len() - 1)]
        })
        .collect()
}

/// A fixed-width bar for a percentage.
pub fn bar(percent: f64, width: usize) -> String {
    let filled = ((percent.clamp(0.0, 100.0) / 100.0) * width as f64).round() as usize;
    let mut out = String::with_capacity(width + 2);
    out.push('[');
    out.extend(std::iter::repeat_n('#', filled.min(width)));
    out.extend(std::iter::repeat_n('.', width.saturating_sub(filled)));
    out.push(']');
    out
}

/// One screenful of a longer list, clamped so the last page is full rather than
/// half empty.
pub(super) fn window(
    lines: Vec<Line<'static>>,
    offset: usize,
    height: usize,
) -> Vec<Line<'static>> {
    if height == 0 {
        return Vec::new();
    }
    if lines.len() <= height {
        return lines;
    }
    let start = offset.min(lines.len() - height);
    lines.into_iter().skip(start).take(height).collect()
}

/// First row of a list window that keeps `selected` in view.
pub(super) fn window_start(len: usize, selected: usize, rows: usize) -> usize {
    if rows == 0 || len <= rows {
        return 0;
    }
    selected.saturating_sub(rows / 2).min(len - rows)
}
