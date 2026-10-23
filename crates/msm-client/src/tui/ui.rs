//! Drawing the panel.
//!
//! Everything is plain ASCII in one monospace grid: no icons, no colour, no
//! boxes. The only emphasis is reverse video on the selected row.

use std::time::Duration;

use ratatui::Frame;
use ratatui::backend::TestBackend;
use ratatui::buffer::Buffer;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Terminal;

use super::app::{App, Screen, Status};
use super::worker::Sample;

const RAMP: [char; 9] = [' ', '.', ':', '-', '=', '+', '*', '#', '@'];

/// Draw the current screen.
pub fn draw(frame: &mut Frame, app: &App) {
    let area = frame.size();
    let lines = lines_for(app, area.width as usize);
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

fn lines_for(app: &App, width: usize) -> Vec<Line<'static>> {
    let rule = "-".repeat(width.max(1));
    let mut lines = Vec::new();
    match app.screen {
        Screen::Nodes => nodes(app, width, &mut lines),
        Screen::Pair => pair(app, width, &mut lines),
        Screen::Detail => detail(app, width, &mut lines),
        Screen::Logs => logs(app, width, &mut lines),
    }
    lines.push(Line::from(rule));
    let help = match app.screen {
        Screen::Nodes => {
            "j/k move  space mark  a all  enter detail  u update  i install  r restart  l logs  s ssh  f sftp  p pair  q quit"
        }
        Screen::Pair => "d discover  up/down choose  tab field  enter next/pair  esc back  q quit",
        Screen::Detail => "u update  i install  r restart  l logs  s ssh  f sftp  g refresh  esc back  q quit",
        Screen::Logs => "r refresh  esc back  q quit",
    };
    for line in wrap(help, width) {
        lines.push(Line::from(line));
    }
    if let Some(prompt) = &app.prompt {
        lines.push(Line::from(Span::styled(
            format!("{}: {}_", prompt.title, prompt.value),
            Style::default().add_modifier(Modifier::REVERSED),
        )));
    }
    match &app.busy {
        Some(busy) => lines.push(Line::from(activity_line(
            &busy.label,
            busy.elapsed(),
            Some((busy.done(), busy.total)),
            width,
        ))),
        // An error is the one line that must not be clipped: it carries the
        // address and the thing to try next, which is often longer than the
        // terminal is wide.
        None if !app.status.is_empty() => {
            for line in wrap(&app.status, width) {
                lines.push(Line::from(line));
            }
        }
        None => {}
    }
    lines
}

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

fn header(left: &str, right: &str, width: usize) -> Line<'static> {
    let padding = width.saturating_sub(left.len() + right.len());
    Line::from(format!("{left}{}{right}", " ".repeat(padding.max(1))))
}

fn nodes(app: &App, width: usize, out: &mut Vec<Line<'static>>) {
    let marked = if app.marked.is_empty() {
        String::new()
    } else {
        format!("  {} marked", app.marked.len())
    };
    out.push(header(
        "msm  nodes",
        &format!("{}{}", count_label(app.nodes.len()), marked),
        width,
    ));
    out.push(Line::from("-".repeat(width)));

    if app.nodes.is_empty() {
        out.push(Line::from(""));
        out.push(Line::from("no paired nodes"));
        out.push(Line::from("press p to pair with one"));
        return;
    }

    let label_width = app
        .nodes
        .iter()
        .map(|view| view.name().len())
        .max()
        .unwrap_or(5)
        .max(5);
    out.push(Line::from(format!(
        "  {:<label_width$}  {:<22}  {:<24}  {}",
        "LABEL", "ADDRESS", "SSH", "STATUS"
    )));

    for (index, view) in app.nodes.iter().enumerate() {
        let cursor = if index == app.selected { ">" } else { " " };
        let mark = if app.marked.contains(&view.record.node_id) {
            "*"
        } else {
            " "
        };
        let ssh = format!("{}@{}:{}", view.record.ssh_user, view.record.host, view.record.ssh_port);
        // A running node says what it is doing (`installing htop`) rather than
        // repeating the word "running" for every command.
        let state = view.doing.as_deref().unwrap_or(view.status.text());
        let text = format!(
            "{cursor}{mark} {:<label_width$}  {:<22}  {:<24}  {}",
            view.name(),
            format!("{}:{}", view.record.host, view.record.op_port),
            ssh,
            state
        );
        let style = if index == app.selected {
            Style::default().add_modifier(Modifier::REVERSED)
        } else {
            Style::default()
        };
        out.push(Line::from(Span::styled(text, style)));
    }

    if let Some(view) = app.current() {
        out.push(Line::from(""));
        out.push(Line::from(format!(
            "{}   node {}   {}",
            view.name(),
            view.record.node_id,
            match &view.last {
                last if last.is_empty() => "no activity yet".to_string(),
                last => last.clone(),
            }
        )));
        if view.status == Status::Unknown {
            out.push(Line::from("press g to refresh this node"));
        }
    }
}

fn pair(app: &App, width: usize, out: &mut Vec<Line<'static>>) {
    out.push(header("msm  pair", "3 steps: discover, address, code", width));
    out.push(Line::from("-".repeat(width)));
    out.push(Line::from(""));
    out.push(Line::from("discovered  _msm-node._tcp"));

    if app.pair.discovered.is_empty() {
        out.push(Line::from("  none yet; press d to browse"));
    } else {
        for (index, found) in app.pair.discovered.iter().enumerate() {
            let cursor = if index == app.pair.chosen && app.pair.focus == super::app::Focus::Address
            {
                ">"
            } else {
                " "
            };
            let id = found.node_id.clone().unwrap_or_else(|| "-".to_string());
            out.push(Line::from(format!(
                "{cursor} {:<24} {:<22} id={id}",
                found.label,
                found.endpoint()
            )));
        }
    }

    out.push(Line::from(""));
    out.push(Line::from("manual"));
    out.push(field(
        "address",
        &app.pair.address,
        app.pair.focus == super::app::Focus::Address,
        "10.89.0.3:41234",
    ));
    out.push(field(
        "code",
        &app.pair.code,
        app.pair.focus == super::app::Focus::Code,
        "7K3M9QXA",
    ));
    if app.pair.busy {
        out.push(Line::from(""));
        let elapsed = app.pair.since.map(|at| at.elapsed()).unwrap_or_default();
        out.push(Line::from(activity_line(
            &app.pair.working,
            elapsed,
            None,
            width,
        )));
    }
}

fn field(label: &str, value: &str, focused: bool, placeholder: &str) -> Line<'static> {
    let cursor = if focused { "_" } else { " " };
    let shown = if value.is_empty() {
        placeholder.to_string()
    } else {
        value.to_string()
    };
    let style = if focused {
        Style::default().add_modifier(Modifier::REVERSED)
    } else {
        Style::default()
    };
    Line::from(Span::styled(
        format!("  {label:<8} [{shown}{cursor}]"),
        style,
    ))
}

fn detail(app: &App, width: usize, out: &mut Vec<Line<'static>>) {
    let Some(view) = app.current() else {
        out.push(header("msm  node", "none", width));
        out.push(Line::from("-".repeat(width)));
        out.push(Line::from("no paired nodes"));
        return;
    };

    out.push(header(
        &format!("msm  {}", view.name()),
        &format!("{}:{}", view.record.host, view.record.op_port),
        width,
    ));
    out.push(Line::from("-".repeat(width)));
    out.push(Line::from(format!(
        "node {}   ssh {}@{}:{}   status {}",
        view.record.node_id,
        view.record.ssh_user,
        view.record.host,
        view.record.ssh_port,
        view.doing.as_deref().unwrap_or(view.status.text())
    )));
    out.push(Line::from(""));

    let samples: Vec<Sample> = view.history.iter().copied().collect();
    if samples.is_empty() {
        out.push(Line::from("collecting samples"));
    } else {
        let loads: Vec<f64> = samples.iter().map(|sample| sample.load1).collect();
        let latest = samples[samples.len() - 1];
        out.push(Line::from(format!("{:9} {:.2}", "load", latest.load1)));
        out.push(Line::from(format!("          {}", sparkline(&loads, 24))));
        out.push(Line::from(""));
        out.push(Line::from(format!(
            "{:9} {:.0}% of {} MiB",
            "memory",
            latest.memory_pct,
            latest.memory_total_kb / 1024
        )));
        out.push(Line::from(format!(
            "          {} {:.0}%",
            bar(latest.memory_pct, 24),
            latest.memory_pct
        )));
        out.push(Line::from(""));
        out.push(Line::from(format!("{:9} {:.0}% used", "disk", latest.disk_pct)));
        out.push(Line::from(format!(
            "          {} {:.0}%",
            bar(latest.disk_pct, 24),
            latest.disk_pct
        )));
        out.push(Line::from(""));
        out.push(Line::from(format!(
            "{} samples   updated {}",
            samples.len(),
            view.updated
                .map(|at| format!("{}s ago", at.elapsed().as_secs()))
                .unwrap_or_else(|| "-".to_string())
        )));
    }

    out.push(Line::from(""));
    out.push(Line::from(format!(
        "last      {}",
        if view.last.is_empty() {
            "none"
        } else {
            view.last.as_str()
        }
    )));
}

fn logs(app: &App, width: usize, out: &mut Vec<Line<'static>>) {
    let name = app
        .nodes
        .iter()
        .find(|view| Some(&view.record.node_id) == app.logs.node.as_ref())
        .map(|view| view.name().to_string())
        .unwrap_or_else(|| "-".to_string());

    out.push(header(
        &format!("msm  logs  {name}"),
        &format!("{} lines", app.logs.lines.len()),
        width,
    ));
    out.push(Line::from("-".repeat(width)));

    if app.logs.waiting && app.logs.lines.is_empty() {
        out.push(Line::from("reading the node's log"));
        return;
    }
    if app.logs.lines.is_empty() {
        out.push(Line::from("no lines yet"));
        return;
    }

    // Newest at the bottom, which is what a tail means.
    let height = 18;
    let start = app.logs.lines.len().saturating_sub(height);
    for line in &app.logs.lines[start..] {
        out.push(Line::from(line.clone()));
    }
}

fn count_label(count: usize) -> String {
    match count {
        0 => "no nodes".to_string(),
        1 => "1 node".to_string(),
        other => format!("{other} nodes"),
    }
}

/// Map a series onto the ASCII ramp, normalised to its own maximum.
pub fn sparkline(values: &[f64], width: usize) -> String {
    if values.is_empty() {
        return String::new();
    }
    let max = values
        .iter()
        .copied()
        .fold(0.0f64, f64::max)
        .max(0.001);
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
