//! The node list: one row per paired node, and the block under it.

use ratatui::style::Style;
use ratatui::text::{Line, Span};

use super::super::app::App;
use super::super::theme;
use super::widgets::{count_label, fit, header, rule, window_start};

/// Columns of the node table, after the cursor and the mark.
const ADDRESS: usize = 20;

const SSH: usize = 20;

const STATE: usize = 12;

const SESSION: usize = 8;

pub(super) fn nodes(app: &App, width: usize, height: usize) -> Vec<Line<'static>> {
    let mut out = Vec::new();
    let marked = if app.marked.is_empty() {
        String::new()
    } else {
        format!("  {} marked", app.marked.len())
    };
    let open = app.sessions.len();
    let sessions = match open {
        0 => String::new(),
        1 => "  1 ssh".to_string(),
        other => format!("  {other} ssh"),
    };

    // Header, rule and the column titles are fixed; the selected node's block
    // is the first thing dropped when the terminal is short, and the rows get
    // whatever remains. A window keeps the cursor in view and says so in the
    // header, so nothing is silently missing.
    let detail = node_detail(app);
    let fixed = 3;
    let with_detail = height >= fixed + 5 + detail.len();
    let detail_rows = if with_detail { detail.len() } else { 0 };
    let visible = height.saturating_sub(fixed + detail_rows).max(1);
    let start = window_start(app.nodes.len(), app.selected, visible);
    let end = (start + visible).min(app.nodes.len());
    let range = if app.nodes.len() > visible {
        format!("  {}-{} of {}", start + 1, end, app.nodes.len())
    } else {
        String::new()
    };

    out.push(header(
        "msm  nodes",
        &format!(
            "{}{}{}{}",
            count_label(app.nodes.len()),
            marked,
            sessions,
            range
        ),
        width,
    ));
    out.push(rule(width));

    if app.nodes.is_empty() {
        out.push(Line::from(""));
        out.push(Line::from(Span::styled("no paired nodes", theme::dim())));
        out.push(Line::from(Span::styled(
            "press p to pair with one",
            theme::dim(),
        )));
        return out;
    }

    // The table narrows before it clips: the status and the session badge are
    // the point, the address and the ssh endpoint are dropped when the terminal
    // cannot hold them, and the label shrinks with what is left.
    let widest = app
        .nodes
        .iter()
        .map(|view| view.name().len())
        .max()
        .unwrap_or(5)
        .clamp(5, 16);
    let label_width = widest.min(width.saturating_sub(3 + 2 + STATE + 2 + SESSION).max(5));
    let (address, ssh) = node_columns(width, label_width);

    let mut headings = vec![
        Span::raw("   "),
        Span::styled(format!("{:<label_width$}", "LABEL"), theme::column()),
    ];
    if let Some(room) = address {
        headings.push(Span::raw("  "));
        headings.push(Span::styled(
            format!("{:<room$}", fit("ADDRESS", room)),
            theme::column(),
        ));
    }
    if let Some(room) = ssh {
        headings.push(Span::raw("  "));
        headings.push(Span::styled(
            format!("{:<room$}", fit("SSH", room)),
            theme::column(),
        ));
    }
    headings.extend([
        Span::raw("  "),
        Span::styled(format!("{:<STATE$}", "STATUS"), theme::column()),
        Span::raw("  "),
        Span::styled(format!("{:<SESSION$}", "SESSION"), theme::column()),
    ]);
    out.push(Line::from(headings));

    for (index, view) in app.nodes.iter().enumerate().skip(start).take(end - start) {
        let selected = index == app.selected;
        let cursor = if selected { ">" } else { " " };
        let mark = if app.marked.contains(&view.record.node_id) {
            "*"
        } else {
            " "
        };
        let endpoint = format!(
            "{}@{}:{}",
            view.record.ssh_user, view.record.host, view.record.ssh_port
        );
        // A running node says what it is doing (`installing htop`) rather than
        // repeating the word "running" for every command.
        let state = view.doing.as_deref().unwrap_or(view.status.text());
        let state_style = if view.doing.is_some() {
            theme::running()
        } else {
            theme::status(view.status)
        };

        let mut spans = vec![
            Span::styled(format!("{cursor}{mark} "), theme::dim()),
            Span::styled(
                format!("{:<label_width$}", fit(view.name(), label_width)),
                theme::strong(),
            ),
        ];
        if let Some(room) = address {
            spans.push(Span::raw("  "));
            spans.push(Span::styled(
                format!(
                    "{:<room$}",
                    fit(
                        &format!("{}:{}", view.record.host, view.record.op_port),
                        room
                    )
                ),
                theme::dim(),
            ));
        }
        if let Some(room) = ssh {
            spans.push(Span::raw("  "));
            spans.push(Span::styled(
                format!("{:<room$}", fit(&endpoint, room)),
                theme::dim(),
            ));
        }
        spans.extend([
            Span::raw("  "),
            Span::styled(format!("{:<STATE$}", fit(state, STATE)), state_style),
            Span::raw("  "),
        ]);

        match app.session_label(&view.record.node_id) {
            Some(label) => spans.push(Span::styled(
                format!("{:<SESSION$}", label),
                session_badge_style(label),
            )),
            None => spans.push(Span::styled(format!("{:<SESSION$}", "-"), theme::dim())),
        }

        if selected {
            spans = spans
                .into_iter()
                .map(|span| {
                    let style = theme::selected().patch(span.style);
                    span.style(style)
                })
                .collect();
        }
        out.push(Line::from(spans));
    }

    if with_detail {
        out.extend(detail);
    }
    out
}

/// The block under the node table: what the highlighted node is and what its
/// login is doing. Never longer than three lines, so the table keeps its rows.
fn node_detail(app: &App) -> Vec<Line<'static>> {
    let Some(view) = app.current() else {
        return Vec::new();
    };
    let mut out = vec![Line::from("")];
    let last = match &view.last {
        last if last.is_empty() => "no activity yet".to_string(),
        last => last.clone(),
    };
    out.push(Line::from(vec![
        Span::styled(view.name().to_string(), theme::strong()),
        Span::raw("   "),
        Span::styled(format!("node {}", view.record.node_id), theme::dim()),
        Span::raw("   "),
        Span::styled(last, theme::dim()),
    ]));

    out.push(session_line(app, &view.record.node_id, "ssh      "));
    out
}

/// The `ssh` line both the node block and the detail screen show: the state,
/// and what `s`/`x` will do about it. One owner, so the two screens cannot
/// describe the same login differently.
pub(super) fn session_line(app: &App, node_id: &str, prefix: &str) -> Line<'static> {
    match app.session_label(node_id) {
        Some(label) => Line::from(vec![
            Span::styled(prefix.to_string(), theme::label()),
            Span::styled(format!("{label}  "), session_badge_style(label)),
            Span::styled(
                if label == "closed" {
                    "s shows the last screen, x forgets it"
                } else {
                    "s resumes it, x terminates it"
                },
                theme::dim(),
            ),
        ]),
        None => Line::from(vec![
            Span::styled(prefix.to_string(), theme::label()),
            Span::styled("none; press s to open one", theme::dim()),
        ]),
    }
}

/// Which optional node columns fit at this width, and how wide each may be.
fn node_columns(width: usize, label: usize) -> (Option<usize>, Option<usize>) {
    let mut spare = width.saturating_sub(3 + label + 2 + STATE + 2 + SESSION);
    let address = if spare >= 12 {
        let room = spare.min(ADDRESS);
        spare = spare.saturating_sub(room + 2);
        Some(room)
    } else {
        None
    };
    let ssh = if spare >= 12 {
        Some(spare.min(SSH))
    } else {
        None
    };
    (address, ssh)
}

pub(super) fn session_badge_style(label: &str) -> Style {
    match label {
        "live" => theme::live(),
        "detached" => theme::detached(),
        _ => theme::closed(),
    }
}
