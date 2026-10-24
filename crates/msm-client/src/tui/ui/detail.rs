//! One node in full: what it is, what it is doing, and its gauges.

use ratatui::style::Style;
use ratatui::text::{Line, Span};

use super::super::app::App;
use super::super::theme;
use super::super::worker::Sample;
use super::nodes::session_line;
use super::widgets::{bar, fit, header, rule, sparkline};

pub(super) fn detail(app: &App, width: usize, out: &mut Vec<Line<'static>>) {
    // The caller windows this screen by `App::scroll`; nothing here knows the
    // terminal height, so the gauges are the same at every size.
    let Some(view) = app.current() else {
        out.push(header("msm  node", "none", width));
        out.push(rule(width));
        out.push(Line::from(Span::styled("no paired nodes", theme::dim())));
        return;
    };

    out.push(header(
        &format!("msm  {}", view.name()),
        &format!("{}:{}", view.record.host, view.record.op_port),
        width,
    ));
    out.push(rule(width));
    let state = view.doing.as_deref().unwrap_or(view.status.text());
    let state_style = if view.doing.is_some() {
        theme::running()
    } else {
        theme::status(view.status)
    };
    // One summary line, narrowed in this order: the ssh endpoint goes first,
    // then the node id, so the status is always readable.
    let mut summary = vec![Span::styled("node ", theme::label())];
    let id_room = if width >= 64 {
        width.saturating_sub(64).max(12)
    } else {
        width.saturating_sub(20).max(6)
    };
    summary.push(Span::styled(
        fit(&view.record.node_id, id_room),
        theme::dim(),
    ));
    if width >= 64 {
        summary.push(Span::styled("   ssh ", theme::label()));
        summary.push(Span::raw(format!(
            "{}@{}:{}",
            view.record.ssh_user, view.record.host, view.record.ssh_port
        )));
    }
    summary.push(Span::styled("   status ", theme::label()));
    summary.push(Span::styled(state.to_string(), state_style));
    out.push(Line::from(summary));
    out.push(session_line(app, &view.record.node_id, "ssh session "));
    out.push(Line::from(""));

    let samples: Vec<Sample> = view.history.iter().copied().collect();
    if samples.is_empty() {
        out.push(Line::from(Span::styled("collecting samples", theme::dim())));
    } else {
        let loads: Vec<f64> = samples.iter().map(|sample| sample.load1).collect();
        let latest = samples[samples.len() - 1];
        out.push(Line::from(vec![
            Span::styled(format!("{:9} ", "load"), theme::label()),
            Span::styled(format!("{:.2}", latest.load1), Style::default()),
        ]));
        out.push(Line::from(vec![
            Span::raw("          "),
            Span::styled(sparkline(&loads, 24), theme::subtitle()),
        ]));
        out.push(Line::from(""));
        out.push(Line::from(vec![
            Span::styled(format!("{:9} ", "memory"), theme::label()),
            Span::raw(format!(
                "{:.0}% of {} MiB",
                latest.memory_pct,
                latest.memory_total_kb / 1024
            )),
        ]));
        out.push(Line::from(vec![
            Span::raw("          "),
            Span::styled(bar(latest.memory_pct, 24), theme::gauge(latest.memory_pct)),
            Span::styled(
                format!(" {:.0}%", latest.memory_pct),
                theme::gauge(latest.memory_pct),
            ),
        ]));
        out.push(Line::from(""));
        out.push(Line::from(vec![
            Span::styled(format!("{:9} ", "disk"), theme::label()),
            Span::raw(format!("{:.0}% used", latest.disk_pct)),
        ]));
        out.push(Line::from(vec![
            Span::raw("          "),
            Span::styled(bar(latest.disk_pct, 24), theme::gauge(latest.disk_pct)),
            Span::styled(
                format!(" {:.0}%", latest.disk_pct),
                theme::gauge(latest.disk_pct),
            ),
        ]));
        out.push(Line::from(""));
        out.push(Line::from(Span::styled(
            format!(
                "{} samples   updated {}",
                samples.len(),
                view.updated
                    .map(|at| format!("{}s ago", at.elapsed().as_secs()))
                    .unwrap_or_else(|| "-".to_string())
            ),
            theme::dim(),
        )));
    }

    out.push(Line::from(""));
    let last = if view.last.is_empty() {
        "none".to_string()
    } else {
        view.last.clone()
    };
    out.push(Line::from(vec![
        Span::styled("last      ", theme::label()),
        Span::styled(last, Style::default()),
    ]));
}

/// Rows the detail screen's body has; the keys use it to clamp scrolling.
pub fn detail_body_len(app: &App, width: usize) -> usize {
    let mut lines = Vec::new();
    detail(app, width, &mut lines);
    lines.len()
}
