//! How a command outcome is shown to a human.
//!
//! One header line per node — label, state, what was asked, and either the
//! payload summary or the refusal — followed by the captured process output
//! indented under it.

use std::fmt::Write as _;

use msm_protocol::Message;
use msm_protocol::commands::{
    Command, LogsResult, MetricsResult, PackageResult, RebootResult, ServiceResult, SetupResult,
};
use serde_json::Value;

use crate::fanout::Outcome;

/// Render one node's outcome as printable lines.
pub fn lines(outcome: &Outcome, command: &Command, width: usize) -> Vec<String> {
    let label = &outcome.label;
    let mut out = Vec::new();

    match &outcome.reply {
        Err(err) => {
            out.push(format!(
                "{label:<width$}  {:<8} {}  error={err}",
                "error",
                command.describe()
            ));
        }
        Ok(Message::Error { code, detail, .. }) => {
            out.push(format!(
                "{label:<width$}  {:<8} {}  code={code}  detail={detail}",
                "refused",
                command.describe()
            ));
        }
        Ok(Message::Result { ok, .. }) => {
            let state = if *ok { "ok" } else { "failed" };
            let mut header = format!("{label:<width$}  {state:<8} {}", command.describe());

            if let Some(code) = outcome.code() {
                let _ = write!(header, "  code={code}");
            }
            if let Some(detail) = outcome.detail() {
                let _ = write!(header, "  detail={detail}");
            }

            if outcome.elapsed >= std::time::Duration::from_secs(1) {
                let _ = write!(header, "  took={:.1}s", outcome.elapsed.as_secs_f64());
            }

            let mut extra = Vec::new();
            if let Some(data) = outcome.data()
                && let Some(summary) = summary(command, data, &mut extra)
            {
                let _ = write!(header, "  {summary}");
            }
            out.push(header);
            out.extend(extra.into_iter().map(|line| format!("    {line}")));
        }
        Ok(other) => {
            out.push(format!(
                "{label:<width$}  {:<8} {}  unexpected={}",
                "error",
                command.describe(),
                other.kind()
            ));
        }
    }

    out
}

/// One-line summary of the payload, plus any lines to show underneath it.
fn summary(command: &Command, data: &Value, extra: &mut Vec<String>) -> Option<String> {
    match command {
        Command::PkgUpdate | Command::PkgInstall(_) => {
            let payload: PackageResult = serde_json::from_value(data.clone()).ok()?;
            extra.extend(output_lines(&payload.output));
            Some(format!("exit={} manager={}", payload.exit_code, payload.manager))
        }
        Command::MetricsSample => {
            let payload: MetricsResult = serde_json::from_value(data.clone()).ok()?;
            Some(format!(
                "load={:.2}/{:.2}/{:.2} cpu={} mem_total={}MiB mem_avail={}MiB uptime={}s disk_total={}MiB disk_avail={}MiB",
                payload.load1,
                payload.load5,
                payload.load15,
                payload.cpu_count,
                payload.mem_total_kb / 1024,
                payload.mem_available_kb / 1024,
                payload.uptime_s,
                payload.disk_total_kb / 1024,
                payload.disk_available_kb / 1024
            ))
        }
        Command::LogsTail(_) => {
            let payload: LogsResult = serde_json::from_value(data.clone()).ok()?;
            extra.extend(payload.lines.iter().cloned());
            Some(format!(
                "lines={} dropped={}",
                payload.lines.len(),
                payload.dropped
            ))
        }
        Command::SvcRestart(_) => {
            let payload: ServiceResult = serde_json::from_value(data.clone()).ok()?;
            Some(format!("unit={} method={}", payload.unit, payload.method))
        }
        Command::HostReboot(_) => {
            let payload: RebootResult = serde_json::from_value(data.clone()).ok()?;
            Some(format!("method={}", payload.method))
        }
        Command::NodeSetup(_) => {
            let payload: SetupResult = serde_json::from_value(data.clone()).ok()?;
            Some(format!(
                "run_as={} ssh_user={} ssh_port={}",
                payload.run_as, payload.ssh_user, payload.ssh_port
            ))
        }
    }
}

fn output_lines(output: &str) -> Vec<String> {
    output
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| line.to_string())
        .collect()
}
