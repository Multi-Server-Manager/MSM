//! Background work for the panel.
//!
//! Every request runs on its own thread and reports back over one channel, so a
//! slow node never freezes the screen and each row can update in place.
//!
//! A user command carries an id. The panel uses it to count the targets of one
//! action and to draw a progress line while it runs; background refreshes
//! (metrics, log tails) use id 0 and never touch that line.

use std::path::PathBuf;
use std::sync::mpsc::Sender;
use std::thread;

use msm_protocol::Message;
use msm_protocol::commands::{Command, LogsResult, MetricsResult};
use msm_protocol::messages::Setup;
use serde_json::Value;

use crate::discovery;
use crate::fanout::request_id;
use crate::human;
use crate::mdns::Discovered;
use crate::net;
use crate::store::NodeRecord;

/// How many metrics samples a node keeps.
pub const HISTORY: usize = 32;

/// The id background work reports with: it is never a user command.
pub const BACKGROUND: u64 = 0;

/// One usage sample, reduced to what the panel draws.
#[derive(Clone, Copy, Debug)]
pub struct Sample {
    pub load1: f64,
    pub memory_pct: f64,
    pub memory_total_kb: u64,
    pub disk_pct: f64,
}

/// Everything a worker thread can tell the panel.
pub enum Msg {
    Started {
        node: String,
        id: u64,
    },
    Finished {
        node: String,
        id: u64,
        ok: bool,
        summary: String,
    },
    Sample {
        node: String,
        sample: Sample,
    },
    Logs {
        node: String,
        lines: Vec<String>,
    },
    Paired {
        record: Box<NodeRecord>,
        warning: Option<String>,
    },
    /// The node accepted (or refused) an edited setup.
    Configured {
        record: Box<NodeRecord>,
        warning: Option<String>,
    },
    Discovered(Vec<Discovered>),
    Failed(String),
}

/// Run one command against one node and report start, result and payload.
pub fn action(state_dir: PathBuf, record: NodeRecord, request: Command, id: u64, tx: Sender<Msg>) {
    thread::spawn(move || {
        let node = record.node_id.clone();
        if tx
            .send(Msg::Started {
                node: node.clone(),
                id,
            })
            .is_err()
        {
            return;
        }

        let address = format!("{}:{}", record.host, record.op_port);
        let message = request.clone().into_message(&request_id());
        let reply = net::request(
            &state_dir,
            &record,
            &message,
            net::command_timeout(&request),
        );

        let (ok, summary) = match reply {
            Ok(Message::Result {
                ok,
                code,
                detail,
                data,
                ..
            }) => {
                if let Some(sample) = data.as_ref().and_then(parse_metrics) {
                    let _ = tx.send(Msg::Sample {
                        node: node.clone(),
                        sample,
                    });
                }
                if let Some(lines) = data.as_ref().and_then(parse_logs) {
                    let _ = tx.send(Msg::Logs {
                        node: node.clone(),
                        lines,
                    });
                }
                if ok {
                    (true, describe_success(data.as_ref()))
                } else {
                    (false, human::refusal(code.as_deref(), detail.as_deref()))
                }
            }
            Ok(Message::Error { code, detail, .. }) => {
                (false, human::refusal(Some(&code), Some(&detail)))
            }
            Ok(other) => (false, format!("unexpected {} reply", other.kind())),
            Err(err) => (false, human::command(&err, &address)),
        };

        let _ = tx.send(Msg::Finished {
            node,
            id,
            ok,
            summary,
        });
    });
}

/// Ask one node for its metrics (background, no progress line).
pub fn metrics(state_dir: PathBuf, record: NodeRecord, tx: Sender<Msg>) {
    action(state_dir, record, Command::MetricsSample, BACKGROUND, tx);
}

/// Ask one node for the tail of its log (background, no progress line).
pub fn logs(state_dir: PathBuf, record: NodeRecord, lines: u32, tx: Sender<Msg>) {
    action(state_dir, record, Command::LogsTail(lines), BACKGROUND, tx);
}

/// Pair with a node and install the console's SSH key.
pub fn pair(
    state_dir: PathBuf,
    addr: String,
    code: String,
    label: String,
    setup: Setup,
    tx: Sender<Msg>,
) {
    thread::spawn(
        move || match net::pair(&state_dir, &addr, &code, &label, &setup) {
            Ok(outcome) => {
                let _ = tx.send(Msg::Paired {
                    record: Box::new(outcome.record),
                    warning: outcome.ssh_warning,
                });
            }
            Err(err) => {
                let _ = tx.send(Msg::Failed(human::pairing(&err, &addr)));
            }
        },
    );
}

/// Push edited answers to a node, then make sure the console key is installed
/// for the account that will receive it.
pub fn configure(state_dir: PathBuf, record: NodeRecord, setup: Setup, tx: Sender<Msg>) {
    thread::spawn(move || {
        let endpoint = format!("{}:{}", record.host, record.op_port);
        let mut warnings = Vec::new();

        let updated = match net::configure(&state_dir, &record, &setup) {
            Ok((updated, warning)) => {
                if let Some(warning) = warning {
                    warnings.push(warning);
                }
                Some(updated)
            }
            Err(err) => {
                warnings.push(format!(
                    "the node did not accept the change: {}",
                    human::command(&err, &endpoint)
                ));
                None
            }
        };

        let target = updated.as_ref().unwrap_or(&record);
        match crate::sshkey::SshKey::load_or_create(&state_dir) {
            Ok(key) => {
                if let Err(err) =
                    net::authorize_ssh_key(&state_dir, target, &key.public_line, &setup.ssh_user)
                {
                    warnings.push(format!("the console key was not installed: {err}"));
                }
            }
            Err(err) => warnings.push(format!("cannot load the console key: {err}")),
        }

        let _ = tx.send(Msg::Configured {
            record: Box::new(target.clone()),
            warning: if warnings.is_empty() {
                None
            } else {
                Some(warnings.join("; "))
            },
        });
    });
}

/// Browse the local network and the tailnet for nodes.
pub fn discover(state_dir: PathBuf, tx: Sender<Msg>) {
    thread::spawn(move || {
        let found = discovery::browse(&state_dir, std::time::Duration::from_millis(1200));
        let _ = tx.send(Msg::Discovered(found));
    });
}

fn parse_metrics(data: &Value) -> Option<Sample> {
    let payload: MetricsResult = serde_json::from_value(data.clone()).ok()?;
    let total = payload.mem_total_kb.max(1);
    let available = payload.mem_available_kb.min(total);
    let disk_total = payload.disk_total_kb.max(1);
    let disk_available = payload.disk_available_kb.min(disk_total);

    Some(Sample {
        load1: payload.load1,
        memory_pct: 100.0 * (total - available) as f64 / total as f64,
        memory_total_kb: payload.mem_total_kb,
        disk_pct: 100.0 * (disk_total - disk_available) as f64 / disk_total as f64,
    })
}

fn parse_logs(data: &Value) -> Option<Vec<String>> {
    let payload: LogsResult = serde_json::from_value(data.clone()).ok()?;
    Some(payload.lines)
}

/// One line a human can read for a successful result.
fn describe_success(data: Option<&Value>) -> String {
    let Some(data) = data else {
        return "ok".to_string();
    };
    match serde_json::from_value::<PackageResultView>(data.clone()) {
        // The node names the outcome in a sentence. Only an older node (or a
        // run that never reached the manager) has nothing better than numbers.
        Ok(package) => package
            .summary
            .filter(|summary| !summary.is_empty())
            .unwrap_or_else(|| {
                format!(
                    "finished via {} (exit {})",
                    package.manager, package.exit_code
                )
            }),
        Err(_) => "ok".to_string(),
    }
}

#[derive(serde::Deserialize)]
struct PackageResultView {
    manager: String,
    exit_code: i64,
    #[serde(default)]
    summary: Option<String>,
}
