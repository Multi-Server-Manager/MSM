//! The operational command surface: request construction, result payloads and
//! the field validators both implementations must agree on (`PROTOCOL.md` §8).

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::messages::{Message, Setup, VERSION};

/// Largest `lines` value `logs.tail` accepts.
pub const MAX_LOG_LINES: u32 = 500;
/// Longest package name accepted.
pub const MAX_PACKAGE_NAME_LEN: usize = 64;
/// Longest service unit name accepted.
pub const MAX_UNIT_LEN: usize = 64;
/// Longest request id accepted.
pub const MAX_REQUEST_ID_LEN: usize = 64;
/// Longest account name accepted.
pub const MAX_ACCOUNT_NAME_LEN: usize = 32;
/// The one token `host.reboot` accepts.
pub const REBOOT_CONFIRMATION: &str = "reboot";

/// One operational request, before it is given an id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    PkgUpdate,
    PkgInstall(String),
    /// Empty, `self` or `msm-node` all mean the agent itself.
    SvcRestart(String),
    HostReboot(String),
    MetricsSample,
    LogsTail(u32),
    /// Change the answers the node's first pairing asked for.
    NodeSetup(Setup),
}

impl Command {
    /// Render this request as the wire message it is.
    pub fn into_message(self, id: &str) -> Message {
        match self {
            Self::PkgUpdate => Message::PkgUpdate {
                v: VERSION,
                id: id.to_string(),
            },
            Self::PkgInstall(name) => Message::PkgInstall {
                v: VERSION,
                id: id.to_string(),
                name,
            },
            Self::SvcRestart(unit) => Message::SvcRestart {
                v: VERSION,
                id: id.to_string(),
                unit,
            },
            Self::HostReboot(confirm) => Message::HostReboot {
                v: VERSION,
                id: id.to_string(),
                confirm,
            },
            Self::MetricsSample => Message::MetricsSample {
                v: VERSION,
                id: id.to_string(),
            },
            Self::LogsTail(lines) => Message::LogsTail {
                v: VERSION,
                id: id.to_string(),
                lines,
            },
            Self::NodeSetup(setup) => Message::NodeSetup {
                v: VERSION,
                id: id.to_string(),
                run_as: setup.run_as,
                ssh_user: setup.ssh_user,
                ssh_port: setup.ssh_port,
            },
        }
    }

    /// Short human description, used in reports and labels.
    pub fn describe(&self) -> String {
        match self {
            Self::PkgUpdate => "pkg.update".to_string(),
            Self::PkgInstall(name) => format!("pkg.install {name}"),
            Self::SvcRestart(unit) if unit.is_empty() => "svc.restart self".to_string(),
            Self::SvcRestart(unit) => format!("svc.restart {unit}"),
            Self::HostReboot(_) => "host.reboot".to_string(),
            Self::MetricsSample => "metrics.sample".to_string(),
            Self::LogsTail(lines) => format!("logs.tail {lines}"),
            Self::NodeSetup(setup) => format!(
                "node.setup run_as={} ssh_user={} ssh_port={}",
                setup.run_as, setup.ssh_user, setup.ssh_port
            ),
        }
    }
}

/// Build a successful `result`.
pub fn success(id: &str, data: Value) -> Message {
    Message::Result {
        v: VERSION,
        id: id.to_string(),
        ok: true,
        code: None,
        detail: None,
        data: Some(data),
    }
}

/// Build a refused `result`, with an optional payload for the client to show.
pub fn failure(id: &str, code: &str, detail: &str, data: Option<Value>) -> Message {
    Message::Result {
        v: VERSION,
        id: id.to_string(),
        ok: false,
        code: Some(code.to_string()),
        detail: Some(detail.to_string()),
        data,
    }
}

/// `pkg.update` and `pkg.install` payload (§8.5, §8.6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageResult {
    pub manager: String,
    pub commands: Vec<Vec<String>>,
    pub exit_code: i64,
    pub output: String,
    /// The outcome in one sentence — "there were no updates", "3 packages
    /// were updated", "figlet was installed". Display text only: `exit_code`
    /// is what says whether the run succeeded. Absent from older nodes, so
    /// readers fall back to the exit code and manager name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
}

/// `svc.restart` payload (§8.7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceResult {
    pub unit: String,
    pub method: String,
}

/// `host.reboot` payload (§8.8).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebootResult {
    pub method: String,
}

/// `metrics.sample` payload (§8.9).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MetricsResult {
    pub load1: f64,
    pub load5: f64,
    pub load15: f64,
    pub cpu_count: u32,
    pub mem_total_kb: u64,
    pub mem_available_kb: u64,
    pub uptime_s: u64,
    pub disk_total_kb: u64,
    pub disk_available_kb: u64,
}

/// `ssh.authorize` payload (§8.11).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshAuthorizeResult {
    pub path: String,
    pub added: bool,
    #[serde(default)]
    pub user: String,
}

/// `node.setup` payload (§8.13): the answers the node now uses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetupResult {
    pub run_as: String,
    pub ssh_user: String,
    pub ssh_port: u16,
    /// Present when the node cannot escalate to `run_as` yet.
    #[serde(default)]
    pub warn: String,
}

/// `logs.tail` payload (§8.10).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogsResult {
    pub lines: Vec<String>,
    pub dropped: u64,
}

/// Package name charset, and never a leading flag or path character (§8.3).
pub fn valid_package_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_PACKAGE_NAME_LEN {
        return false;
    }
    let first = bytes[0];
    if !first.is_ascii_alphanumeric() && first != b'_' {
        return false;
    }
    bytes.iter().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'+' | b'-')
    })
}

/// Service unit charset, and never a leading flag character (§8.3).
pub fn valid_unit(unit: &str) -> bool {
    let bytes = unit.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_UNIT_LEN {
        return false;
    }
    let first = bytes[0];
    if !first.is_ascii_alphanumeric() && first != b'@' && first != b'_' {
        return false;
    }
    bytes.iter().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'@' | b':' | b'-')
    })
}

/// Account names the node may look up (§8.13).
pub fn valid_account(name: &str) -> bool {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_ACCOUNT_NAME_LEN {
        return false;
    }
    let first = bytes[0];
    if !(first.is_ascii_lowercase() || first == b'_') {
        return false;
    }
    bytes.iter().all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'.' | b'-')
    })
}

/// Request ids travel back in a `result`, so they stay to a printable alphabet.
pub fn valid_request_id(id: &str) -> bool {
    let bytes = id.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= MAX_REQUEST_ID_LEN
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}
