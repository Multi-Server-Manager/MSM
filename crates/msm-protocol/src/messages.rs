use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{ProtocolError, Result};

/// The protocol version this crate speaks.
pub const VERSION: u16 = 1;

/// Every message type defined in `PROTOCOL.md` §6 and §8.
pub const KNOWN_TYPES: [&str; 16] = [
    "pair.hello",
    "pair.challenge",
    "pair.proof",
    "pair.ok",
    "info",
    "info.ok",
    "error",
    "pkg.update",
    "pkg.install",
    "svc.restart",
    "host.reboot",
    "metrics.sample",
    "logs.tail",
    "ssh.authorize",
    "node.setup",
    "result",
];

/// The node's setup answers (§8.13): which account commands run as, where SSH
/// logins land, and the port a console dials.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Setup {
    pub run_as: String,
    pub ssh_user: String,
    pub ssh_port: u16,
}

impl Setup {
    /// The answer set a fresh install starts from.
    pub fn defaults() -> Self {
        Self {
            run_as: "root".to_string(),
            ssh_user: "root".to_string(),
            ssh_port: 22,
        }
    }
}

/// One wire message. The `t` member is the tag, so a serialised value carries
/// the type name exactly once.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t")]
pub enum Message {
    #[serde(rename = "pair.hello")]
    PairHello { v: u16, eph: String, nonce: String },

    #[serde(rename = "pair.challenge")]
    PairChallenge {
        v: u16,
        eph: String,
        nonce: String,
        node_id: String,
        node_spki: String,
        op_port: u16,
        ttl_left: u64,
        trials_left: u32,
    },

    #[serde(rename = "pair.proof")]
    PairProof {
        v: u16,
        mac: String,
        client_id: String,
        client_spki: String,
        /// Answers to the first-run questions; absent means "keep what the
        /// node already has".
        #[serde(default, skip_serializing_if = "Option::is_none")]
        setup: Option<Setup>,
    },

    #[serde(rename = "pair.ok")]
    PairOk {
        v: u16,
        mac: String,
        node_id: String,
        node_spki: String,
        op_port: u16,
        /// The node's own SSH public key, so the console can trust the return
        /// direction. Absent from a node older than the key exchange.
        #[serde(default, skip_serializing_if = "String::is_empty")]
        ssh_key: String,
        /// The answers the node now uses.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        setup: Option<Setup>,
        /// Why the answers cannot work yet, when they cannot (§8.13).
        #[serde(default, skip_serializing_if = "String::is_empty")]
        warn: String,
    },

    #[serde(rename = "info")]
    Info { v: u16 },

    #[serde(rename = "info.ok")]
    InfoOk {
        v: u16,
        node_id: String,
        hostname: String,
        os: String,
        version: String,
        pinned_clients: u32,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        ssh_key: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        setup: Option<Setup>,
    },

    #[serde(rename = "error")]
    Error {
        v: u16,
        code: String,
        detail: String,
    },

    #[serde(rename = "pkg.update")]
    PkgUpdate { v: u16, id: String },

    #[serde(rename = "pkg.install")]
    PkgInstall { v: u16, id: String, name: String },

    #[serde(rename = "svc.restart")]
    SvcRestart { v: u16, id: String, unit: String },

    #[serde(rename = "host.reboot")]
    HostReboot {
        v: u16,
        id: String,
        confirm: String,
    },

    #[serde(rename = "metrics.sample")]
    MetricsSample { v: u16, id: String },

    #[serde(rename = "logs.tail")]
    LogsTail { v: u16, id: String, lines: u32 },

    #[serde(rename = "ssh.authorize")]
    SshAuthorize {
        v: u16,
        id: String,
        key: String,
        /// The account the key is installed for; absent means the node's own
        /// configured SSH account.
        #[serde(default, skip_serializing_if = "String::is_empty")]
        user: String,
    },

    /// Change the node's setup answers from a pinned console (§8.13).
    #[serde(rename = "node.setup")]
    NodeSetup {
        v: u16,
        id: String,
        run_as: String,
        ssh_user: String,
        ssh_port: u16,
    },

    /// The single response envelope for every command (§8.4). Members that do
    /// not apply are absent, never empty strings or nulls.
    #[serde(rename = "result")]
    Result {
        v: u16,
        id: String,
        ok: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        code: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        detail: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        data: Option<Value>,
    },
}

impl Message {
    /// The value of the `t` member.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::PairHello { .. } => "pair.hello",
            Self::PairChallenge { .. } => "pair.challenge",
            Self::PairProof { .. } => "pair.proof",
            Self::PairOk { .. } => "pair.ok",
            Self::Info { .. } => "info",
            Self::InfoOk { .. } => "info.ok",
            Self::Error { .. } => "error",
            Self::PkgUpdate { .. } => "pkg.update",
            Self::PkgInstall { .. } => "pkg.install",
            Self::SvcRestart { .. } => "svc.restart",
            Self::HostReboot { .. } => "host.reboot",
            Self::MetricsSample { .. } => "metrics.sample",
            Self::LogsTail { .. } => "logs.tail",
            Self::SshAuthorize { .. } => "ssh.authorize",
            Self::NodeSetup { .. } => "node.setup",
            Self::Result { .. } => "result",
        }
    }
}

/// Serialise a message to its payload bytes.
pub fn encode(message: &Message) -> Result<Vec<u8>> {
    serde_json::to_vec(message)
        .map_err(|err| ProtocolError::Internal(format!("cannot encode a message: {err}")))
}

/// Parse a payload, enforcing the ordering and error codes of `PROTOCOL.md` §2.
///
/// The version is checked before the type, and an unrecognised type is
/// reported distinctly from a malformed one, so both implementations agree on
/// which code to send back.
pub fn decode(payload: &[u8]) -> Result<Message> {
    let value: Value = serde_json::from_slice(payload)
        .map_err(|_| ProtocolError::BadFrame("payload is not valid JSON".into()))?;

    let object = value
        .as_object()
        .ok_or_else(|| ProtocolError::BadFrame("payload is not a JSON object".into()))?;

    match object.get("v") {
        Some(Value::Number(number)) if number.as_u64() == Some(u64::from(VERSION)) => {}
        Some(Value::Number(number)) => {
            return Err(ProtocolError::BadVersion(format!(
                "protocol version {number}, want {VERSION}"
            )));
        }
        Some(_) => return Err(ProtocolError::BadVersion("v is not an integer".into())),
        None => return Err(ProtocolError::BadVersion("missing v".into())),
    }

    let kind = match object.get("t") {
        Some(Value::String(kind)) => kind.clone(),
        Some(_) => return Err(ProtocolError::BadFrame("t is not a string".into())),
        None => return Err(ProtocolError::BadFrame("missing t".into())),
    };

    if !KNOWN_TYPES.contains(&kind.as_str()) {
        return Err(ProtocolError::UnknownType(format!(
            "unknown message type {kind:?}"
        )));
    }

    serde_json::from_value(value)
        .map_err(|_| ProtocolError::BadFrame(format!("malformed {kind:?} payload")))
}
