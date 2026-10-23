//! Console state: the client identity and one pin per paired node.
//!
//! Everything lives under `~/.msm` with owner-only permissions. Only the pins
//! and public identifiers are stored; no pairing code is ever written.

use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use msm_protocol::tls::Identity;
use msm_protocol::{ProtocolError, Result};
use serde::{Deserialize, Serialize};

/// `~/.msm`, or `.msm` when the home directory is unknown.
pub fn default_state_dir() -> PathBuf {
    match std::env::var_os("HOME") {
        Some(home) => PathBuf::from(home).join(".msm"),
        None => PathBuf::from(".msm"),
    }
}

/// One paired node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeRecord {
    /// Node identity id, base64.
    pub node_id: String,
    /// Node identity pin, base64 SPKI.
    pub spki: String,
    /// Operator-facing name.
    pub label: String,
    /// Host, with brackets kept for IPv6 literals.
    pub host: String,
    /// Port of the node's operational listener.
    pub op_port: u16,
    /// Unix seconds when this pin was recorded.
    pub paired_at: u64,
    /// Account the SSH jump logs in as.
    #[serde(default = "default_ssh_user")]
    pub ssh_user: String,
    /// Port the SSH jump connects to.
    #[serde(default = "default_ssh_port")]
    pub ssh_port: u16,
}

fn default_ssh_user() -> String {
    "root".to_string()
}

fn default_ssh_port() -> u16 {
    22
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Registry {
    nodes: Vec<NodeRecord>,
}

#[derive(Debug, Serialize, Deserialize)]
struct StoredIdentity {
    id: String,
    key: String,
}

/// Create the state directory with owner-only permissions.
pub fn ensure_dir(dir: &Path) -> Result<()> {
    fs::create_dir_all(dir)?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

/// Load the console identity, creating it on first use.
pub fn load_or_create_identity(dir: &Path) -> Result<Identity> {
    ensure_dir(dir)?;
    let path = dir.join("identity.json");

    if path.exists() {
        let raw = fs::read_to_string(&path)?;
        let stored: StoredIdentity = serde_json::from_str(&raw)
            .map_err(|err| ProtocolError::Internal(format!("cannot parse identity.json: {err}")))?;
        return Identity::from_stored(&stored.id, &stored.key, "msm-client");
    }

    let identity = Identity::generate("msm-client")?;
    let stored = StoredIdentity {
        id: identity.id_b64(),
        key: identity.key_b64(),
    };
    let payload = serde_json::to_vec_pretty(&stored)
        .map_err(|err| ProtocolError::Internal(format!("cannot encode identity.json: {err}")))?;
    write_private(&path, &payload)?;
    Ok(identity)
}

/// Every paired node, ordered by label.
pub fn load_nodes(dir: &Path) -> Result<Vec<NodeRecord>> {
    let path = dir.join("nodes.json");
    if !path.exists() {
        return Ok(Vec::new());
    }
    let raw = fs::read_to_string(&path)?;
    let mut registry: Registry = serde_json::from_str(&raw)
        .map_err(|err| ProtocolError::Internal(format!("cannot parse nodes.json: {err}")))?;
    registry.nodes.sort_by(|a, b| a.label.cmp(&b.label));
    Ok(registry.nodes)
}

/// Insert or replace a node record, keyed by node id.
pub fn save_node(dir: &Path, record: NodeRecord) -> Result<()> {
    ensure_dir(dir)?;
    let mut nodes = load_nodes(dir)?;

    match nodes.iter_mut().find(|node| node.node_id == record.node_id) {
        Some(existing) => *existing = record,
        None => nodes.push(record),
    }

    let registry = Registry { nodes };
    let payload = serde_json::to_vec_pretty(&registry)
        .map_err(|err| ProtocolError::Internal(format!("cannot encode nodes.json: {err}")))?;
    write_private(&dir.join("nodes.json"), &payload)
}

/// Resolve a node by label, falling back to its id.
pub fn find_node(dir: &Path, target: &str) -> Result<NodeRecord> {
    let nodes = load_nodes(dir)?;
    nodes
        .iter()
        .find(|node| node.label == target)
        .or_else(|| nodes.iter().find(|node| node.node_id == target))
        .cloned()
        .ok_or_else(|| ProtocolError::Internal(format!("no paired node named {target:?}")))
}

/// Seconds since the Unix epoch.
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

fn write_private(path: &Path, payload: &[u8]) -> Result<()> {
    let temporary = path.with_extension("tmp");
    {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(payload)?;
        file.sync_all()?;
    }
    fs::rename(&temporary, path)?;
    Ok(())
}
