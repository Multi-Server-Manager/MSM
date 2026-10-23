//! One answer to "which nodes can I pair with right now?".
//!
//! Two transports, asked at the same time: multicast DNS for the local network
//! (PROTOCOL.md §9) and the Tailscale probe for the tailnet (`tailnet.rs`).
//! A node that answers both is listed once.

use std::collections::HashSet;
use std::path::Path;
use std::thread;
use std::time::Duration;

use crate::mdns::{self, Discovered};
use crate::tailnet;

/// Browse both transports and merge the answers.
pub fn browse(state_dir: &Path, window: Duration) -> Vec<Discovered> {
    browse_sources(state_dir, window, false)
}

/// Browse the tailnet only. Useful when a firewall drops multicast, and the
/// only way to test the tailnet path without a second network.
pub fn browse_tailnet(state_dir: &Path) -> Vec<Discovered> {
    browse_sources(state_dir, Duration::ZERO, true)
}

fn browse_sources(state_dir: &Path, window: Duration, tailnet_only: bool) -> Vec<Discovered> {
    if tailnet_only {
        return tailnet::browse(state_dir);
    }

    let lan = thread::spawn(move || mdns::browse(window).unwrap_or_default());
    let state_dir = state_dir.to_path_buf();
    let tail = thread::spawn(move || tailnet::browse(&state_dir));

    let mut found = lan.join().unwrap_or_default();
    found.extend(tail.join().unwrap_or_default());

    // The same node can answer over the LAN and the tailnet; the first answer
    // wins, which keeps the LAN endpoint when the console is on that network.
    let mut seen = HashSet::new();
    found.retain(|node| match &node.node_id {
        Some(id) => seen.insert(id.clone()),
        None => seen.insert(node.endpoint()),
    });
    found.sort_by(|a, b| a.label.cmp(&b.label));
    found
}
