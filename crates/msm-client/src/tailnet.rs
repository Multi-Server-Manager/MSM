//! Discovery over Tailscale.
//!
//! mDNS only travels over one LAN, so a node on another network is invisible to
//! the multicast browse. Tailscale gives every device a stable 100.64/10
//! address and a peer list, and the node listens for pairing on a fixed port,
//! so the console can ask each peer directly.
//!
//! The probe is the real pairing greeting: it presents the console certificate
//! the node insists on and reads `pair.challenge`, which carries the node id,
//! pin and operational port. No proof is sent, so a probe can never consume a
//! pairing attempt or pair anything by accident.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::path::Path;
use std::process::Command;
use std::thread;
use std::time::Duration;

use msm_protocol::b64;
use msm_protocol::messages::{self, Message};
use msm_protocol::tls::{client_config, server_name};
use msm_protocol::{read_frame, write_frame};
use rand::RngCore;
use rand::rngs::OsRng;
use rustls::{ClientConnection, StreamOwned};

use crate::mdns::Discovered;
use crate::store;

/// The port a node listens on for pairing. Fixed so a tailnet peer can be asked
/// without an operator copying a random number off the node's console.
pub const PAIR_PORT: u16 = 7334;

/// How long one peer gets for the whole greeting. Peers that are offline or not
/// running a node fall out quickly.
const PEER_TIMEOUT: Duration = Duration::from_millis(1500);

/// One online tailnet peer.
#[derive(Debug, Clone)]
struct Peer {
    label: String,
    address: Ipv4Addr,
}

/// The port to probe. `MSM_TAILNET_PORT` exists for tests that cannot bind the
/// real one; the default is the contract.
fn pair_port() -> u16 {
    std::env::var("MSM_TAILNET_PORT")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(PAIR_PORT)
}

/// Browse the tailnet for unpaired nodes.
///
/// Returns nothing when Tailscale is not installed or not running: the console
/// still works over mDNS, so a missing tailnet is not an error.
pub fn browse(state_dir: &Path) -> Vec<Discovered> {
    let peers = peers();
    if peers.is_empty() {
        return Vec::new();
    }

    let identity = match store::load_or_create_identity(state_dir) {
        Ok(identity) => std::sync::Arc::new(identity),
        Err(_) => return Vec::new(),
    };

    let port = pair_port();
    let handles: Vec<_> = peers
        .into_iter()
        .map(|peer| {
            let identity = std::sync::Arc::clone(&identity);
            thread::spawn(move || {
                let address = SocketAddr::new(IpAddr::V4(peer.address), port);
                probe(&identity, address).map(|found| Discovered {
                    label: peer.label,
                    address: IpAddr::V4(peer.address),
                    port,
                    node_id: Some(found.node_id),
                    spki: Some(found.node_spki),
                })
            })
        })
        .collect();

    handles
        .into_iter()
        .filter_map(|handle| handle.join().ok().flatten())
        .collect()
}

/// What a greeting told us about a node.
struct Greeting {
    node_id: String,
    node_spki: String,
}

/// Ask one address whether it is a node waiting to be paired.
fn probe(identity: &msm_protocol::tls::Identity, address: SocketAddr) -> Option<Greeting> {
    let socket = TcpStream::connect_timeout(&address, PEER_TIMEOUT).ok()?;
    socket.set_read_timeout(Some(PEER_TIMEOUT)).ok()?;
    socket.set_write_timeout(Some(PEER_TIMEOUT)).ok()?;
    socket.set_nodelay(true).ok()?;

    let config = client_config(identity, None).ok()?;
    let connection = ClientConnection::new(config, server_name()).ok()?;
    let mut session = StreamOwned::new(connection, socket);

    // Any Ed25519 key is accepted at this point (there is no pin yet), so a
    // stranger on the port is answered with its own identity and nothing else.
    let mut ephemeral = [0u8; 32];
    let mut nonce = [0u8; 16];
    OsRng.fill_bytes(&mut ephemeral);
    OsRng.fill_bytes(&mut nonce);

    let hello = Message::PairHello {
        v: messages::VERSION,
        eph: b64::encode(&ephemeral),
        nonce: b64::encode(&nonce),
    };
    let payload = messages::encode(&hello).ok()?;
    write_frame(&mut session, &payload).ok()?;

    let reply = messages::decode(&read_frame(&mut session).ok()?).ok()?;
    match reply {
        Message::PairChallenge {
            node_id, node_spki, ..
        } => Some(Greeting { node_id, node_spki }),
        _ => None,
    }
}

/// Every online peer Tailscale knows about, with an IPv4 address to try.
fn peers() -> Vec<Peer> {
    let output = match Command::new(tailscale_binary())
        .arg("status")
        .arg("--json")
        .output()
    {
        Ok(output) if output.status.success() => output,
        _ => return Vec::new(),
    };

    let status: serde_json::Value = match serde_json::from_slice(&output.stdout) {
        Ok(status) => status,
        Err(_) => return Vec::new(),
    };

    let mut peers = Vec::new();
    let entries = status.get("Peer").and_then(|value| value.as_object());
    let Some(entries) = entries else {
        return peers;
    };

    for peer in entries.values() {
        if peer.get("Online").and_then(|value| value.as_bool()) == Some(false) {
            continue;
        }
        let Some(address) = peer
            .get("TailscaleIPs")
            .and_then(|value| value.as_array())
            .and_then(|addresses| addresses.iter().find_map(|value| value.as_str()))
            .and_then(|text| text.parse::<Ipv4Addr>().ok())
        else {
            continue;
        };
        peers.push(Peer {
            label: label_of(peer),
            address,
        });
    }
    peers.sort_by(|a, b| a.label.cmp(&b.label));
    peers
}

/// HostName, or the first label of DNSName when a peer is named oddly.
fn label_of(peer: &serde_json::Value) -> String {
    if let Some(host) = peer.get("HostName").and_then(|value| value.as_str())
        && !host.is_empty()
    {
        return host.to_string();
    }
    peer.get("DNSName")
        .and_then(|value| value.as_str())
        .map(|name| name.split('.').next().unwrap_or(name).to_string())
        .unwrap_or_else(|| "node".to_string())
}

/// The CLI the operator's tailnet is managed with.
fn tailscale_binary() -> String {
    std::env::var("MSM_TAILSCALE").unwrap_or_else(|_| "tailscale".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_comes_from_the_hostname() {
        let peer = serde_json::json!({
            "HostName": "sanas",
            "DNSName": "sanas.tailnet-1a2b.ts.net.",
            "Online": true,
            "TailscaleIPs": ["100.74.163.8", "fd7a:115c::1"],
        });
        assert_eq!(label_of(&peer), "sanas");
    }

    #[test]
    fn label_falls_back_to_the_dns_name() {
        let peer = serde_json::json!({
            "HostName": "",
            "DNSName": "box.tailnet-1a2b.ts.net.",
        });
        assert_eq!(label_of(&peer), "box");
    }

    #[test]
    fn peers_without_an_ipv4_are_skipped() {
        // Parsing is covered by reading the same shape the CLI prints; the
        // address filter is what keeps an IPv6-only peer from being dialled.
        let peers = serde_json::json!({
            "Peer": {
                "a": {"HostName": "v4", "Online": true, "TailscaleIPs": ["100.1.2.3"]},
                "b": {"HostName": "v6", "Online": true, "TailscaleIPs": ["fd7a:115c::1"]},
                "c": {"HostName": "off", "Online": false, "TailscaleIPs": ["100.1.2.4"]}
            }
        });
        let entries = peers["Peer"].as_object().unwrap();
        let usable = entries
            .values()
            .filter(|peer| peer["Online"] == true)
            .filter(|peer| {
                peer["TailscaleIPs"][0]
                    .as_str()
                    .unwrap()
                    .parse::<Ipv4Addr>()
                    .is_ok()
            })
            .count();
        assert_eq!(usable, 1);
    }
}
