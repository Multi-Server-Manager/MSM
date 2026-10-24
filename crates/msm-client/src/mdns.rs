//! Discovery of nodes on the local network (PROTOCOL.md §9).
//!
//! One question, a short wait, and whatever answers: no daemon, no cache. The
//! result only ever suggests a target — trust still comes from pairing.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use msm_protocol::{ProtocolError, Result};

/// The DNS-SD service type both implementations agree on.
pub const SERVICE: &str = "_msm-node._tcp.local.";

const GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const PORT: u16 = 5353;
const TYPE_A: u16 = 1;
const TYPE_PTR: u16 = 12;
const TYPE_TXT: u16 = 16;
const TYPE_SRV: u16 = 33;

/// One node that answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Discovered {
    /// Instance label, e.g. `msmenv-1`.
    pub label: String,
    /// Address from the A record.
    pub address: IpAddr,
    /// Port from the SRV record.
    pub port: u16,
    /// TXT `id=`, when present.
    pub node_id: Option<String>,
    /// TXT `spki=`, when present.
    pub spki: Option<String>,
}

impl Discovered {
    /// `host:port` for the dialer, bracketing IPv6.
    pub fn endpoint(&self) -> String {
        match self.address {
            IpAddr::V4(_) => format!("{}:{}", self.address, self.port),
            IpAddr::V6(_) => format!("[{}]:{}", self.address, self.port),
        }
    }
}

/// Browse for nodes for `window` and return everything that answered.
pub fn browse(window: Duration) -> Result<Vec<Discovered>> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
    socket.set_read_timeout(Some(Duration::from_millis(200)))?;
    socket.send_to(&query(), SocketAddr::from((GROUP, PORT)))?;

    let deadline = Instant::now() + window;
    let mut buffer = [0u8; 2048];
    let mut records = Records::default();

    while Instant::now() < deadline {
        match socket.recv_from(&mut buffer) {
            Ok((count, _)) => records.absorb(&buffer[..count]),
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(err) if err.kind() == std::io::ErrorKind::TimedOut => {}
            Err(err) => return Err(ProtocolError::Io(err)),
        }
    }

    records
        .finish()
        .map_err(|_| ProtocolError::Internal("an mDNS answer could not be parsed".to_string()))
}

/// The PTR question for the service type.
fn query() -> Vec<u8> {
    let mut packet = vec![0u8; 12];
    packet[5] = 1; // one question
    push_name(&mut packet, SERVICE);
    push_u16(&mut packet, TYPE_PTR);
    push_u16(&mut packet, 1); // class IN
    packet
}

/// Records collected across every answer packet, keyed by instance name.
#[derive(Default)]
struct Records {
    ptr: HashMap<String, String>,
    srv: HashMap<String, (u16, String)>,
    txt: HashMap<String, (Option<String>, Option<String>)>,
    a: HashMap<String, IpAddr>,
}

impl Records {
    fn absorb(&mut self, packet: &[u8]) {
        if packet.len() < 12 {
            return;
        }
        let questions = u16::from_be_bytes([packet[4], packet[5]]) as usize;
        let answers = u16::from_be_bytes([packet[6], packet[7]]) as usize
            + u16::from_be_bytes([packet[8], packet[9]]) as usize
            + u16::from_be_bytes([packet[10], packet[11]]) as usize;

        let mut offset = 12;
        for _ in 0..questions {
            let (_, next) = match read_name(packet, offset) {
                Some(value) => value,
                None => return,
            };
            offset = next + 4;
        }

        for _ in 0..answers {
            let (name, next) = match read_name(packet, offset) {
                Some(value) => value,
                None => return,
            };
            offset = next;
            if offset + 10 > packet.len() {
                return;
            }
            let kind = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
            let length = u16::from_be_bytes([packet[offset + 8], packet[offset + 9]]) as usize;
            let start = offset + 10;
            let end = match start.checked_add(length) {
                Some(end) if end <= packet.len() => end,
                _ => return,
            };
            self.record(&name, kind, &packet[start..end]);
            offset = end;
        }
    }

    fn record(&mut self, name: &str, kind: u16, data: &[u8]) {
        match kind {
            TYPE_PTR => {
                if let Some((target, _)) = read_name(data, 0) {
                    self.ptr.insert(name.to_string(), target);
                }
            }
            TYPE_SRV => {
                if data.len() >= 6 {
                    let port = u16::from_be_bytes([data[4], data[5]]);
                    if let Some((target, _)) = read_name(data, 6) {
                        self.srv.insert(name.to_string(), (port, target));
                    }
                }
            }
            TYPE_TXT => {
                let (mut id, mut spki) = (None, None);
                for entry in txt_entries(data) {
                    if let Some(value) = entry.strip_prefix("id=") {
                        id = Some(value.to_string());
                    }
                    if let Some(value) = entry.strip_prefix("spki=") {
                        spki = Some(value.to_string());
                    }
                }
                self.txt.insert(name.to_string(), (id, spki));
            }
            TYPE_A if data.len() == 4 => {
                self.a.insert(
                    name.to_string(),
                    IpAddr::V4(Ipv4Addr::new(data[0], data[1], data[2], data[3])),
                );
            }
            _ => {}
        }
    }

    fn finish(&self) -> std::result::Result<Vec<Discovered>, ()> {
        let mut found = Vec::new();
        for (service, instance) in &self.ptr {
            if !service.eq_ignore_ascii_case(SERVICE) {
                continue;
            }
            let (port, target) = match self.srv.get(instance) {
                Some(value) => value.clone(),
                None => continue,
            };
            let address = match self.a.get(&target) {
                Some(address) => *address,
                None => continue,
            };
            let (id, spki) = self.txt.get(instance).cloned().unwrap_or((None, None));
            found.push(Discovered {
                label: instance
                    .trim_end_matches(SERVICE)
                    .trim_end_matches('.')
                    .to_string(),
                address,
                port,
                node_id: id,
                spki,
            });
        }
        found.sort_by(|a, b| a.label.cmp(&b.label));
        Ok(found)
    }
}

fn txt_entries(data: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut offset = 0;
    while offset < data.len() {
        let length = data[offset] as usize;
        offset += 1;
        if offset + length > data.len() {
            break;
        }
        if let Ok(text) = std::str::from_utf8(&data[offset..offset + length]) {
            out.push(text.to_string());
        }
        offset += length;
    }
    out
}

/// Read a possibly compressed DNS name; returns it and the offset after it.
fn read_name(packet: &[u8], start: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut offset = start;
    let mut next = start;
    let mut jumps = 0;

    loop {
        let length = *packet.get(offset)? as usize;
        match length {
            0 => {
                if jumps == 0 {
                    next = offset + 1;
                }
                return Some((format!("{}.", labels.join(".")), next));
            }
            0xC0..=0xFF => {
                if jumps > 8 {
                    return None;
                }
                let pointer = ((length & 0x3F) << 8) | *packet.get(offset + 1)? as usize;
                if jumps == 0 {
                    next = offset + 2;
                }
                jumps += 1;
                offset = pointer;
            }
            _ => {
                let label = packet.get(offset + 1..offset + 1 + length)?;
                labels.push(String::from_utf8_lossy(label).to_string());
                offset += 1 + length;
            }
        }
    }
}

fn push_name(out: &mut Vec<u8>, name: &str) {
    for label in name.trim_end_matches('.').split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
}

fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mdns_parses_an_answer() {
        // PTR + SRV + TXT + A, built the same way the node builds them.
        let instance = "node-one._msm-node._tcp.local.";
        let host = "node-one.local.";
        let mut packet = vec![0u8; 12];
        packet[2] = 0x84;
        packet[7] = 4;

        let mut record = |name: &str, kind: u16, data: Vec<u8>| {
            push_name(&mut packet, name);
            push_u16(&mut packet, kind);
            push_u16(&mut packet, 1 | 0x8000);
            packet.extend_from_slice(&120u32.to_be_bytes());
            push_u16(&mut packet, data.len() as u16);
            packet.extend_from_slice(&data);
        };

        let mut ptr = Vec::new();
        push_name(&mut ptr, instance);
        record(SERVICE, TYPE_PTR, ptr);

        let mut srv = vec![0u8, 0, 0, 0];
        push_u16(&mut srv, 7333);
        push_name(&mut srv, host);
        record(instance, TYPE_SRV, srv);

        let txt = b"\x06id=abc\x07spki=de\x03v=1".to_vec();
        record(instance, TYPE_TXT, txt);
        record(host, TYPE_A, vec![10, 89, 0, 3]);

        let mut records = Records::default();
        records.absorb(&packet);
        let found = records.finish().expect("parse");

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].label, "node-one");
        assert_eq!(found[0].port, 7333);
        assert_eq!(found[0].address, IpAddr::V4(Ipv4Addr::new(10, 89, 0, 3)));
        assert_eq!(found[0].node_id.as_deref(), Some("abc"));
        assert_eq!(found[0].endpoint(), "10.89.0.3:7333");
    }

    #[test]
    fn mdns_query_is_a_ptr_question() {
        let packet = query();
        assert_eq!(packet[5], 1);
        let (name, next) = read_name(&packet, 12).expect("name");
        assert_eq!(name, SERVICE);
        assert_eq!(
            u16::from_be_bytes([packet[next], packet[next + 1]]),
            TYPE_PTR
        );
    }
}
