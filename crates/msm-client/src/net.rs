//! Network side of the console: pairing and the operational channel.
//!
//! Every step here follows `docs/PROTOCOL.md`; the derivation must match the Go
//! node exactly or the handshake fails closed.

use std::net::{TcpStream, ToSocketAddrs};
use std::path::Path;
use std::time::Duration;

use msm_protocol::b64;
use msm_protocol::code::normalize_code;
use msm_protocol::derive::{Transcript, client_proof, mac_eq, node_proof, pair_keys};
use msm_protocol::commands::{Command, SshAuthorizeResult};
use msm_protocol::messages::{self, Message};
use msm_protocol::tls::{Identity, client_config, server_name, spki_from_cert_der};
use msm_protocol::{ProtocolError, Result, read_frame, write_frame};
use rand::RngCore;
use rand::rngs::OsRng;
use rustls::{ClientConnection, StreamOwned};
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::sshkey::SshKey;
use crate::store::{self, NodeRecord};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const IO_TIMEOUT: Duration = Duration::from_secs(20);

/// How long a command may take before the console gives up on the socket.
/// Package operations run a real manager, so they get the long one.
pub fn command_timeout(command: &Command) -> Duration {
    match command {
        Command::PkgUpdate | Command::PkgInstall(_) => Duration::from_secs(320),
        _ => Duration::from_secs(60),
    }
}

type Session = StreamOwned<ClientConnection, TcpStream>;

/// What pairing produced: the pin, plus how the SSH key install went.
pub struct PairOutcome {
    pub record: NodeRecord,
    /// The console is paired even when the key could not be installed, so the
    /// failure is reported instead of thrown away.
    pub ssh_warning: Option<String>,
}

/// What an `info` request returns.
#[derive(Debug, Clone)]
pub struct InfoSummary {
    pub node_id: String,
    pub hostname: String,
    pub os: String,
    pub version: String,
    pub pinned_clients: u32,
}

/// Pair with a node using its one-time code, pin its identity and store it.
pub fn pair(state_dir: &Path, addr: &str, code: &str, label: &str) -> Result<PairOutcome> {
    let code = normalize_code(code)?;
    let identity = store::load_or_create_identity(state_dir)?;
    let mut session = connect(addr, &identity, None, IO_TIMEOUT)?;

    let ephemeral = EphemeralSecret::random_from_rng(OsRng);
    let ephemeral_public = PublicKey::from(&ephemeral);
    let mut client_nonce = [0u8; 16];
    OsRng.fill_bytes(&mut client_nonce);

    send(
        &mut session,
        &Message::PairHello {
            v: messages::VERSION,
            eph: b64::encode(ephemeral_public.as_bytes()),
            nonce: b64::encode(&client_nonce),
        },
    )?;

    let (node_eph_text, node_nonce_text, node_id_text, node_spki_text, op_port) =
        match receive(&mut session)? {
            Message::PairChallenge {
                eph,
                nonce,
                node_id,
                node_spki,
                op_port,
                ..
            } => (eph, nonce, node_id, node_spki, op_port),
            Message::Error { code, detail, .. } => return Err(ProtocolError::Peer { code, detail }),
            other => {
                return Err(ProtocolError::UnknownType(format!(
                    "expected pair.challenge, got {}",
                    other.kind()
                )));
            }
        };

    if op_port == 0 {
        return Err(ProtocolError::BadFrame(
            "the node advertised an invalid operational port".into(),
        ));
    }

    // Bind the advertised identity to the certificate actually presented: a
    // relay cannot substitute its own key into the challenge.
    let observed_pin = peer_pin(&session)?;
    let advertised_pin = b64::decode_n::<44>(&node_spki_text)?;
    if !mac_eq(&observed_pin, &advertised_pin) {
        return Err(ProtocolError::BadProof(
            "the node certificate does not match the identity it advertised".into(),
        ));
    }

    let node_eph_bytes = b64::decode_n::<32>(&node_eph_text)?;
    let node_eph = PublicKey::from(node_eph_bytes);
    let node_nonce = b64::decode_n::<16>(&node_nonce_text)?;
    let node_id = b64::decode_n::<16>(&node_id_text)?;

    let shared = ephemeral.diffie_hellman(&node_eph);
    if shared.as_bytes().iter().all(|byte| *byte == 0) {
        return Err(ProtocolError::BadProof(
            "the node sent a low-order ephemeral key".into(),
        ));
    }

    let transcript = Transcript {
        client_eph: ephemeral_public.as_bytes(),
        node_eph: &node_eph_bytes,
        client_nonce: &client_nonce,
        node_nonce: &node_nonce,
        node_id: &node_id,
        node_spki: &advertised_pin,
        client_id: identity.id(),
        client_spki: identity.spki(),
    }
    .hash();

    let (client_key, node_key) = pair_keys(&code, shared.as_bytes())?;
    send(
        &mut session,
        &Message::PairProof {
            v: messages::VERSION,
            mac: b64::encode(&client_proof(&client_key, &transcript)),
            client_id: identity.id_b64(),
            client_spki: identity.spki_b64(),
        },
    )?;

    let (ack_mac, ack_node_id, ack_spki, ack_port) = match receive(&mut session)? {
        Message::PairOk {
            mac,
            node_id,
            node_spki,
            op_port,
            ..
        } => (mac, node_id, node_spki, op_port),
        Message::Error { code, detail, .. } => return Err(ProtocolError::Peer { code, detail }),
        other => {
            return Err(ProtocolError::UnknownType(format!(
                "expected pair.ok, got {}",
                other.kind()
            )));
        }
    };

    if ack_node_id != node_id_text || ack_spki != node_spki_text || ack_port != op_port {
        return Err(ProtocolError::BadProof(
            "the node acknowledgement does not match the challenge".into(),
        ));
    }
    let received = b64::decode_n::<32>(&ack_mac)?;
    if !mac_eq(&node_proof(&node_key, &transcript), &received) {
        return Err(ProtocolError::BadProof("the node proof did not verify".into()));
    }

    let ssh_key = SshKey::load_or_create(state_dir)?;
    let record = NodeRecord {
        node_id: node_id_text,
        spki: node_spki_text,
        label: label.to_string(),
        host: host_of(addr)?,
        op_port,
        paired_at: store::now_unix(),
        ssh_user: "root".to_string(),
        ssh_port: 22,
    };
    store::save_node(state_dir, record.clone())?;

    // The key travels over the channel the pin now authenticates, so the
    // pairing transcript itself is unchanged (PROTOCOL.md §8.11).
    let ssh_warning = authorize_ssh_key(state_dir, &record, &ssh_key.public_line)
        .err()
        .map(|err| format!("the SSH key was not installed: {err}"));

    Ok(PairOutcome {
        record,
        ssh_warning,
    })
}

/// Install the console's public key into a node's authorized_keys.
pub fn authorize_ssh_key(
    state_dir: &Path,
    record: &NodeRecord,
    key: &str,
) -> Result<SshAuthorizeResult> {
    let identity = store::load_or_create_identity(state_dir)?;
    let pin = b64::decode(&record.spki)?;
    let endpoint = format!("{}:{}", record.host, record.op_port);
    let mut session = connect(&endpoint, &identity, Some(pin), IO_TIMEOUT)?;

    send(
        &mut session,
        &Message::SshAuthorize {
            v: messages::VERSION,
            id: crate::fanout::request_id(),
            key: key.to_string(),
        },
    )?;

    match receive(&mut session)? {
        Message::Result {
            ok: true,
            data: Some(data),
            ..
        } => serde_json::from_value(data).map_err(|_| {
            ProtocolError::BadFrame("ssh.authorize returned an unexpected payload".into())
        }),
        Message::Result { code, detail, .. } => Err(ProtocolError::Peer {
            code: code.unwrap_or_default(),
            detail: detail.unwrap_or_default(),
        }),
        Message::Error { code, detail, .. } => Err(ProtocolError::Peer { code, detail }),
        other => Err(ProtocolError::UnknownType(format!(
            "expected result, got {}",
            other.kind()
        ))),
    }
}

/// Ask a paired node for its identity over the pinned channel.
pub fn info(state_dir: &Path, target: &str) -> Result<InfoSummary> {
    let record = store::find_node(state_dir, target)?;
    let identity = store::load_or_create_identity(state_dir)?;
    let pin = b64::decode(&record.spki)?;

    let endpoint = format!("{}:{}", record.host, record.op_port);
    let mut session = connect(&endpoint, &identity, Some(pin), IO_TIMEOUT)?;

    send(
        &mut session,
        &Message::Info {
            v: messages::VERSION,
        },
    )?;

    match receive(&mut session)? {
        Message::InfoOk {
            node_id,
            hostname,
            os,
            version,
            pinned_clients,
            ..
        } => Ok(InfoSummary {
            node_id,
            hostname,
            os,
            version,
            pinned_clients,
        }),
        Message::Error { code, detail, .. } => Err(ProtocolError::Peer { code, detail }),
        other => Err(ProtocolError::UnknownType(format!(
            "expected info.ok, got {}",
            other.kind()
        ))),
    }
}

/// Send one request to a paired node over its pinned channel.
pub fn request(
    state_dir: &Path,
    record: &NodeRecord,
    message: &Message,
    timeout: Duration,
) -> Result<Message> {
    let identity = store::load_or_create_identity(state_dir)?;
    let pin = b64::decode(&record.spki)?;
    let endpoint = format!("{}:{}", record.host, record.op_port);

    let mut session = connect(&endpoint, &identity, Some(pin), timeout)?;
    send(&mut session, message)?;
    receive(&mut session)
}

fn connect(
    addr: &str,
    identity: &Identity,
    pin: Option<Vec<u8>>,
    io_timeout: Duration,
) -> Result<Session> {
    let target = addr
        .to_socket_addrs()
        .map_err(|err| ProtocolError::Internal(format!("cannot resolve {addr}: {err}")))?
        .next()
        .ok_or_else(|| ProtocolError::Internal(format!("{addr} resolved to no addresses")))?;

    let socket = TcpStream::connect_timeout(&target, CONNECT_TIMEOUT)?;
    socket.set_read_timeout(Some(io_timeout))?;
    socket.set_write_timeout(Some(io_timeout))?;
    socket.set_nodelay(true)?;

    let config = client_config(identity, pin)?;
    let connection = ClientConnection::new(config, server_name())
        .map_err(|err| ProtocolError::Tls(format!("cannot start the TLS session: {err}")))?;
    Ok(StreamOwned::new(connection, socket))
}

fn peer_pin(session: &Session) -> Result<Vec<u8>> {
    let certificates = session
        .conn
        .peer_certificates()
        .ok_or_else(|| ProtocolError::Tls("the node presented no certificate".into()))?;
    let end_entity = certificates
        .first()
        .ok_or_else(|| ProtocolError::Tls("the node presented no certificate".into()))?;
    spki_from_cert_der(end_entity.as_ref())
}

fn send(session: &mut Session, message: &Message) -> Result<()> {
    let payload = messages::encode(message)?;
    write_frame(session, &payload)
}

fn receive(session: &mut Session) -> Result<Message> {
    let payload = read_frame(session)?;
    messages::decode(&payload)
}

/// Split the host out of a `host:port` string, keeping IPv6 brackets.
fn host_of(addr: &str) -> Result<String> {
    addr.rsplit_once(':')
        .map(|(host, _)| host.to_string())
        .ok_or_else(|| ProtocolError::Internal(format!("{addr} is not host:port")))
}
