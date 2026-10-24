//! Fan out one command to several pinned nodes and keep every answer.
//!
//! Each node is contacted in its own thread: a node that is down or slow must
//! not delay the others, and every node still gets its own request id.

use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use msm_protocol::commands::Command;
use msm_protocol::{Message, ProtocolError};
use rand::RngCore;
use rand::rngs::OsRng;
use serde_json::Value;

use crate::net;
use crate::store::NodeRecord;

/// One node's answer, or the reason there is none.
#[derive(Debug)]
pub struct Outcome {
    pub label: String,
    pub endpoint: String,
    pub elapsed: Duration,
    pub reply: Result<Message, ProtocolError>,
}

impl Outcome {
    /// True when the node answered with `result` and `ok: true`.
    pub fn succeeded(&self) -> bool {
        matches!(&self.reply, Ok(Message::Result { ok: true, .. }))
    }

    /// The refusal code, when the node refused the command.
    pub fn code(&self) -> Option<&str> {
        match &self.reply {
            Ok(Message::Result { code, .. }) => code.as_deref(),
            Ok(Message::Error { code, .. }) => Some(code.as_str()),
            _ => None,
        }
    }

    /// The human-readable refusal detail.
    pub fn detail(&self) -> Option<&str> {
        match &self.reply {
            Ok(Message::Result { detail, .. }) => detail.as_deref(),
            Ok(Message::Error { detail, .. }) => Some(detail.as_str()),
            _ => None,
        }
    }

    /// The payload, when the node sent one.
    pub fn data(&self) -> Option<&Value> {
        match &self.reply {
            Ok(Message::Result { data, .. }) => data.as_ref(),
            _ => None,
        }
    }
}

/// Run `command` against every node, in parallel, and return one outcome each.
pub fn execute(nodes: &[NodeRecord], state_dir: &Path, command: &Command) -> Vec<Outcome> {
    let timeout = net::command_timeout(command);

    thread::scope(|scope| {
        let handles: Vec<_> = nodes
            .iter()
            .map(|record| {
                scope.spawn(move || {
                    let id = request_id();
                    let message = command.clone().into_message(&id);
                    let started = Instant::now();
                    let reply = net::request(state_dir, record, &message, timeout);
                    Outcome {
                        label: label_of(&record.label),
                        endpoint: format!("{}:{}", record.host, record.op_port),
                        elapsed: started.elapsed(),
                        reply,
                    }
                })
            })
            .collect();

        handles
            .into_iter()
            .zip(nodes)
            .map(|(handle, record)| match handle.join() {
                Ok(outcome) => outcome,
                Err(_) => Outcome {
                    label: label_of(&record.label),
                    endpoint: format!("{}:{}", record.host, record.op_port),
                    elapsed: Duration::ZERO,
                    reply: Err(ProtocolError::Internal(
                        "the console thread panicked".into(),
                    )),
                },
            })
            .collect()
    })
}

/// A fresh correlation id; the node echoes it back unchanged.
pub fn request_id() -> String {
    let mut bytes = [0u8; 8];
    OsRng.fill_bytes(&mut bytes);
    let mut id = String::from("c-");
    for byte in bytes {
        id.push_str(&format!("{byte:02x}"));
    }
    id
}

fn label_of(label: &str) -> String {
    if label.is_empty() {
        "-".to_string()
    } else {
        label.to_string()
    }
}
