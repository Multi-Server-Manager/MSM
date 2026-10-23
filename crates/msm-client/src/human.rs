//! Failures in the words an operator needs, not the words the wire uses.
//!
//! The panel used to show `bad_proof: pairing proof did not verify` and
//! `io: Connection refused (os error 111)`. Both are true and neither tells you
//! what to do. Everything here maps a failure onto a sentence that says what
//! happened and, where it is knowable, what to try next. The protocol codes
//! stay in the message only when nothing better can be said.

use std::io::ErrorKind;

use msm_protocol::ProtocolError;

/// A failed pairing attempt against `address`.
pub fn pairing(err: &ProtocolError, address: &str) -> String {
    match err {
        ProtocolError::Peer { code, detail } => match code.as_str() {
            "bad_proof" => {
                "the node rejected that code. Check the eight characters and try again".to_string()
            }
            "expired" => "that code expired; the node printed a new one".to_string(),
            "abuse" => {
                "too many wrong codes; the node printed a new one in its window".to_string()
            }
            "bad_version" => {
                "the node speaks a different protocol version; update both sides".to_string()
            }
            "unauthorized" => "the node refused this console's certificate".to_string(),
            other => format!("the node refused the pairing ({other}: {detail})"),
        },
        ProtocolError::BadProof(detail) if detail.starts_with("pairing code must be") => {
            "a pairing code is eight characters; retype it from the node's window".to_string()
        }
        ProtocolError::BadProof(detail) if detail.starts_with("pairing code contains") => {
            "that code has a character pairing codes never use (I, L, O and U are skipped)"
                .to_string()
        }
        ProtocolError::BadProof(detail) => format!("that code is not usable: {detail}"),
        ProtocolError::Io(err) => connection(err, address),
        ProtocolError::Tls(detail) => {
            format!("the secure connection to {address} failed: {detail}")
        }
        ProtocolError::Internal(detail) if detail.starts_with("cannot resolve") => {
            format!("{detail}: check the host name or the address")
        }
        other => format!("pairing with {address} failed: {other}"),
    }
}

/// A request to a paired node that never produced an answer.
pub fn command(err: &ProtocolError, address: &str) -> String {
    match err {
        ProtocolError::Io(err) => connection(err, address),
        ProtocolError::Peer { code, detail } => refusal(Some(code), Some(detail)),
        other => format!("{address}: {other}"),
    }
}

/// A refusal the node sent back (`result` with `ok: false`, or `error`).
pub fn refusal(code: Option<&str>, detail: Option<&str>) -> String {
    let detail = detail.unwrap_or("").trim();
    let with_detail = |head: &str| {
        if detail.is_empty() {
            head.to_string()
        } else {
            format!("{head}: {detail}")
        }
    };

    match code.unwrap_or("") {
        "busy" => "busy: another command is already running on that node".to_string(),
        "unauthorized" => {
            "this console is not paired with that node any more; pair it again".to_string()
        }
        "bad_argument" => with_detail("the node rejected the argument"),
        "unsupported" => "that node cannot run this command".to_string(),
        "failed" => with_detail("the command failed on the node"),
        "confirmation_required" => "refusing to reboot without the confirmation token".to_string(),
        "unknown_type" | "bad_frame" | "bad_version" => {
            with_detail("the node did not understand the request")
        }
        "internal" => with_detail("the node hit an internal error"),
        "" if !detail.is_empty() => detail.to_string(),
        "" => "the node refused the request".to_string(),
        other => with_detail(&format!("the node refused the request ({other})")),
    }
}

/// One connection failure, phrased for the address that was dialled.
fn connection(err: &std::io::Error, address: &str) -> String {
    match err.kind() {
        ErrorKind::ConnectionRefused => {
            format!("nothing is listening at {address}; is msm-node running?")
        }
        ErrorKind::TimedOut | ErrorKind::WouldBlock => format!("{address} did not answer in time"),
        // A tailnet that is up but a host firewall that rejects the port reads
        // exactly like this, which is the most common reason a node cannot be
        // reached at all.
        ErrorKind::NetworkUnreachable | ErrorKind::HostUnreachable => format!(
            "cannot reach {address}; check the network or the tailnet, and that the node's firewall allows TCP 7333-7334"
        ),
        ErrorKind::AddrNotAvailable | ErrorKind::AddrInUse => {
            format!("{address} is not usable from this machine")
        }
        // Some sandboxes answer a connect to a dead address with ENOENT.
        ErrorKind::NotFound => format!("cannot reach {address}; check the address"),
        ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted => {
            format!("{address} closed the connection unexpectedly")
        }
        _ => format!("cannot reach {address}: {err}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    fn peer(code: &str, detail: &str) -> ProtocolError {
        ProtocolError::Peer {
            code: code.to_string(),
            detail: detail.to_string(),
        }
    }

    #[test]
    fn wrong_code_says_what_to_do() {
        let message = pairing(&peer("bad_proof", "pairing proof did not verify"), "10.0.0.4:7334");
        assert!(message.contains("rejected that code"), "{message}");
        assert!(message.contains("try again"), "{message}");
        assert!(!message.contains("bad_proof"), "{message}");
    }

    #[test]
    fn expired_and_abuse_point_at_the_new_code() {
        assert!(pairing(&peer("expired", "the pairing code expired"), "h:1").contains("new one"));
        assert!(pairing(&peer("abuse", "too many attempts"), "h:1").contains("new one"));
    }

    #[test]
    fn refused_connection_names_the_address_and_the_agent() {
        let err = ProtocolError::Io(io::Error::from(ErrorKind::ConnectionRefused));
        let message = pairing(&err, "100.74.163.8:7334");
        assert!(message.contains("100.74.163.8:7334"), "{message}");
        assert!(message.contains("msm-node"), "{message}");
        assert!(!message.contains("os error"), "{message}");
    }

    #[test]
    fn a_dead_address_with_no_errno_kind_still_reads_well() {
        let odd = ProtocolError::Io(io::Error::from(ErrorKind::NotFound));
        let message = pairing(&odd, "127.0.0.3:1");
        assert!(message.contains("cannot reach 127.0.0.3:1"), "{message}");
        assert!(!message.contains("os error"), "{message}");
    }

    #[test]
    fn timeout_and_unreachable_are_distinct() {
        let timeout = ProtocolError::Io(io::Error::from(ErrorKind::TimedOut));
        assert!(pairing(&timeout, "h:1").contains("did not answer"));
        let unreachable = ProtocolError::Io(io::Error::from(ErrorKind::NetworkUnreachable));
        let message = pairing(&unreachable, "h:1");
        assert!(message.contains("tailnet"), "{message}");
        // The port is the piece an operator can act on when a firewall is the
        // reason the node answers nothing at all.
        assert!(message.contains("7333-7334"), "{message}");
    }

    #[test]
    fn short_code_is_explained_before_it_is_sent() {
        let short = ProtocolError::BadProof("pairing code must be 8 characters, got 5".into());
        let message = pairing(&short, "h:1");
        assert!(message.contains("eight characters"), "{message}");

        let odd = ProtocolError::BadProof(
            "pairing code contains a character outside the Crockford base32 alphabet".into(),
        );
        assert!(pairing(&odd, "h:1").contains("I, L, O and U"));
    }

    #[test]
    fn command_refusals_are_sentences() {
        assert!(refusal(Some("busy"), Some("pkg.update is running")).starts_with("busy:"));
        assert!(refusal(Some("unauthorized"), None).contains("pair it again"));
        assert!(refusal(Some("bad_argument"), Some("not a package name"))
            .contains("not a package name"));
        assert!(refusal(Some("unsupported"), None).contains("cannot run"));
        assert!(refusal(Some("confirmation_required"), None).contains("confirmation"));
        assert!(!refusal(Some("internal"), Some("no package manager")).contains("internal:"));

        // A package manager that exits non-zero comes back as `failed`.
        let failed = refusal(Some("failed"), Some("dnf exited with 1"));
        assert!(failed.contains("failed on the node"), "{failed}");
        assert!(failed.contains("dnf exited with 1"), "{failed}");
    }
}
