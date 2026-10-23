use std::io;

/// Result type used across the protocol crate.
pub type Result<T> = std::result::Result<T, ProtocolError>;

/// A protocol failure. Each variant maps to one `error` code in
/// `PROTOCOL.md` §9, except `Io` and `Tls` which never reach the wire.
#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("bad_frame: {0}")]
    BadFrame(String),
    #[error("unknown_type: {0}")]
    UnknownType(String),
    #[error("bad_version: {0}")]
    BadVersion(String),
    #[error("bad_proof: {0}")]
    BadProof(String),
    #[error("expired: {0}")]
    Expired(String),
    #[error("abuse: {0}")]
    Abuse(String),
    #[error("unauthorized: {0}")]
    Unauthorized(String),
    #[error("internal: {0}")]
    Internal(String),
    #[error("tls: {0}")]
    Tls(String),
    #[error("peer reported {code}: {detail}")]
    Peer { code: String, detail: String },
    #[error("io: {0}")]
    Io(#[from] io::Error),
}

impl ProtocolError {
    /// The wire error code for this failure, or an empty string when the failure
    /// is local and must not be reported to the peer.
    pub fn code(&self) -> &str {
        match self {
            Self::BadFrame(_) => "bad_frame",
            Self::UnknownType(_) => "unknown_type",
            Self::BadVersion(_) => "bad_version",
            Self::BadProof(_) => "bad_proof",
            Self::Expired(_) => "expired",
            Self::Abuse(_) => "abuse",
            Self::Unauthorized(_) => "unauthorized",
            Self::Internal(_) => "internal",
            Self::Peer { code, .. } => code,
            Self::Tls(_) | Self::Io(_) => "",
        }
    }
}
