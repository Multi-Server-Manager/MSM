//! The MSM wire protocol, version 1.
//!
//! `docs/PROTOCOL.md` is authoritative. This crate exists to implement it and
//! nothing else; the Go node agent implements the same document independently.

pub mod b64;
pub mod code;
pub mod commands;
pub mod derive;
pub mod error;
pub mod frame;
pub mod hkdf;
pub mod messages;
pub mod tls;

pub use error::{ProtocolError, Result};
pub use frame::{MAX_FRAME_LEN, read_frame, write_frame};
pub use messages::{Message, VERSION, decode, encode};
