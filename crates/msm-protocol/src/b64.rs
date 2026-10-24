use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use crate::error::{ProtocolError, Result};

/// Encode a binary field (`PROTOCOL.md` §3).
pub fn encode(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

/// Decode a binary field.
pub fn decode(text: &str) -> Result<Vec<u8>> {
    STANDARD
        .decode(text)
        .map_err(|_| ProtocolError::BadFrame("field is not canonical base64".into()))
}

/// Decode a binary field that must have an exact length.
pub fn decode_n<const N: usize>(text: &str) -> Result<[u8; N]> {
    let bytes = decode(text)?;
    bytes
        .try_into()
        .map_err(|_| ProtocolError::BadFrame(format!("field is not {N} bytes")))
}
