use std::io::{Read, Write};

use crate::error::{ProtocolError, Result};

/// Largest payload a frame may carry (`PROTOCOL.md` §2).
pub const MAX_FRAME_LEN: usize = 1 << 20;

/// Write one length-prefixed payload.
pub fn write_frame<W: Write>(writer: &mut W, payload: &[u8]) -> Result<()> {
    if payload.is_empty() {
        return Err(ProtocolError::BadFrame("zero-length frame".into()));
    }
    if payload.len() > MAX_FRAME_LEN {
        return Err(ProtocolError::BadFrame(format!(
            "frame exceeds {MAX_FRAME_LEN} bytes"
        )));
    }
    let length = (payload.len() as u32).to_be_bytes();
    writer.write_all(&length)?;
    writer.write_all(payload)?;
    Ok(())
}

/// Read one length-prefixed payload.
///
/// The announced length is validated before the buffer is allocated, so a peer
/// cannot make this process reserve more than [`MAX_FRAME_LEN`] for one frame.
pub fn read_frame<R: Read>(reader: &mut R) -> Result<Vec<u8>> {
    let mut header = [0u8; 4];
    reader.read_exact(&mut header)?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 {
        return Err(ProtocolError::BadFrame("zero-length frame".into()));
    }
    if length > MAX_FRAME_LEN {
        return Err(ProtocolError::BadFrame(format!(
            "frame exceeds {MAX_FRAME_LEN} bytes"
        )));
    }
    let mut payload = vec![0u8; length];
    reader.read_exact(&mut payload)?;
    Ok(payload)
}
