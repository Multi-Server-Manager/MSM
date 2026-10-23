use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::error::{ProtocolError, Result};

type HmacSha256 = Hmac<Sha256>;

/// HKDF-Extract (RFC 5869 §2.2).
pub fn extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(salt).expect("HMAC accepts any key length");
    mac.update(ikm);
    mac.finalize().into_bytes().into()
}

/// HKDF-Expand (RFC 5869 §2.3) with SHA-256.
pub fn expand(prk: &[u8], info: &[u8], length: usize) -> Result<Vec<u8>> {
    if length == 0 || length > 255 * 32 {
        return Err(ProtocolError::Internal(
            "hkdf output length out of range".into(),
        ));
    }

    let mut out = Vec::with_capacity(length + 32);
    let mut block: Vec<u8> = Vec::new();
    let mut counter: u8 = 1;

    while out.len() < length {
        let mut mac = HmacSha256::new_from_slice(prk).expect("HMAC accepts any key length");
        mac.update(&block);
        mac.update(info);
        mac.update(&[counter]);
        block = mac.finalize().into_bytes().to_vec();
        out.extend_from_slice(&block);
        counter = counter.wrapping_add(1);
    }

    out.truncate(length);
    Ok(out)
}
