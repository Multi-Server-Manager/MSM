use rand::RngCore;

use crate::error::{ProtocolError, Result};

/// Crockford Base32: no I, L, O or U (`PROTOCOL.md` §4).
pub const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Number of characters in a pairing code.
pub const CODE_LEN: usize = 8;

/// Read 40 bits from the generator and render them as 8 characters.
pub fn generate_code<R: RngCore>(rng: &mut R) -> String {
    let mut raw = [0u8; 5];
    rng.fill_bytes(&mut raw);

    let mut value = 0u64;
    for byte in raw {
        value = (value << 8) | u64::from(byte);
    }

    let mut out = [0u8; CODE_LEN];
    for slot in out.iter_mut().rev() {
        *slot = ALPHABET[(value & 0x1f) as usize];
        value >>= 5;
    }
    // The alphabet is ASCII, so this cannot fail.
    String::from_utf8(out.to_vec()).expect("Crockford alphabet is ASCII")
}

/// Accept what a human types and return the canonical code.
///
/// Separators are dropped, letters are uppercased and the Crockford confusables
/// I/L and O are folded to 1 and 0.
pub fn normalize_code(input: &str) -> Result<String> {
    let mut out = String::with_capacity(CODE_LEN);

    for ch in input.chars() {
        if matches!(ch, '-' | ' ' | '\t' | '\r' | '\n') {
            continue;
        }
        let folded = match ch.to_ascii_uppercase() {
            'I' | 'L' => '1',
            'O' => '0',
            other => other,
        };
        if !folded.is_ascii() || !ALPHABET.contains(&(folded as u8)) {
            return Err(ProtocolError::BadProof(
                "pairing code contains a character outside the Crockford base32 alphabet".into(),
            ));
        }
        out.push(folded);
    }

    if out.len() != CODE_LEN {
        return Err(ProtocolError::BadProof(format!(
            "pairing code must be {CODE_LEN} characters, got {}",
            out.len()
        )));
    }
    Ok(out)
}
