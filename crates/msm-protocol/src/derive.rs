use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::error::Result;
use crate::hkdf;

type HmacSha256 = Hmac<Sha256>;

/// Domain separator for every derived value (`PROTOCOL.md` §7).
pub const SEPARATOR: &[u8] = b"MSM-PAIR-V1";

/// Every value bound into a pairing session (`PROTOCOL.md` §7.2).
pub struct Transcript<'a> {
    pub client_eph: &'a [u8],
    pub node_eph: &'a [u8],
    pub client_nonce: &'a [u8],
    pub node_nonce: &'a [u8],
    pub node_id: &'a [u8],
    pub node_spki: &'a [u8],
    pub client_id: &'a [u8],
    pub client_spki: &'a [u8],
}

impl Transcript<'_> {
    /// SHA-256 over the separator and the length-prefixed fields, in the order
    /// fixed by the protocol document.
    pub fn hash(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(SEPARATOR);

        let fields: [&[u8]; 8] = [
            self.client_eph,
            self.node_eph,
            self.client_nonce,
            self.node_nonce,
            self.node_id,
            self.node_spki,
            self.client_id,
            self.client_spki,
        ];
        for field in fields {
            let length =
                u16::try_from(field.len()).expect("transcript fields are far shorter than 64 KiB");
            digest.update(length.to_be_bytes());
            digest.update(field);
        }

        digest.finalize().into()
    }
}

/// Derive the client and node proof keys (`PROTOCOL.md` §7.3).
///
/// The first extract binds the one-time code, the second binds the shared
/// X25519 secret, so neither the code nor the secret alone yields a key.
pub fn pair_keys(code: &str, shared: &[u8]) -> Result<([u8; 32], [u8; 32])> {
    let prk1 = hkdf::extract(b"msm-pair-v1 code seal", code.as_bytes());
    let prk2 = hkdf::extract(&prk1, shared);

    let client = hkdf::expand(&prk2, b"msm-pair-v1 client proof", 32)?;
    let node = hkdf::expand(&prk2, b"msm-pair-v1 node proof", 32)?;

    Ok((
        client.try_into().expect("32 byte expansion"),
        node.try_into().expect("32 byte expansion"),
    ))
}

/// `HMAC-SHA256(c2n, "MSM-PAIR-V1 client" || th)`.
pub fn client_proof(client_key: &[u8], transcript: &[u8; 32]) -> [u8; 32] {
    proof(client_key, b"MSM-PAIR-V1 client", transcript)
}

/// `HMAC-SHA256(n2c, "MSM-PAIR-V1 node" || th)`.
pub fn node_proof(node_key: &[u8], transcript: &[u8; 32]) -> [u8; 32] {
    proof(node_key, b"MSM-PAIR-V1 node", transcript)
}

fn proof(key: &[u8], label: &[u8], transcript: &[u8; 32]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(label);
    mac.update(transcript);
    mac.finalize().into_bytes().into()
}

/// Compare two proofs in constant time.
pub fn mac_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && bool::from(a.ct_eq(b))
}
