//! The console's SSH identity.
//!
//! One Ed25519 keypair lives under the state directory at 0600. Its public half
//! travels to each node inside `ssh.authorize` (PROTOCOL.md §8.11), so `ssh` and
//! `sftp` can be started from the console with exactly that identity.

use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use msm_protocol::b64;
use msm_protocol::{ProtocolError, Result};
use rand::RngCore;
use rand::rngs::OsRng;
use rcgen::{KeyPair, PKCS_ED25519};

/// File name of the private key inside `<state>/ssh/`.
pub const KEY_NAME: &str = "id_ed25519";
/// Comment carried by the public key, so a node operator can tell where it
/// came from.
pub const COMMENT: &str = "msm-console";

/// The console's SSH keypair in the forms the rest of the program needs.
#[derive(Debug, Clone)]
pub struct SshKey {
    /// OpenSSH private key, PEM armoured.
    pub private_pem: String,
    /// One `authorized_keys` line.
    pub public_line: String,
}

impl SshKey {
    /// Generate a fresh Ed25519 keypair.
    pub fn generate() -> Result<Self> {
        let key = KeyPair::generate_for(&PKCS_ED25519)
            .map_err(|err| ProtocolError::Internal(format!("cannot generate an SSH key: {err}")))?;

        let der = key.serialize_der();
        let seed = ed25519_seed(&der).ok_or_else(|| {
            ProtocolError::Internal(format!(
                "the generated SSH key is not a usable Ed25519 PKCS#8 key ({} bytes)",
                der.len()
            ))
        })?;
        let public = key.public_key_raw().to_vec();

        Ok(Self {
            private_pem: armoured(&openssh_private_key(&seed, &public, COMMENT)),
            public_line: public_line(&public),
        })
    }

    /// Load the stored keypair, creating and storing one on first use.
    pub fn load_or_create(state_dir: &Path) -> Result<Self> {
        let path = key_path(state_dir);
        if path.exists() {
            let private_pem = fs::read_to_string(&path)?;
            return match parse_public_key(&private_pem) {
                Ok(public_line) => Ok(Self {
                    private_pem,
                    public_line,
                }),
                Err(_) => Err(ProtocolError::Internal(format!(
                    "{} is not a usable OpenSSH Ed25519 key",
                    path.display()
                ))),
            };
        }

        let key = Self::generate()?;
        store(state_dir, &key)?;
        Ok(key)
    }

    /// Path of the private key for this state directory.
    pub fn path(state_dir: &Path) -> PathBuf {
        key_path(state_dir)
    }
}

/// Pull the 32-byte seed out of a PKCS#8 Ed25519 private key.
///
/// Both encodings in the wild are accepted: the bare v1 form (the private key
/// octet string holds the seed) and the v2 form that also carries the public
/// key (the octet string holds a nested `04 20 <seed>`).
fn ed25519_seed(der: &[u8]) -> Option<[u8; 32]> {
    let (tag, body, _) = read_tlv(der, 0)?;
    if tag != 0x30 {
        return None;
    }

    let mut cursor = 0;
    let (version_tag, _, next) = read_tlv(body, cursor)?;
    if version_tag != 0x02 {
        return None;
    }
    cursor = next;

    let (algorithm_tag, _, next) = read_tlv(body, cursor)?;
    if algorithm_tag != 0x30 {
        return None;
    }
    cursor = next;

    let (key_tag, contents, _) = read_tlv(body, cursor)?;
    if key_tag != 0x04 {
        return None;
    }

    let seed: &[u8] = match contents.len() {
        32 => contents,
        34 if contents[0] == 0x04 && contents[1] == 0x20 => &contents[2..],
        _ => return None,
    };

    let mut out = [0u8; 32];
    out.copy_from_slice(seed);
    Some(out)
}

/// Read one DER TLV: tag, contents and the offset just past it.
fn read_tlv(data: &[u8], at: usize) -> Option<(u8, &[u8], usize)> {
    let tag = *data.get(at)?;
    let first = *data.get(at + 1)? as usize;
    let (length, start) = if first & 0x80 == 0 {
        (first, at + 2)
    } else {
        let count = first & 0x7f;
        if count == 0 || count > 2 {
            return None;
        }
        let mut length = 0usize;
        for index in 0..count {
            length = (length << 8) | *data.get(at + 2 + index)? as usize;
        }
        (length, at + 2 + count)
    };
    let end = start.checked_add(length)?;
    Some((tag, data.get(start..end)?, end))
}

fn key_path(state_dir: &Path) -> PathBuf {
    state_dir.join("ssh").join(KEY_NAME)
}

/// Write the keypair with owner-only permissions, refusing to widen them.
fn store(state_dir: &Path, key: &SshKey) -> Result<()> {
    let dir = state_dir.join("ssh");
    fs::create_dir_all(&dir)?;
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;

    let path = key_path(state_dir);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&path)?;
    file.write_all(key.private_pem.as_bytes())?;
    file.sync_all()?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;

    let public = path.with_extension("pub");
    fs::write(&public, format!("{}\n", key.public_line))?;
    Ok(())
}

/// The SSH wire-format public key blob: `string "ssh-ed25519" || string key`.
pub fn ssh_blob(public: &[u8]) -> Vec<u8> {
    let mut blob = Vec::with_capacity(51);
    push_string(&mut blob, b"ssh-ed25519");
    push_string(&mut blob, public);
    blob
}

/// One `authorized_keys` line for a raw 32-byte Ed25519 public key.
pub fn public_line(public: &[u8]) -> String {
    format!("ssh-ed25519 {} {COMMENT}", b64::encode(&ssh_blob(public)))
}

/// The unencrypted `openssh-key-v1` container (the format `ssh-keygen` writes
/// for a key without a passphrase).
fn openssh_private_key(seed: &[u8; 32], public: &[u8], comment: &str) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"openssh-key-v1\0");
    push_string(&mut out, b"none"); // cipher
    push_string(&mut out, b"none"); // kdf
    push_string(&mut out, b""); // kdf options

    push_u32(&mut out, 1); // one key
    push_string(&mut out, &ssh_blob(public));

    let mut private = Vec::new();
    let mut check = [0u8; 4];
    OsRng.fill_bytes(&mut check);
    let check = u32::from_be_bytes(check);
    push_u32(&mut private, check);
    push_u32(&mut private, check);
    push_string(&mut private, b"ssh-ed25519");
    push_string(&mut private, public);

    let mut secret = Vec::with_capacity(64);
    secret.extend_from_slice(seed);
    secret.extend_from_slice(public);
    push_string(&mut private, &secret);
    push_string(&mut private, comment.as_bytes());

    // Pad to the 8-byte block size with 1, 2, 3 …
    let mut pad = 1u8;
    while private.len() % 8 != 0 {
        private.push(pad);
        pad += 1;
    }
    push_string(&mut out, &private);
    out
}

fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn push_string(out: &mut Vec<u8>, value: &[u8]) {
    push_u32(out, value.len() as u32);
    out.extend_from_slice(value);
}

/// Wrap the container in the PEM armour OpenSSH expects.
fn armoured(blob: &[u8]) -> String {
    let encoded = b64::encode(blob);
    let mut out = String::from("-----BEGIN OPENSSH PRIVATE KEY-----\n");
    for chunk in encoded.as_bytes().chunks(70) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        out.push('\n');
    }
    out.push_str("-----END OPENSSH PRIVATE KEY-----\n");
    out
}

/// Recover the public key line from a stored private key.
///
/// Only the unencrypted form this module writes is understood; anything else is
/// reported rather than guessed at.
pub fn parse_public_key(pem: &str) -> Result<String> {
    let body: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    let blob = b64::decode(&body)?;

    let magic = b"openssh-key-v1\0";
    if !blob.starts_with(magic) {
        return Err(ProtocolError::Internal(
            "the stored key is not an openssh-key-v1 file".into(),
        ));
    }

    let mut cursor = magic.len();
    for _ in 0..3 {
        cursor = read_string(&blob, cursor)?.1;
    }
    if read_u32(&blob, cursor)? != 1 {
        return Err(ProtocolError::Internal(
            "the stored key holds more than one key".into(),
        ));
    }
    cursor += 4;
    let (public_blob, _) = read_string(&blob, cursor)?;

    let mut blob_cursor = 0;
    let (kind, next) = read_string(public_blob, blob_cursor)?;
    blob_cursor = next;
    if kind != b"ssh-ed25519" {
        return Err(ProtocolError::Internal(
            "the stored key is not Ed25519".into(),
        ));
    }
    let (public, _) = read_string(public_blob, blob_cursor)?;
    if public.len() != 32 {
        return Err(ProtocolError::Internal(
            "the stored key has the wrong length".into(),
        ));
    }

    Ok(format!("ssh-ed25519 {} {COMMENT}", b64::encode(public_blob)))
}

fn read_u32(data: &[u8], at: usize) -> Result<u32> {
    let bytes: [u8; 4] = data
        .get(at..at + 4)
        .ok_or_else(|| ProtocolError::Internal("the stored key is truncated".into()))?
        .try_into()
        .map_err(|_| ProtocolError::Internal("the stored key is truncated".into()))?;
    Ok(u32::from_be_bytes(bytes))
}

fn read_string(data: &[u8], at: usize) -> Result<(&[u8], usize)> {
    let length = read_u32(data, at)? as usize;
    let start = at + 4;
    let end = start
        .checked_add(length)
        .ok_or_else(|| ProtocolError::Internal("the stored key is truncated".into()))?;
    if end > data.len() {
        return Err(ProtocolError::Internal(
            "the stored key is truncated".into(),
        ));
    }
    Ok((&data[start..end], end))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_key_roundtrip() {
        let key = SshKey::generate().expect("generate");
        assert!(key.private_pem.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----\n"));
        assert!(key.private_pem.ends_with("-----END OPENSSH PRIVATE KEY-----\n"));
        assert!(key.public_line.starts_with("ssh-ed25519 "));
        assert!(key.public_line.ends_with(&format!(" {COMMENT}")));
        assert_eq!(parse_public_key(&key.private_pem).expect("parse"), key.public_line);
    }

    #[test]
    fn ssh_key_storage_is_private() {
        let dir = std::env::temp_dir().join(format!("msm-ssh-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let key = SshKey::load_or_create(&dir).expect("create");
        let path = SshKey::path(&dir);
        assert_eq!(
            fs::metadata(&path).expect("stat").permissions().mode() & 0o777,
            0o600
        );
        // A second load returns the same key rather than rotating it.
        let again = SshKey::load_or_create(&dir).expect("load");
        assert_eq!(again.public_line, key.public_line);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn ssh_key_blob_and_garbage() {
        let blob = ssh_blob(&[7u8; 32]);
        assert_eq!(blob.len(), 51);
        assert!(parse_public_key("not a key").is_err());
    }
}
