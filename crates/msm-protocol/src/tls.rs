use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use rand::RngCore;
use rand::rngs::OsRng;
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, PKCS_ED25519};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use subtle::ConstantTimeEq;

use crate::error::{ProtocolError, Result};

/// Length of a node or client identifier.
pub const ID_LEN: usize = 16;

/// DER length of an Ed25519 SubjectPublicKeyInfo.
pub const SPKI_LEN: usize = 44;

/// The fixed Ed25519 SubjectPublicKeyInfo prefix (`PROTOCOL.md` §1).
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// An Ed25519 identity plus the self-signed certificate built from it.
///
/// The pin is the certificate's SubjectPublicKeyInfo, not a hostname and not a
/// CA chain, so a node keeps its identity regardless of address.
pub struct Identity {
    id: [u8; ID_LEN],
    key: KeyPair,
    certificate: Vec<u8>,
    spki: Vec<u8>,
}

impl Identity {
    /// Generate a fresh identity for the given role.
    pub fn generate(role: &str) -> Result<Self> {
        let key = KeyPair::generate_for(&PKCS_ED25519)
            .map_err(|err| ProtocolError::Tls(format!("cannot generate an Ed25519 key: {err}")))?;
        let certificate = build_certificate(&key, role)?;
        let spki = spki_from_cert_der(&certificate)?;

        let mut id = [0u8; ID_LEN];
        OsRng.fill_bytes(&mut id);

        Ok(Self {
            id,
            key,
            certificate,
            spki,
        })
    }

    /// Rebuild an identity from its stored form.
    pub fn from_stored(id_b64: &str, key_b64: &str, role: &str) -> Result<Self> {
        let id = B64
            .decode(id_b64)
            .map_err(|_| ProtocolError::Tls("identity id is not base64".into()))?;
        if id.len() != ID_LEN {
            return Err(ProtocolError::Tls(format!(
                "identity id is {} bytes, want {ID_LEN}",
                id.len()
            )));
        }
        let key_der = B64
            .decode(key_b64)
            .map_err(|_| ProtocolError::Tls("identity key is not base64".into()))?;
        let key = KeyPair::from_pkcs8_der_and_sign_algo(
            &PrivatePkcs8KeyDer::from(key_der),
            &PKCS_ED25519,
        )
        .map_err(|err| ProtocolError::Tls(format!("identity key is not PKCS#8: {err}")))?;
        let certificate = build_certificate(&key, role)?;
        let spki = spki_from_cert_der(&certificate)?;

        let mut id_bytes = [0u8; ID_LEN];
        id_bytes.copy_from_slice(&id);

        Ok(Self {
            id: id_bytes,
            key,
            certificate,
            spki,
        })
    }

    /// The identity bytes.
    pub fn id(&self) -> &[u8; ID_LEN] {
        &self.id
    }

    /// The identity bytes as base64.
    pub fn id_b64(&self) -> String {
        B64.encode(self.id)
    }

    /// The pin as base64.
    pub fn spki_b64(&self) -> String {
        B64.encode(&self.spki)
    }

    /// The raw pin bytes.
    pub fn spki(&self) -> &[u8] {
        &self.spki
    }

    /// The certificate presented during the handshake.
    pub fn certificate(&self) -> &[u8] {
        &self.certificate
    }

    /// The PKCS#8 private key, for `with_client_auth_cert`.
    pub fn key_pkcs8(&self) -> Vec<u8> {
        self.key.serialize_der()
    }

    /// The PKCS#8 private key as base64, for storage.
    pub fn key_b64(&self) -> String {
        B64.encode(self.key.serialize_der())
    }
}

fn build_certificate(key: &KeyPair, role: &str) -> Result<Vec<u8>> {
    let mut params = CertificateParams::new(vec![role.to_string()])
        .map_err(|err| ProtocolError::Tls(format!("cannot build certificate params: {err}")))?;
    params.distinguished_name.push(DnType::CommonName, role);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let certificate = params
        .self_signed(key)
        .map_err(|err| ProtocolError::Tls(format!("cannot self-sign the certificate: {err}")))?;
    Ok(certificate.der().to_vec())
}

/// Extract the Ed25519 pin from a DER certificate.
///
/// Only the fixed 44-byte SubjectPublicKeyInfo is accepted, so a peer offering
/// another key type can never be pinned by accident.
pub fn spki_from_cert_der(certificate: &[u8]) -> Result<Vec<u8>> {
    if certificate.len() < SPKI_LEN {
        return Err(ProtocolError::Tls(
            "peer identity is not an Ed25519 key".into(),
        ));
    }
    for start in 0..=certificate.len() - SPKI_LEN {
        if certificate[start..start + ED25519_SPKI_PREFIX.len()] == ED25519_SPKI_PREFIX {
            return Ok(certificate[start..start + SPKI_LEN].to_vec());
        }
    }
    Err(ProtocolError::Tls(
        "peer identity is not an Ed25519 key".into(),
    ))
}

/// Build the client TLS configuration from `PROTOCOL.md` §1.
///
/// `pin` is `None` while pairing, where the one-time code authenticates the
/// peer, and `Some` for every later connection, where the stored pin does.
pub fn client_config(identity: &Identity, pin: Option<Vec<u8>>) -> Result<Arc<ClientConfig>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = Arc::new(PinVerifier {
        algorithms: provider.signature_verification_algorithms.clone(),
        pin,
    });

    let config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|err| ProtocolError::Tls(format!("cannot pin TLS 1.3: {err}")))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(
            vec![CertificateDer::from(identity.certificate().to_vec())],
            PrivatePkcs8KeyDer::from(identity.key_pkcs8()).into(),
        )
        .map_err(|err| ProtocolError::Tls(format!("cannot build the client identity: {err}")))?;

    Ok(Arc::new(config))
}

/// The server name is fixed: pinning replaces name validation, but rustls still
/// requires a name and the certificate carries it as its only SAN.
pub fn server_name() -> ServerName<'static> {
    ServerName::try_from("msm-node")
        .expect("a static ASCII server name")
        .to_owned()
}

/// Accepts a peer certificate when its pin matches, and rejects every other key
/// type outright.
#[derive(Debug)]
struct PinVerifier {
    algorithms: WebPkiSupportedAlgorithms,
    pin: Option<Vec<u8>>,
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let spki = spki_from_cert_der(end_entity.as_ref())
            .map_err(|_| rustls::Error::General("peer identity is not an Ed25519 key".into()))?;

        if let Some(expected) = &self.pin {
            if expected.ct_eq(&spki).unwrap_u8() != 1 {
                return Err(rustls::Error::General(
                    "peer identity does not match the pin".into(),
                ));
            }
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}
