#![forbid(unsafe_code)]
#![deny(clippy::all, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

pub mod spki;
pub mod verifier;

use base64::{Engine, engine::general_purpose::STANDARD};
use rcgen::{CertificateParams, KeyPair, PKCS_ED25519};
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use thiserror::Error;

pub use spki::extract_spki;
pub use verifier::{PeerValidator, PinnedClientVerifier, PinnedServerVerifier};

/// Errors encountered in identity generation, verification, or serialization.
#[derive(Debug, Error)]
pub enum IdentityError {
    /// Certificate generation error.
    #[error("certificate generation error: {0}")]
    Cert(#[from] rcgen::Error),
    /// Invalid private key or certificate format.
    #[error("invalid key material: {0}")]
    InvalidKey(String),
    /// Insecure file permissions detected on private key file.
    #[error("insecure file mode on private key: {0:o}")]
    UnsafeKeyMode(u32),
    /// File system input or output failure.
    #[error("file system error: {0}")]
    Io(String),
    /// Hex decoding error.
    #[error("hex decode error")]
    HexDecode,
}

/// PEM and DER representation of an ed25519 identity keypair and self-signed certificate.
#[derive(Clone, Debug)]
pub struct KeyMaterial {
    /// PKCS#8 private key in PEM format.
    pub private_key_pem: String,
    /// Self-signed X.509 certificate in PEM format.
    pub certificate_pem: String,
    /// DER bytes of the self-signed certificate.
    pub certificate_der: Vec<u8>,
    /// Hex-encoded SHA-256 fingerprint of the `SubjectPublicKeyInfo`.
    pub fingerprint: String,
}

/// Generates a fresh ed25519 keypair and self-signed X.509 certificate.
///
/// # Errors
///
/// Returns an [`IdentityError`] if key or certificate construction fails.
pub fn generate_identity(name: &str) -> Result<KeyMaterial, IdentityError> {
    let key_pair = KeyPair::generate_for(&PKCS_ED25519)?;
    let mut params = CertificateParams::new(vec![name.to_string()])?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, name);
    let cert = params.self_signed(&key_pair)?;
    let certificate_der = cert.der().to_vec();
    let certificate_pem = cert.pem();
    let private_key_pem = key_pair.serialize_pem();
    let spki_der = extract_spki(&certificate_der)?;
    let fingerprint = fingerprint_from_spki(spki_der);
    Ok(KeyMaterial {
        private_key_pem,
        certificate_pem,
        certificate_der,
        fingerprint,
    })
}

/// Computes the hex-encoded SHA-256 fingerprint of `SubjectPublicKeyInfo` bytes.
#[must_use]
pub fn fingerprint_from_spki(spki_der: &[u8]) -> String {
    let digest = Sha256::digest(spki_der);
    hex_encode(&digest)
}

/// Encodes binary data into lowercase hexadecimal.
#[must_use]
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut out, "{byte:02x}").expect("writing to a string cannot fail");
    }
    out
}

/// Decodes binary data from hexadecimal.
///
/// # Errors
///
/// Returns [`IdentityError::HexDecode`] if the input length is odd or contains invalid hex characters.
pub fn hex_decode(s: &str) -> Result<Vec<u8>, IdentityError> {
    if !s.len().is_multiple_of(2) {
        return Err(IdentityError::HexDecode);
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| IdentityError::HexDecode))
        .collect()
}

/// Performs a constant-time equality comparison between two byte slices.
#[must_use]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Validates that a peer name contains only lower-case alphanumerics and hyphens.
#[must_use]
pub fn is_valid_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 63 {
        return false;
    }
    name.chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// Decodes a base64 PEM block into raw DER bytes.
///
/// # Errors
///
/// Returns [`IdentityError::InvalidKey`] if the PEM cannot be parsed or base64 decoded.
pub fn pem_to_der(pem: &str) -> Result<Vec<u8>, IdentityError> {
    let base64_str: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    STANDARD
        .decode(base64_str)
        .map_err(|e| IdentityError::InvalidKey(e.to_string()))
}

/// Loads a keypair and certificate from disk, validating file permissions on Unix.
///
/// # Errors
///
/// Returns [`IdentityError::UnsafeKeyMode`] if the private key file has group or world permissions,
/// or [`IdentityError::Io`] if reading fails.
pub fn load_identity(state_dir: &Path) -> Result<KeyMaterial, IdentityError> {
    let key_path = state_dir.join("identity.key");
    let cert_path = state_dir.join("identity.crt");

    #[cfg(unix)]
    let meta = fs::metadata(&key_path).map_err(|e| IdentityError::Io(e.to_string()))?;
    #[cfg(unix)]
    {
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(IdentityError::UnsafeKeyMode(mode));
        }
    }

    let private_key_pem =
        fs::read_to_string(&key_path).map_err(|e| IdentityError::Io(e.to_string()))?;
    let certificate_pem =
        fs::read_to_string(&cert_path).map_err(|e| IdentityError::Io(e.to_string()))?;
    let certificate_der = pem_to_der(&certificate_pem)?;
    let spki_der = extract_spki(&certificate_der)?;
    let fingerprint = fingerprint_from_spki(spki_der);

    Ok(KeyMaterial {
        private_key_pem,
        certificate_pem,
        certificate_der,
        fingerprint,
    })
}

/// Saves an identity keypair and certificate to disk with strict file permissions (0600 on Unix).
///
/// # Errors
///
/// Returns [`IdentityError::Io`] if file creation or permission assignment fails.
pub fn save_identity(state_dir: &Path, identity: &KeyMaterial) -> Result<(), IdentityError> {
    fs::create_dir_all(state_dir).map_err(|e| IdentityError::Io(e.to_string()))?;
    let key_path = state_dir.join("identity.key");
    let cert_path = state_dir.join("identity.crt");

    fs::write(&key_path, &identity.private_key_pem)
        .map_err(|e| IdentityError::Io(e.to_string()))?;
    #[cfg(unix)]
    {
        let mut perms = fs::metadata(&key_path)
            .map_err(|e| IdentityError::Io(e.to_string()))?
            .permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&key_path, perms).map_err(|e| IdentityError::Io(e.to_string()))?;
    }

    fs::write(&cert_path, &identity.certificate_pem)
        .map_err(|e| IdentityError::Io(e.to_string()))?;
    Ok(())
}

/// A parsed enrollment URI containing target host, port, relay fingerprint, and one-time token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnrollmentUri {
    /// Relay host address.
    pub host: String,
    /// Relay listening UDP port.
    pub port: u16,
    /// Relay pinned SPKI fingerprint.
    pub relay_fingerprint: String,
    /// Secret enrollment token.
    pub token: String,
}

impl EnrollmentUri {
    /// Parses an `rtunnel://<host>:<port>/?fp=<fp>&token=<token>` enrollment URI.
    ///
    /// # Errors
    ///
    /// Returns an [`IdentityError::InvalidKey`] if any component is missing or invalid.
    pub fn parse(uri: &str) -> Result<Self, IdentityError> {
        let without_scheme = uri
            .strip_prefix("rtunnel://")
            .ok_or_else(|| IdentityError::InvalidKey("URI must use rtunnel:// scheme".into()))?;
        let (authority, query) = without_scheme
            .split_once('/')
            .unwrap_or((without_scheme, ""));
        let (host, port_str) = authority.rsplit_once(':').unwrap_or((authority, "4433"));
        let port = port_str
            .parse::<u16>()
            .map_err(|_| IdentityError::InvalidKey("invalid port in enrollment URI".into()))?;

        let mut fp = None;
        let mut token = None;
        for pair in query.trim_start_matches('?').split('&') {
            if let Some((k, v)) = pair.split_once('=') {
                match k {
                    "fp" => fp = Some(v.to_string()),
                    "token" => token = Some(v.to_string()),
                    _ => {}
                }
            }
        }
        let relay_fingerprint =
            fp.ok_or_else(|| IdentityError::InvalidKey("missing relay fingerprint (fp)".into()))?;
        let token =
            token.ok_or_else(|| IdentityError::InvalidKey("missing enrollment token".into()))?;

        Ok(Self {
            host: host.to_string(),
            port,
            relay_fingerprint,
            token,
        })
    }
}

impl std::fmt::Display for EnrollmentUri {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "rtunnel://{}:{}/?fp={}&token={}",
            self.host, self.port, self.relay_fingerprint, self.token
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_and_saves_identity() {
        let dir = tempfile::tempdir().unwrap();
        let id = generate_identity("relay").unwrap();
        assert_eq!(id.fingerprint.len(), 64);
        save_identity(dir.path(), &id).unwrap();

        let loaded = load_identity(dir.path()).unwrap();
        assert_eq!(loaded.fingerprint, id.fingerprint);
    }

    #[test]
    fn parses_enrollment_uri() {
        let raw = "rtunnel://10.0.0.1:4433/?fp=abcdef123456&token=tok789";
        let parsed = EnrollmentUri::parse(raw).unwrap();
        assert_eq!(parsed.host, "10.0.0.1");
        assert_eq!(parsed.port, 4433);
        assert_eq!(parsed.relay_fingerprint, "abcdef123456");
        assert_eq!(parsed.token, "tok789");
    }

    #[test]
    fn constant_time_eq_works() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"hello", b"hell"));
    }
}
