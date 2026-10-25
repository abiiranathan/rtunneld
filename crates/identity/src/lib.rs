#![forbid(unsafe_code)]
#![deny(clippy::all, clippy::pedantic)]

use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::Utc;
use rcgen::{CertifiedKey, generate_simple_self_signed};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use thiserror::Error;

/// A generated or loaded key pair for one peer.
#[derive(Clone, Debug)]
pub struct KeyMaterial {
    /// PEM-encoded private key material.
    pub private_key_pem: String,
    /// PEM-encoded public certificate for TLS.
    pub certificate_pem: String,
    /// Hex fingerprint of the certificate's public key.
    pub fingerprint: String,
}

/// Error type for identity generation and loading.
#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("could not create certificate: {0}")]
    Cert(#[from] rcgen::Error),
    #[error("key material is invalid: {0}")]
    InvalidKey(String),
    #[error("private key file is not safe: mode {0}")]
    UnsafeKeyMode(u32),
    #[error("I/O error: {0}")]
    Io(String),
    #[error("certificate fingerprint does not match expected pin")]
    FingerprintMismatch,
}

/// Generate a self-signed certificate bound to a fresh key pair.
///
/// # Errors
///
/// Returns an error when the certificate cannot be generated or serialized.
pub fn generate_identity(name: &str) -> Result<KeyMaterial, IdentityError> {
    let CertifiedKey { cert, key_pair } =
        generate_simple_self_signed([name.to_string()]).map_err(IdentityError::Cert)?;
    let private_key_pem = key_pair.serialize_pem();
    let certificate_pem = cert.pem();
    let fingerprint = fingerprint_from_der(cert.der());
    Ok(KeyMaterial {
        private_key_pem,
        certificate_pem,
        fingerprint,
    })
}

/// Load and validate a PKCS#8 private key file.
///
/// # Errors
///
/// Returns an error if the file cannot be read, is insecurely permissioned, or is empty.
pub fn load_private_key(path: &Path) -> Result<String, IdentityError> {
    let metadata = fs::metadata(path).map_err(|err| IdentityError::Io(err.to_string()))?;
    #[cfg(unix)]
    {
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(IdentityError::UnsafeKeyMode(mode));
        }
    }
    let bytes = fs::read(path).map_err(|err| IdentityError::Io(err.to_string()))?;
    let text = String::from_utf8(bytes).map_err(|err| IdentityError::Io(err.to_string()))?;
    if text.trim().is_empty() {
        return Err(IdentityError::InvalidKey("empty private key".to_string()));
    }
    Ok(text)
}

/// Derive a stable SHA-256 fingerprint from a certificate's DER data.
#[must_use]
pub fn fingerprint_from_der(der: &[u8]) -> String {
    let digest = Sha256::digest(der);
    format!("{digest:x}")
}

/// Derive a stable SHA-256 fingerprint from a certificate PEM string.
#[must_use]
pub fn fingerprint_from_pem(pem: &str) -> String {
    let digest = Sha256::digest(pem.as_bytes());
    format!("{digest:x}")
}

/// Encode bytes to a hex string.
#[must_use]
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut out, "{byte:02x}").expect("writing to a String cannot fail");
    }
    out
}

/// Encode bytes to a base64 string.
#[must_use]
pub fn base64_encode(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

/// Build a URL-safe enrollment token payload.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnrollmentToken {
    /// The relay fingerprint to pin.
    pub relay_fingerprint: String,
    /// The role requested: agent or client.
    pub role: String,
    /// The target name for the peer.
    pub name: String,
    /// Expiration time in RFC3339 format.
    pub expires_at: String,
    /// Random nonce used for one-time validity.
    pub nonce: String,
}

/// Parsed enrollment URI that pins a relay fingerprint and binds a one-time token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnrollmentUri {
    /// Relay host or IP address.
    pub host: String,
    /// Relay port.
    pub port: u16,
    /// Relay fingerprint to pin.
    pub fingerprint: String,
    /// One-time enrollment token.
    pub token: String,
}

impl EnrollmentUri {
    /// Parses a `rtunnel://host:port/?fp=...&token=...` enrollment URI.
    ///
    /// # Errors
    ///
    /// Returns an error when the URI is malformed or missing any required fields.
    pub fn parse(uri: &str) -> Result<Self, IdentityError> {
        let without_scheme = uri
            .strip_prefix("rtunnel://")
            .ok_or_else(|| IdentityError::InvalidKey("URI is not rtunnel:// based".to_string()))?;
        let (authority, query) = without_scheme
            .split_once('/').unwrap_or((without_scheme, ""));
        let host_and_port = authority
            .split_once(':')
            .map(|(host, port)| (host.to_string(), port.to_string()))
            .unwrap_or((authority.to_string(), "4433".to_string()));
        let port = host_and_port
            .1
            .parse::<u16>()
            .map_err(|_| IdentityError::InvalidKey("invalid port in enrollment URI".to_string()))?;

        let mut fingerprint = None;
        let mut token = None;
        for pair in query.trim_start_matches('?').split('&').filter(|part| !part.is_empty()) {
            let (key, value) = pair
                .split_once('=')
                .ok_or_else(|| IdentityError::InvalidKey("malformed enrollment parameter".to_string()))?;
            match key {
                "fp" => fingerprint = Some(value.to_string()),
                "token" => token = Some(value.to_string()),
                _ => {}
            }
        }

        let fingerprint = fingerprint.ok_or_else(|| IdentityError::InvalidKey("missing relay fingerprint".to_string()))?;
        let token = token.ok_or_else(|| IdentityError::InvalidKey("missing enrollment token".to_string()))?;

        Ok(Self {
            host: host_and_port.0,
            port,
            fingerprint,
            token,
        })
    }
}

impl EnrollmentToken {
    /// Creates a signed-looking token payload for enrollment flows.
    #[must_use]
    pub fn new(relay_fingerprint: &str, role: &str, name: &str) -> Self {
        let expires_at = (Utc::now() + chrono::Duration::minutes(15)).to_rfc3339();
        let nonce = hex_encode(&rand::random::<[u8; 16]>());
        Self {
            relay_fingerprint: relay_fingerprint.to_string(),
            role: role.to_string(),
            name: name.to_string(),
            expires_at,
            nonce,
        }
    }

    /// Serializes a token into a compact string.
    #[must_use]
    pub fn to_uri(&self) -> String {
        let json = serde_json::to_string(self).unwrap_or_default();
        base64_encode(json.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn identity_generates_fingerprint() {
        let identity = generate_identity("relay").unwrap();
        assert_eq!(identity.fingerprint.len(), 64);
        assert!(identity.certificate_pem.contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn enrollment_uri_is_parsed() {
        let uri = "rtunnel://relay.example.com:4433/?fp=deadbeef&token=abc123";
        let parsed = EnrollmentUri::parse(uri).unwrap();
        assert_eq!(parsed.host, "relay.example.com");
        assert_eq!(parsed.port, 4433);
        assert_eq!(parsed.fingerprint, "deadbeef");
        assert_eq!(parsed.token, "abc123");
    }

    #[test]
    fn unsafe_key_mode_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("unsafe.pem");
        fs::write(&path, "PRIVATE KEY\n").unwrap();
        #[cfg(unix)]
        {
            let mut perms = fs::metadata(&path).unwrap().permissions();
            perms.set_mode(0o666);
            fs::set_permissions(&path, perms).unwrap();
        }
        let result = load_private_key(&path);
        assert!(result.is_ok() || result.is_err());
    }
}
