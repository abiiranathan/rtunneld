#![forbid(unsafe_code)]
#![deny(clippy::all, clippy::pedantic)]

use crate::fingerprint_from_spki;
use crate::spki::extract_spki;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, Error as RustlsError, SignatureScheme};
use std::fmt;
use std::sync::{Arc, Mutex};

/// Dynamic validator interface checking peer certificate authorization against a database.
pub trait PeerValidator: Send + Sync {
    /// Returns `true` if the peer with the specified SPKI fingerprint is recognized and active.
    fn is_peer_allowed(&self, fingerprint: &str) -> bool;
}

/// Client-side TLS server certificate verifier that enforces SPKI fingerprint pinning.
#[derive(Debug)]
pub struct PinnedServerVerifier {
    expected_fingerprint: String,
}

impl PinnedServerVerifier {
    /// Creates a verifier pinned to the provided hexadecimal fingerprint.
    #[must_use]
    pub fn new(expected_fingerprint: &str) -> Self {
        Self {
            expected_fingerprint: expected_fingerprint.to_ascii_lowercase(),
        }
    }
}

impl ServerCertVerifier for PinnedServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        let spki = extract_spki(end_entity.as_ref())
            .map_err(|_| RustlsError::InvalidCertificate(rustls::CertificateError::BadEncoding))?;
        let fingerprint = fingerprint_from_spki(spki);
        if fingerprint.to_ascii_lowercase() != self.expected_fingerprint {
            return Err(RustlsError::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Server-side TLS client certificate verifier that checks against active peer registrations.
pub struct PinnedClientVerifier {
    validator: Option<Arc<dyn PeerValidator>>,
    allow_unregistered: bool,
}

impl fmt::Debug for PinnedClientVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PinnedClientVerifier")
            .field("allow_unregistered", &self.allow_unregistered)
            .finish_non_exhaustive()
    }
}

impl PinnedClientVerifier {
    /// Creates a verifier requiring known registered peers.
    #[must_use]
    pub fn new_strict(validator: Arc<dyn PeerValidator>) -> Self {
        Self {
            validator: Some(validator),
            allow_unregistered: false,
        }
    }

    /// Creates an enrollment verifier validating signatures while permitting unknown peers.
    #[must_use]
    pub fn new_enrollment() -> Self {
        Self {
            validator: None,
            allow_unregistered: true,
        }
    }
}

impl ClientCertVerifier for PinnedClientVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, RustlsError> {
        let spki = extract_spki(end_entity.as_ref())
            .map_err(|_| RustlsError::InvalidCertificate(rustls::CertificateError::BadEncoding))?;
        let fingerprint = fingerprint_from_spki(spki);
        if !self.allow_unregistered
            && let Some(validator) = &self.validator
            && !validator.is_peer_allowed(&fingerprint)
        {
            return Err(RustlsError::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ));
        }
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Client-side TLS server certificate verifier that supports Trust-On-First-Use (TOFU)
/// or optional fingerprint pinning, capturing the observed SPKI fingerprint.
#[derive(Debug)]
pub struct TofuServerVerifier {
    expected_fingerprint: Option<String>,
    observed_fingerprint: Arc<Mutex<Option<String>>>,
}

impl TofuServerVerifier {
    /// Creates a TOFU verifier that accepts any valid self-signed server certificate
    /// and records its SPKI fingerprint.
    #[must_use]
    pub fn new(observed_fingerprint: Arc<Mutex<Option<String>>>) -> Self {
        Self {
            expected_fingerprint: None,
            observed_fingerprint,
        }
    }

    /// Creates a verifier that checks against an expected fingerprint if provided,
    /// or records the observed fingerprint if `None`.
    #[must_use]
    pub fn new_with_optional(
        expected: Option<String>,
        observed: Arc<Mutex<Option<String>>>,
    ) -> Self {
        Self {
            expected_fingerprint: expected.map(|s| s.to_ascii_lowercase()),
            observed_fingerprint: observed,
        }
    }
}

impl ServerCertVerifier for TofuServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        let spki = extract_spki(end_entity.as_ref())
            .map_err(|_| RustlsError::InvalidCertificate(rustls::CertificateError::BadEncoding))?;
        let fingerprint = fingerprint_from_spki(spki);
        if let Some(expected) = &self.expected_fingerprint
            && fingerprint.to_ascii_lowercase() != *expected
        {
            return Err(RustlsError::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ));
        }
        if let Ok(mut lock) = self.observed_fingerprint.lock() {
            *lock = Some(fingerprint);
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
