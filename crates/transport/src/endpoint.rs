#![forbid(unsafe_code)]
#![deny(clippy::all, clippy::pedantic)]

use crate::TransportError;
use crate::limits;
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{ClientConfig, Endpoint, IdleTimeout, ServerConfig, TransportConfig, VarInt};
use rustls::client::danger::ServerCertVerifier;
use rustls::server::danger::ClientCertVerifier;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::net::SocketAddr;
use std::sync::Arc;

/// Creates a hardened [`TransportConfig`] enforcing the project resource limits.
///
/// # Panics
///
/// Panics if the configured transport limits do not fit within the QUIC `VarInt` values.
#[must_use]
pub fn make_transport_config(max_bidi: u64) -> Arc<TransportConfig> {
    let mut config = TransportConfig::default();
    config.max_idle_timeout(Some(
        IdleTimeout::try_from(limits::MAX_IDLE_TIMEOUT).expect("valid idle duration"),
    ));
    config.keep_alive_interval(Some(limits::KEEPALIVE_INTERVAL));
    config.stream_receive_window(VarInt::from_u32(u32::try_from(limits::MAX_STREAM_RECEIVE_WINDOW).expect("valid stream receive window")));
    config.receive_window(VarInt::from_u32(
        u32::try_from(limits::MAX_CONNECTION_RECEIVE_WINDOW).expect("valid connection receive window"),
    ));
    config.max_concurrent_bidi_streams(VarInt::from_u64(max_bidi).expect("valid bidi limit"));
    Arc::new(config)
}

/// Builds a listening server endpoint bound to the specified socket address.
///
/// # Errors
///
/// Returns a [`TransportError`] if socket binding fails.
pub fn create_server_endpoint(
    listen_addr: SocketAddr,
    server_config: ServerConfig,
) -> Result<Endpoint, TransportError> {
    let endpoint = Endpoint::server(server_config, listen_addr)
        .map_err(|e| TransportError::Io(e.to_string()))?;
    Ok(endpoint)
}

/// Builds an unbound client endpoint ready to establish outgoing connections.
///
/// # Errors
///
/// Returns a [`TransportError`] if UDP socket allocation fails.
pub fn create_client_endpoint(bind_addr: SocketAddr) -> Result<Endpoint, TransportError> {
    let endpoint = Endpoint::client(bind_addr).map_err(|e| TransportError::Io(e.to_string()))?;
    Ok(endpoint)
}

/// Configures QUIC server TLS settings for mutual TLS with pinned or dynamic client verification.
///
/// # Errors
///
/// Returns a [`TransportError`] if certificate parsing or TLS configuration fails.
pub fn make_server_config(
    cert_der: &[u8],
    key_pem: &str,
    client_verifier: Arc<dyn ClientCertVerifier>,
    alpn_protocols: Vec<Vec<u8>>,
) -> Result<ServerConfig, TransportError> {
    let key_der =
        rtunnel_identity::pem_to_der(key_pem).map_err(|e| TransportError::Config(e.to_string()))?;
    let certs = vec![CertificateDer::from(cert_der.to_vec())];
    let priv_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der));

    let mut rustls_server = rustls::ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(certs, priv_key)
        .map_err(|e| TransportError::Config(e.to_string()))?;
    rustls_server.alpn_protocols = alpn_protocols;

    let quic_crypto = QuicServerConfig::try_from(rustls_server)
        .map_err(|e| TransportError::Config(e.to_string()))?;
    let mut server_config = ServerConfig::with_crypto(Arc::new(quic_crypto));
    server_config.transport_config(make_transport_config(limits::MAX_BIDIRECTIONAL_STREAMS));
    Ok(server_config)
}

/// Configures QUIC client TLS settings for mutual TLS with pinned server verification.
///
/// # Errors
///
/// Returns a [`TransportError`] if certificate parsing or TLS configuration fails.
pub fn make_client_config(
    cert_der: &[u8],
    key_pem: &str,
    server_verifier: Arc<dyn ServerCertVerifier>,
    alpn_protocols: Vec<Vec<u8>>,
) -> Result<ClientConfig, TransportError> {
    let key_der =
        rtunnel_identity::pem_to_der(key_pem).map_err(|e| TransportError::Config(e.to_string()))?;
    let certs = vec![CertificateDer::from(cert_der.to_vec())];
    let priv_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der));

    let mut rustls_client = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|e| TransportError::Config(e.to_string()))?
    .dangerous()
    .with_custom_certificate_verifier(server_verifier)
    .with_client_auth_cert(certs, priv_key)
    .map_err(|e| TransportError::Config(e.to_string()))?;
    rustls_client.alpn_protocols = alpn_protocols;

    let quic_crypto = QuicClientConfig::try_from(rustls_client)
        .map_err(|e| TransportError::Config(e.to_string()))?;
    let mut client_config = ClientConfig::new(Arc::new(quic_crypto));
    client_config.transport_config(make_transport_config(
        limits::CLIENT_MAX_BIDIRECTIONAL_STREAMS,
    ));
    Ok(client_config)
}
