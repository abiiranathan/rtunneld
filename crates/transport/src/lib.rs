#![forbid(unsafe_code)]
#![deny(clippy::all, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

pub mod endpoint;
pub mod ratelimit;
pub mod splice;

use quinn::Connection;
use rand::Rng;
use rtunnel_proto::{ControlMessage, FRAME_HEADER_LEN, MAX_FRAME_SIZE};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub use endpoint::{
    create_client_endpoint, create_server_endpoint, make_client_config, make_server_config,
    make_transport_config,
};
pub use ratelimit::RateLimiter;
pub use splice::{splice_quic_streams, splice_quic_to_stdio, splice_quic_to_tcp};

/// Central transport limits mandated by the project architecture.
pub mod limits {
    use std::time::Duration;

    /// Keepalive heartbeat interval while the QUIC connection is idle.
    pub const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);
    /// Maximum idle duration before an inactive connection is terminated.
    pub const MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
    /// Maximum stream receive flow control window.
    pub const MAX_STREAM_RECEIVE_WINDOW: usize = 1024 * 1024;
    /// Maximum total connection receive flow control window.
    pub const MAX_CONNECTION_RECEIVE_WINDOW: usize = 8 * 1024 * 1024;
    /// Maximum number of concurrent bidirectional streams per agent connection.
    pub const MAX_BIDIRECTIONAL_STREAMS: u64 = 64;
    /// Maximum number of concurrent bidirectional streams per client connection.
    pub const CLIENT_MAX_BIDIRECTIONAL_STREAMS: u64 = 16;
    /// Default TCP dial timeout when dialing a destination target.
    pub const TARGET_DIAL_TIMEOUT: Duration = Duration::from_secs(5);
    /// Pre-authentication handshake timeout.
    pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
    /// Fixed copy buffer size for zero-queue splicing loops.
    pub const COPY_BUFFER_SIZE: usize = 32 * 1024;
}

/// Errors raised across transport, dial, and framing operations.
#[derive(Debug, Error)]
pub enum TransportError {
    /// Underlying network or system I/O failure.
    #[error("I/O error: {0}")]
    Io(String),
    /// Configuration or crypto setup failure.
    #[error("configuration error: {0}")]
    Config(String),
    /// Protocol frame decoding failure.
    #[error("protocol frame error: {0}")]
    Protocol(#[from] rtunnel_proto::ProtocolError),
    /// Handshake or authentication failure.
    #[error("handshake error: {0}")]
    Handshake(String),
    /// Destination connection timed out.
    #[error("dial timed out")]
    Timeout,
}

/// Exponential backoff controller with full jitter for agent reconnection loops.
pub struct Backoff {
    base: Duration,
    factor: u32,
    cap: Duration,
    current_attempt: u32,
}

impl Default for Backoff {
    fn default() -> Self {
        Self {
            base: Duration::from_secs(1),
            factor: 2,
            cap: Duration::from_secs(60),
            current_attempt: 0,
        }
    }
}

impl Backoff {
    /// Calculates the next backoff duration applying full jitter.
    pub fn next_delay(&mut self) -> Duration {
        let exp = self
            .base
            .saturating_mul(self.factor.saturating_pow(self.current_attempt.min(10)));
        let ceiling = exp.min(self.cap);
        self.current_attempt = self.current_attempt.saturating_add(1);
        let millis = ceiling.as_millis();
        if millis == 0 {
            return Duration::ZERO;
        }
        let jittered = rand::thread_rng().gen_range(0..=millis);
        Duration::from_millis(u64::try_from(jittered).unwrap_or(0))
    }

    /// Resets the backoff attempt counter after a connection is stable.
    pub fn reset(&mut self) {
        self.current_attempt = 0;
    }
}

/// Asynchronously reads a length-prefixed control message from a stream.
///
/// # Errors
///
/// Returns [`TransportError::Protocol`] if the frame is oversized or malformed, or
/// [`TransportError::Io`] if reading from the underlying stream fails.
pub async fn read_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<ControlMessage, TransportError> {
    let mut header = [0u8; FRAME_HEADER_LEN];
    reader
        .read_exact(&mut header)
        .await
        .map_err(|e| TransportError::Io(e.to_string()))?;
    let length = usize::from(u16::from_be_bytes(header));
    if length > MAX_FRAME_SIZE {
        return Err(TransportError::Protocol(
            rtunnel_proto::ProtocolError::OversizedFrame,
        ));
    }
    let mut payload = vec![0u8; length];
    reader
        .read_exact(&mut payload)
        .await
        .map_err(|e| TransportError::Io(e.to_string()))?;
    let msg: ControlMessage = postcard::from_bytes(&payload)
        .map_err(|_| TransportError::Protocol(rtunnel_proto::ProtocolError::ProtocolViolation))?;
    Ok(msg)
}

/// Asynchronously writes a length-prefixed control message to a stream.
///
/// # Errors
///
/// Returns [`TransportError::Protocol`] if the message exceeds [`MAX_FRAME_SIZE`], or
/// [`TransportError::Io`] if writing to the underlying stream fails.
pub async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    message: &ControlMessage,
) -> Result<(), TransportError> {
    let frame = rtunnel_proto::encode_frame(message)?;
    writer
        .write_all(&frame)
        .await
        .map_err(|e| TransportError::Io(e.to_string()))?;
    writer
        .flush()
        .await
        .map_err(|e| TransportError::Io(e.to_string()))?;
    Ok(())
}

/// Extracts the negotiated application-level protocol (ALPN) from a QUIC connection.
#[must_use]
pub fn extract_alpn(connection: &Connection) -> Option<Vec<u8>> {
    let hd = connection.handshake_data()?;
    if let Some(data) = hd.downcast_ref::<quinn::crypto::rustls::HandshakeData>() {
        return data.protocol.clone();
    }
    None
}

/// Extracts the hex-encoded SPKI fingerprint from a peer's authenticated certificate.
///
/// # Errors
///
/// Returns [`TransportError::Handshake`] if the peer identity is missing or unparseable.
pub fn extract_peer_fingerprint(connection: &Connection) -> Result<String, TransportError> {
    let identity = connection
        .peer_identity()
        .ok_or_else(|| TransportError::Handshake("peer certificate missing".into()))?;
    if let Some(certs) = identity.downcast_ref::<Vec<rustls_pki_types::CertificateDer<'static>>>()
        && let Some(cert) = certs.first()
    {
        let spki = rtunnel_identity::extract_spki(cert.as_ref())
            .map_err(|e| TransportError::Handshake(e.to_string()))?;
        return Ok(rtunnel_identity::fingerprint_from_spki(spki));
    }
    if let Some(certs) =
        identity.downcast_ref::<Arc<Vec<rustls_pki_types::CertificateDer<'static>>>>()
        && let Some(cert) = certs.first()
    {
        let spki = rtunnel_identity::extract_spki(cert.as_ref())
            .map_err(|e| TransportError::Handshake(e.to_string()))?;
        return Ok(rtunnel_identity::fingerprint_from_spki(spki));
    }
    Err(TransportError::Handshake(
        "unable to downcast peer certificate identity".into(),
    ))
}
