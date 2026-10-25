#![forbid(unsafe_code)]
#![deny(clippy::all, clippy::pedantic)]

use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Common limits required by the QUIC transport.
pub mod limits {
    use std::time::Duration;

    /// Keepalive interval while the connection is active.
    pub const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);
    /// Maximum idle time before an endpoint is dropped.
    pub const MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
    /// Maximum stream receive window.
    pub const MAX_STREAM_RECEIVE_WINDOW: usize = 1024 * 1024;
    /// Maximum total connection receive window.
    pub const MAX_CONNECTION_RECEIVE_WINDOW: usize = 8 * 1024 * 1024;
    /// Maximum number of concurrent bidirectional streams per direction.
    pub const MAX_BIDIRECTIONAL_STREAMS: u64 = 64;
    /// Maximum number of concurrent bidirectional streams for a client connection.
    pub const CLIENT_MAX_BIDIRECTIONAL_STREAMS: u64 = 16;
    /// Default TCP timeout when dialing a target.
    pub const TARGET_DIAL_TIMEOUT: Duration = Duration::from_secs(5);
    /// Standard copy buffer size used in relay and agent splicing.
    pub const COPY_BUFFER_SIZE: usize = 32 * 1024;
}

/// Transport errors for dialing and relaying.
#[derive(Debug, Error)]
pub enum TransportError {
    #[error("IO failure: {0}")]
    Io(String),
    #[error("handshake timed out")]
    HandshakeTimeout,
    #[error("invalid target")]
    InvalidTarget,
}

/// Backoff configuration for reconnect loops.
pub struct Backoff {
    /// Base reconnect delay before jitter.
    pub base: Duration,
    /// Exponential growth factor.
    pub factor: u32,
    /// Maximum backoff bound.
    pub max: Duration,
}

impl Default for Backoff {
    fn default() -> Self {
        Self {
            base: Duration::from_secs(1),
            factor: 2,
            max: Duration::from_secs(60),
        }
    }
}

/// Compute the next backoff duration for a given attempt count.
#[must_use]
pub fn backoff_for(attempt: u32) -> Duration {
    let base = Backoff::default();
    let exp = base
        .base
        .saturating_mul(2u32.saturating_pow(attempt.min(10)));
    exp.min(base.max)
}

/// Splice two TCP streams without building an unbounded queue.
///
/// # Errors
///
/// Returns an error if either stream cannot be read or the shutdown step fails.
pub async fn splice_streams(left: &mut TcpStream, right: &mut TcpStream) -> std::io::Result<()> {
    let mut left_buffer = vec![0u8; limits::COPY_BUFFER_SIZE];
    let mut right_buffer = vec![0u8; limits::COPY_BUFFER_SIZE];
    loop {
        tokio::select! {
            result = left.read(&mut left_buffer) => {
                let read = result?;
                if read == 0 {
                    right.shutdown().await?;
                    return Ok(());
                }
                right.write_all(&left_buffer[..read]).await?;
            }
            result = right.read(&mut right_buffer) => {
                let read = result?;
                if read == 0 {
                    left.shutdown().await?;
                    return Ok(());
                }
                left.write_all(&right_buffer[..read]).await?;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_stays_bounded() {
        let first = backoff_for(0);
        let second = backoff_for(4);
        let last = backoff_for(100);
        assert!(first <= Duration::from_secs(60));
        assert!(second <= Duration::from_secs(60));
        assert!(last <= Duration::from_secs(60));
    }
}
