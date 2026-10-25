#![forbid(unsafe_code)]
#![deny(clippy::all, clippy::pedantic)]

use crate::TransportError;
use crate::limits;
use quinn::{RecvStream, SendStream};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

/// Splices raw bytes between two QUIC bidirectional streams, propagating FIN and half-close.
///
/// # Errors
///
/// Returns a [`TransportError`] if reading, writing, or finishing either stream fails.
pub async fn splice_quic_streams(
    mut send_a: SendStream,
    mut recv_a: RecvStream,
    mut send_b: SendStream,
    mut recv_b: RecvStream,
) -> Result<(u64, u64), TransportError> {
    let a_to_b = async {
        let mut buf = vec![0u8; limits::COPY_BUFFER_SIZE];
        let mut transferred = 0u64;
        loop {
            match recv_a.read(&mut buf).await {
                Ok(Some(n)) => {
                    send_b
                        .write_all(&buf[..n])
                        .await
                        .map_err(|e| TransportError::Io(e.to_string()))?;
                    transferred += n as u64;
                }
                Ok(None) => {
                    let _ = send_b.finish();
                    break;
                }
                Err(e) => {
                    let _ = send_b.reset(quinn::VarInt::from_u32(0));
                    return Err(TransportError::Io(e.to_string()));
                }
            }
        }
        Ok::<u64, TransportError>(transferred)
    };

    let b_to_a = async {
        let mut buf = vec![0u8; limits::COPY_BUFFER_SIZE];
        let mut transferred = 0u64;
        loop {
            match recv_b.read(&mut buf).await {
                Ok(Some(n)) => {
                    send_a
                        .write_all(&buf[..n])
                        .await
                        .map_err(|e| TransportError::Io(e.to_string()))?;
                    transferred += n as u64;
                }
                Ok(None) => {
                    let _ = send_a.finish();
                    break;
                }
                Err(e) => {
                    let _ = send_a.reset(quinn::VarInt::from_u32(0));
                    return Err(TransportError::Io(e.to_string()));
                }
            }
        }
        Ok::<u64, TransportError>(transferred)
    };

    let (up, down) = tokio::try_join!(a_to_b, b_to_a)?;
    Ok((up, down))
}

/// Splices raw bytes between a QUIC stream and a local TCP stream.
///
/// # Errors
///
/// Returns a [`TransportError`] if reading, writing, or shutting down either socket fails.
pub async fn splice_quic_to_tcp(
    mut quic_send: SendStream,
    mut quic_recv: RecvStream,
    tcp: TcpStream,
) -> Result<(u64, u64), TransportError> {
    let (mut tcp_read, mut tcp_write) = tcp.into_split();

    let quic_to_tcp = async {
        let mut buf = vec![0u8; limits::COPY_BUFFER_SIZE];
        let mut transferred = 0u64;
        loop {
            match quic_recv.read(&mut buf).await {
                Ok(Some(n)) => {
                    tcp_write
                        .write_all(&buf[..n])
                        .await
                        .map_err(|e| TransportError::Io(e.to_string()))?;
                    transferred += n as u64;
                }
                Ok(None) => {
                    let _ = tcp_write.shutdown().await;
                    break;
                }
                Err(e) => {
                    let _ = tcp_write.shutdown().await;
                    return Err(TransportError::Io(e.to_string()));
                }
            }
        }
        Ok::<u64, TransportError>(transferred)
    };

    let tcp_to_quic = async {
        let mut buf = vec![0u8; limits::COPY_BUFFER_SIZE];
        let mut transferred = 0u64;
        loop {
            match tcp_read.read(&mut buf).await {
                Ok(0) => {
                    let _ = quic_send.finish();
                    break;
                }
                Ok(n) => {
                    quic_send
                        .write_all(&buf[..n])
                        .await
                        .map_err(|e| TransportError::Io(e.to_string()))?;
                    transferred += n as u64;
                }
                Err(e) => {
                    let _ = quic_send.reset(quinn::VarInt::from_u32(0));
                    return Err(TransportError::Io(e.to_string()));
                }
            }
        }
        Ok::<u64, TransportError>(transferred)
    };

    let (up, down) = tokio::try_join!(quic_to_tcp, tcp_to_quic)?;
    Ok((up, down))
}

/// Bridges standard input and output with a remote QUIC stream for `ProxyCommand` operations.
///
/// # Errors
///
/// Returns a [`TransportError`] if I/O on stdin, stdout, or the QUIC stream fails.
pub async fn splice_quic_to_stdio<R, W>(
    mut quic_send: SendStream,
    mut quic_recv: RecvStream,
    mut input: R,
    mut output: W,
) -> Result<(u64, u64), TransportError>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let in_to_quic = async {
        let mut buf = vec![0u8; limits::COPY_BUFFER_SIZE];
        let mut transferred = 0u64;
        loop {
            let n = input
                .read(&mut buf)
                .await
                .map_err(|e| TransportError::Io(e.to_string()))?;
            if n == 0 {
                let _ = quic_send.finish();
                break;
            }
            quic_send
                .write_all(&buf[..n])
                .await
                .map_err(|e| TransportError::Io(e.to_string()))?;
            transferred += n as u64;
        }
        Ok::<u64, TransportError>(transferred)
    };

    let quic_to_out = async {
        let mut buf = vec![0u8; limits::COPY_BUFFER_SIZE];
        let mut transferred = 0u64;
        loop {
            match quic_recv.read(&mut buf).await {
                Ok(Some(n)) => {
                    output
                        .write_all(&buf[..n])
                        .await
                        .map_err(|e| TransportError::Io(e.to_string()))?;
                    output
                        .flush()
                        .await
                        .map_err(|e| TransportError::Io(e.to_string()))?;
                    transferred += n as u64;
                }
                Ok(None) => {
                    output
                        .flush()
                        .await
                        .map_err(|e| TransportError::Io(e.to_string()))?;
                    break;
                }
                Err(e) => {
                    return Err(TransportError::Io(e.to_string()));
                }
            }
        }
        Ok::<u64, TransportError>(transferred)
    };

    let (up, down) = tokio::try_join!(in_to_quic, quic_to_out)?;
    Ok((up, down))
}
