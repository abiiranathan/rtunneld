#![forbid(unsafe_code)]
#![deny(clippy::all, clippy::pedantic)]

use bytes::{Buf, BufMut, BytesMut};
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

/// Hard maximum size for a protocol frame before decoding allocates.
pub const MAX_FRAME_SIZE: usize = 4 * 1024;
pub const FRAME_HEADER_LEN: usize = 2;

/// Stable protocol error codes sent to peers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorCode {
    /// The client is not authorized for this agent.
    Unauthorized,
    /// The requested agent is offline.
    AgentOffline,
    /// The requested target is outside the allowed list.
    TargetNotAllowed,
    /// The target cannot be reached.
    TargetUnreachable,
    /// The connection timed out.
    Timeout,
    /// The peer hit a rate limit.
    RateLimited,
    /// The other side violated the protocol.
    ProtocolViolation,
    /// The peer was superseded by a newer connection.
    Superseded,
    /// The peer has been revoked.
    Revoked,
    /// Unexpected server-side failure.
    Internal,
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Unauthorized => "Unauthorized",
            Self::AgentOffline => "AgentOffline",
            Self::TargetNotAllowed => "TargetNotAllowed",
            Self::TargetUnreachable => "TargetUnreachable",
            Self::Timeout => "Timeout",
            Self::RateLimited => "RateLimited",
            Self::ProtocolViolation => "ProtocolViolation",
            Self::Superseded => "Superseded",
            Self::Revoked => "Revoked",
            Self::Internal => "Internal",
        };
        write!(f, "{name}")
    }
}

/// A hostname and port pair used for target authorization.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostPort {
    /// The hostname or literal IP that is allowed to be reached.
    pub host: String,
    /// The destination TCP port.
    pub port: u16,
}

impl HostPort {
    /// Parses a host:port string without accepting malformed values.
    ///
    /// # Errors
    ///
    /// Returns an error when the string is empty, missing a port, or contains an invalid port value.
    pub fn parse(value: &str) -> Result<Self, ProtocolError> {
        let mut pieces = value.rsplitn(2, ':');
        let port = pieces.next().ok_or(ProtocolError::ProtocolViolation)?;
        let host = pieces.next().unwrap_or_default();

        if host.is_empty() || port.is_empty() {
            return Err(ProtocolError::ProtocolViolation);
        }

        let port_number = port
            .parse::<u16>()
            .map_err(|_| ProtocolError::ProtocolViolation)?;
        Ok(Self {
            host: host.to_string(),
            port: port_number,
        })
    }
}

/// Result of opening a target socket on the agent side.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResultStatus {
    Ok,
    Err(ErrorCode),
}

/// Control frames exchanged on the QUIC stream.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlMessage {
    /// Initial protocol handshake from a peer.
    Hello {
        protocol_minor: u16,
        features: Vec<String>,
    },
    /// Relay acknowledges a known agent or client.
    HelloAck { agent_name: String },
    /// A generic failure from the opposite side.
    Error { code: ErrorCode, message: String },
    /// Agent announces itself and its hostname.
    AgentHello {
        protocol_minor: u16,
        agent_version: String,
        hostname: String,
    },
    /// Client requests a connection to an agent.
    ConnectRequest {
        agent: String,
        target: Option<HostPort>,
    },
    /// Relay instructs the agent to open a target.
    OpenTarget {
        session_id: String,
        client_name: String,
        host: String,
        port: u16,
    },
    /// Agent reports the result of opening the target.
    OpenResult {
        session_id: String,
        status: ResultStatus,
    },
    /// Relay forwards a target opening result to the client.
    ConnectResponse {
        session_id: String,
        status: ResultStatus,
    },
    /// Client asks for the list of granted agents.
    ListAgents { client_name: String },
    /// Relay lists agent availability.
    ListAgentsResponse { agents: Vec<AgentInfo> },
    /// Agent registration is closing down.
    Shutdown { reason: String },
    /// The peer has been revoked.
    Revoked { reason: String },
}

/// Describes a remote endpoint that may be online.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentInfo {
    /// The agent's configured name.
    pub name: String,
    /// Whether the relay has an active connection to the agent.
    pub online: bool,
}

/// Errors raised when decoding or encoding a wire frame.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProtocolError {
    /// The incoming frame exceeds allowed memory limits.
    #[error("frame exceeds max size")]
    OversizedFrame,
    /// A frame contains trailing bytes after a valid message.
    #[error("trailing bytes remain")]
    TrailingBytes,
    /// A supported variant was not recognized.
    #[error("unknown protocol variant")]
    UnknownVariant,
    /// Wire data is malformed.
    #[error("protocol violation")]
    ProtocolViolation,
    /// An I/O-related issue occurred during encoding.
    #[error("I/O error: {0}")]
    Io(String),
}

/// Encode a control message into a length-prefixed frame.
///
/// # Errors
///
/// Returns an error when the message is too large or serialization fails.
pub fn encode_frame(message: &ControlMessage) -> Result<Vec<u8>, ProtocolError> {
    let bytes = postcard::to_allocvec(message).map_err(|err| ProtocolError::Io(err.to_string()))?;
    if bytes.len() > MAX_FRAME_SIZE {
        return Err(ProtocolError::OversizedFrame);
    }

    let length = u16::try_from(bytes.len()).map_err(|_| ProtocolError::OversizedFrame)?;
    let mut out = BytesMut::with_capacity(FRAME_HEADER_LEN + bytes.len());
    out.put_u16(length);
    out.extend_from_slice(&bytes);
    Ok(out.to_vec())
}

/// Decode a single control frame from a byte slice.
///
/// # Errors
///
/// Returns an error when the buffer is too short, oversized, or contains malformed data.
pub fn decode_frame(buf: &[u8]) -> Result<(ControlMessage, usize), ProtocolError> {
    if buf.len() < FRAME_HEADER_LEN {
        return Err(ProtocolError::ProtocolViolation);
    }

    let mut reader = buf;
    let length = reader.get_u16() as usize;
    if length > MAX_FRAME_SIZE {
        return Err(ProtocolError::OversizedFrame);
    }
    let total = FRAME_HEADER_LEN + length;
    if buf.len() < total {
        return Err(ProtocolError::ProtocolViolation);
    }

    let payload = &buf[FRAME_HEADER_LEN..total];
    let message: ControlMessage =
        postcard::from_bytes(payload).map_err(|_| ProtocolError::ProtocolViolation)?;

    Ok((message, total))
}

/// Validate that a byte stream does not end with embedded extra bytes.
///
/// # Errors
///
/// Returns an error when the stream contains trailing frame bytes or invalid frame metadata.
pub fn ensure_no_trailing_bytes(buf: &[u8]) -> Result<(), ProtocolError> {
    if buf.is_empty() {
        return Ok(());
    }
    let _ = decode_frame(buf)?;
    if buf.len() > FRAME_HEADER_LEN + MAX_FRAME_SIZE {
        return Err(ProtocolError::TrailingBytes);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn arb_host_port() -> impl Strategy<Value = HostPort> {
        ("[a-z0-9.-]{1,32}", 1u16..=65535).prop_map(|(host, port)| HostPort { host, port })
    }

    fn arb_message() -> impl Strategy<Value = ControlMessage> {
        prop_oneof![
            (
                "[a-z0-9-]{1,16}",
                0u16..=10,
                prop::collection::vec("[a-z0-9-]{0,16}", 0..=4)
            )
                .prop_map(|(_agent, minor, features)| ControlMessage::Hello {
                    protocol_minor: minor,
                    features,
                }),
            ("[a-z0-9-]{1,16}", "[a-z0-9-]{1,16}", "[a-z0-9-]{1,16}").prop_map(
                |(_name, host, version)| ControlMessage::AgentHello {
                    protocol_minor: 1,
                    agent_version: version,
                    hostname: host,
                }
            ),
            ("[a-z0-9-]{1,16}", arb_host_port()).prop_map(|(agent, target)| {
                ControlMessage::ConnectRequest {
                    agent,
                    target: Some(target),
                }
            }),
            ("[a-z0-9-]{1,16}", "[a-z0-9-]{1,16}", any::<u16>()).prop_map(
                |(session_id, client_name, port)| ControlMessage::OpenTarget {
                    session_id,
                    client_name,
                    host: "db1.lan".to_string(),
                    port,
                }
            ),
            ("[a-z0-9-]{1,16}", "[a-z0-9-]{1,16}").prop_map(|(session_id, _status)| {
                ControlMessage::OpenResult {
                    session_id,
                    status: ResultStatus::Ok,
                }
            }),
            ("[a-z0-9-]{1,16}", any::<bool>()).prop_map(|(name, online)| {
                ControlMessage::ListAgentsResponse {
                    agents: vec![AgentInfo { name, online }],
                }
            }),
        ]
    }

    #[test]
    fn encode_decode_round_trip() {
        let message = ControlMessage::ConnectRequest {
            agent: "clinic-a".to_string(),
            target: Some(HostPort {
                host: "db1.lan".to_string(),
                port: 5432,
            }),
        };

        let encoded = encode_frame(&message).unwrap();
        let (decoded, len) = decode_frame(&encoded).unwrap();
        assert_eq!(decoded, message);
        assert_eq!(len, encoded.len());
    }

    #[test]
    fn oversized_frame_rejected() {
        let mut payload = vec![0u8; MAX_FRAME_SIZE + 1];
        payload[0..2].copy_from_slice(&(u16::try_from(MAX_FRAME_SIZE).unwrap() + 1).to_be_bytes());
        assert!(decode_frame(&payload).is_err());
    }

    proptest! {
        #[test]
        fn any_message_round_trips(message in arb_message()) {
            let bytes = encode_frame(&message).unwrap();
            let (decoded, _) = decode_frame(&bytes).unwrap();
            prop_assert_eq!(decoded, message);
        }
    }
}
