#![forbid(unsafe_code)]
#![deny(clippy::all, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

use bytes::{BufMut, BytesMut};
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

/// Hard maximum size for a protocol frame in bytes before decoding allocates.
pub const MAX_FRAME_SIZE: usize = 4 * 1024;

/// Length of the framing header in bytes (big-endian 16-bit unsigned integer).
pub const FRAME_HEADER_LEN: usize = 2;

/// Application-level ALPN identifier for normal authenticated tunnel sessions.
pub const ALPN_TUNNEL: &[u8] = b"rtunnel/1";

/// Application-level ALPN identifier used exclusively for one-time enrollment exchanges.
pub const ALPN_ENROLL: &[u8] = b"rtunnel-enroll/1";

/// Current protocol minor revision.
pub const PROTOCOL_MINOR: u16 = 1;

/// Stable protocol error codes exchanged between relay, agent, and client peers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorCode {
    /// The client is not authorized for this agent.
    Unauthorized = 1,
    /// The requested agent is offline or disconnected.
    AgentOffline = 2,
    /// The requested target is outside the agent's allowed target list.
    TargetNotAllowed = 3,
    /// The target socket could not be reached or connection timed out.
    TargetUnreachable = 4,
    /// A network or protocol handshake timeout occurred.
    Timeout = 5,
    /// The peer exceeded pre-authentication or session rate limits.
    RateLimited = 6,
    /// The remote peer violated the framing or messaging specification.
    ProtocolViolation = 7,
    /// The peer was superseded by a newer connection with the same identity.
    Superseded = 8,
    /// The peer identity has been revoked.
    Revoked = 9,
    /// An internal relay or agent failure occurred.
    Internal = 10,
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

/// A target destination consisting of a valid hostname or IP address and a destination port.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostPort {
    /// The destination host name or literal IP address.
    pub host: String,
    /// The destination TCP port.
    pub port: u16,
}

impl HostPort {
    /// Creates a validated destination host and port pair.
    ///
    /// # Errors
    ///
    /// Returns a [`ProtocolError::ProtocolViolation`] if the hostname is empty, exceeds 253 bytes,
    /// or contains control characters.
    pub fn new(host: impl Into<String>, port: u16) -> Result<Self, ProtocolError> {
        let host = host.into();
        Self::validate_host(&host)?;
        if port == 0 {
            return Err(ProtocolError::ProtocolViolation);
        }
        Ok(Self { host, port })
    }

    /// Parses a string formatted as `host:port`.
    ///
    /// # Errors
    ///
    /// Returns a [`ProtocolError::ProtocolViolation`] when the input is malformed, lacks a port,
    /// or contains an invalid host or port.
    pub fn parse(value: &str) -> Result<Self, ProtocolError> {
        let (host, port_str) = value
            .rsplit_once(':')
            .ok_or(ProtocolError::ProtocolViolation)?;
        let port = port_str
            .parse::<u16>()
            .map_err(|_| ProtocolError::ProtocolViolation)?;
        Self::new(host, port)
    }

    fn validate_host(host: &str) -> Result<(), ProtocolError> {
        if host.is_empty() || host.len() > 253 {
            return Err(ProtocolError::ProtocolViolation);
        }
        if host
            .chars()
            .any(|c| c.is_ascii_control() || c.is_whitespace())
        {
            return Err(ProtocolError::ProtocolViolation);
        }
        Ok(())
    }
}

impl fmt::Display for HostPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

/// Status reported by the agent after attempting to connect to a target.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResultStatus {
    /// The destination socket was dialed successfully.
    Ok,
    /// Dialing the destination socket failed with the specified error code.
    Err(ErrorCode),
}

/// Information describing a registered agent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentInfo {
    /// The unique name of the agent.
    pub name: String,
    /// Whether the agent currently holds an active connection to the relay.
    pub online: bool,
}

/// Control messages exchanged over QUIC bidirectional streams.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlMessage {
    /// Initial client capability greeting.
    Hello {
        /// Minor version of the peer protocol implementation.
        protocol_minor: u16,
        /// List of supported feature strings.
        features: Vec<String>,
    },
    /// Relay acknowledgement of greeting.
    HelloAck {
        /// Assigned peer name confirmed by the relay.
        agent_name: String,
    },
    /// Agent announcement upon completing the TLS handshake.
    AgentHello {
        /// Minor version of the peer protocol implementation.
        protocol_minor: u16,
        /// Software version of the connecting agent.
        agent_version: String,
        /// Machine hostname where the agent runs.
        hostname: String,
    },
    /// Client request to connect to a named agent and optional target.
    ConnectRequest {
        /// Target agent name.
        agent: String,
        /// Destination host and port, or `None` for agent default.
        target: Option<HostPort>,
    },
    /// Relay instruction directing an agent to open a TCP target socket.
    OpenTarget {
        /// Stable session identifier for auditing and telemetry.
        session_id: String,
        /// Authenticated client name initiating the connection.
        client_name: String,
        /// Target destination host.
        host: String,
        /// Target destination port.
        port: u16,
    },
    /// Agent response indicating whether the target socket was opened.
    OpenResult {
        /// Stable session identifier.
        session_id: String,
        /// Status of the open attempt.
        status: ResultStatus,
    },
    /// Relay response to the client indicating whether the tunnel session is ready.
    ConnectResponse {
        /// Stable session identifier.
        session_id: String,
        /// Final status of the connection request.
        status: ResultStatus,
    },
    /// Client query requesting the list of accessible agents.
    ListAgents {
        /// Authenticated client name.
        client_name: String,
    },
    /// Relay listing of agents granted to the requesting client.
    ListAgentsResponse {
        /// Granted agent statuses.
        agents: Vec<AgentInfo>,
    },
    /// Peer request to enroll using a one-time token.
    Enroll {
        /// Secret one-time enrollment token.
        token: String,
    },
    /// Relay confirmation of successful enrollment.
    EnrollAck {
        /// Enrolled peer name.
        name: String,
        /// Assigned peer role (`"agent"` or `"client"`).
        role: String,
    },
    /// Notification that the relay is shutting down gracefully.
    Shutdown {
        /// Human-readable explanation.
        reason: String,
    },
    /// Notification that the peer's authorization has been revoked.
    Revoked {
        /// Human-readable explanation.
        reason: String,
    },
    /// Generic error notification.
    Error {
        /// Machine-readable error code.
        code: ErrorCode,
        /// Human-readable error message.
        message: String,
    },
}

/// Errors occurring during control frame serialization or decoding.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProtocolError {
    /// The serialized or declared frame size exceeds [`MAX_FRAME_SIZE`].
    #[error("frame size exceeds maximum limit of {MAX_FRAME_SIZE} bytes")]
    OversizedFrame,
    /// Unconsumed trailing bytes were detected after decoding a valid message.
    #[error("trailing unconsumed bytes after frame")]
    TrailingBytes,
    /// The wire data could not be parsed into a recognized message.
    #[error("protocol violation: malformed frame payload")]
    ProtocolViolation,
    /// An internal serialization error occurred.
    #[error("serialization error: {0}")]
    Serialization(String),
}

/// Encodes a [`ControlMessage`] into a length-prefixed wire frame.
///
/// # Errors
///
/// Returns [`ProtocolError::OversizedFrame`] if the message serialized representation
/// exceeds [`MAX_FRAME_SIZE`].
pub fn encode_frame(message: &ControlMessage) -> Result<Vec<u8>, ProtocolError> {
    let payload = postcard::to_allocvec(message)
        .map_err(|err| ProtocolError::Serialization(err.to_string()))?;
    if payload.len() > MAX_FRAME_SIZE {
        return Err(ProtocolError::OversizedFrame);
    }
    let length = u16::try_from(payload.len()).map_err(|_| ProtocolError::OversizedFrame)?;
    let mut out = BytesMut::with_capacity(FRAME_HEADER_LEN + payload.len());
    out.put_u16(length);
    out.extend_from_slice(&payload);
    Ok(out.to_vec())
}

/// Decodes a [`ControlMessage`] and consumed byte count from a wire buffer.
///
/// # Errors
///
/// Returns [`ProtocolError::OversizedFrame`] if the declared frame length exceeds [`MAX_FRAME_SIZE`],
/// or [`ProtocolError::ProtocolViolation`] if the buffer is incomplete or corrupt.
pub fn decode_frame(buf: &[u8]) -> Result<(ControlMessage, usize), ProtocolError> {
    if buf.len() < FRAME_HEADER_LEN {
        return Err(ProtocolError::ProtocolViolation);
    }
    let length = usize::from(u16::from_be_bytes([buf[0], buf[1]]));
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

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn arb_host_port() -> impl Strategy<Value = HostPort> {
        ("[a-z0-9.-]{1,32}", 1u16..=65535).prop_filter_map("valid hostport", |(host, port)| {
            HostPort::new(host, port).ok()
        })
    }

    fn arb_message() -> impl Strategy<Value = ControlMessage> {
        prop_oneof![
            (0u16..=10, prop::collection::vec("[a-z0-9-]{0,16}", 0..=4)).prop_map(
                |(minor, features)| ControlMessage::Hello {
                    protocol_minor: minor,
                    features,
                }
            ),
            "[a-z0-9-]{1,16}".prop_map(|agent_name| ControlMessage::HelloAck { agent_name }),
            ("[a-z0-9-]{1,16}", "[a-z0-9-]{1,16}").prop_map(|(agent_version, hostname)| {
                ControlMessage::AgentHello {
                    protocol_minor: PROTOCOL_MINOR,
                    agent_version,
                    hostname,
                }
            }),
            ("[a-z0-9-]{1,16}", prop::option::of(arb_host_port()))
                .prop_map(|(agent, target)| { ControlMessage::ConnectRequest { agent, target } }),
            (
                "[a-z0-9-]{1,16}",
                "[a-z0-9-]{1,16}",
                "[a-z0-9.-]{1,16}",
                1u16..=65535
            )
                .prop_map(|(session_id, client_name, host, port)| {
                    ControlMessage::OpenTarget {
                        session_id,
                        client_name,
                        host,
                        port,
                    }
                }),
            ("[a-z0-9-]{1,16}").prop_map(|session_id| ControlMessage::OpenResult {
                session_id,
                status: ResultStatus::Ok,
            }),
            ("[a-z0-9-]{1,16}").prop_map(|session_id| ControlMessage::ConnectResponse {
                session_id,
                status: ResultStatus::Ok,
            }),
            "[a-z0-9-]{1,16}".prop_map(|token| ControlMessage::Enroll { token }),
            ("[a-z0-9-]{1,16}", "[a-z0-9-]{1,16}")
                .prop_map(|(name, role)| ControlMessage::EnrollAck { name, role }),
        ]
    }

    #[test]
    fn round_trip_connect_request() {
        let msg = ControlMessage::ConnectRequest {
            agent: "agent-1".into(),
            target: Some(HostPort::new("127.0.0.1", 22).unwrap()),
        };
        let encoded = encode_frame(&msg).unwrap();
        let (decoded, consumed) = decode_frame(&encoded).unwrap();
        assert_eq!(decoded, msg);
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn rejects_oversized_frame() {
        let mut raw = vec![0u8; 10];
        let len = u16::try_from(MAX_FRAME_SIZE + 1).unwrap();
        raw[0..2].copy_from_slice(&len.to_be_bytes());
        assert_eq!(decode_frame(&raw), Err(ProtocolError::OversizedFrame));
    }

    proptest! {
        #[test]
        fn round_trip_property(msg in arb_message()) {
            let encoded = encode_frame(&msg).unwrap();
            let (decoded, consumed) = decode_frame(&encoded).unwrap();
            prop_assert_eq!(decoded, msg);
            prop_assert_eq!(consumed, encoded.len());
        }

        #[test]
        fn arbitrary_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..5000)) {
            let _ = decode_frame(&bytes);
        }
    }
}
