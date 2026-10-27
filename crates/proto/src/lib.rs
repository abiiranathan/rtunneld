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

/// Application-level ALPN identifier used for one-time enrollment exchanges.
pub const ALPN_ENROLL: &[u8] = b"rtunnel-enroll/1";

/// Application-level ALPN identifier for pairing and rendezvous coordination.
pub const ALPN_RENDEZVOUS: &[u8] = b"rtunnel-rendezvous/1";

/// Current protocol minor revision.
///
/// Revision 4 adds the early `PairPending` notice so both operators can compare
/// the SAS before either side approves the pairing request.
pub const PROTOCOL_MINOR: u16 = 4;

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
    /// The pairing code provided was invalid, expired, or locked out.
    InvalidPairingCode = 11,
    /// The pairing request was denied by the remote host operator.
    PairingDenied = 12,
    /// The requested Device ID was not found on the rendezvous relay.
    DeviceNotFound = 13,
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
            Self::InvalidPairingCode => "InvalidPairingCode",
            Self::PairingDenied => "PairingDenied",
            Self::DeviceNotFound => "DeviceNotFound",
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
    /// The unique name or device ID of the agent.
    pub name: String,
    /// Whether the agent currently holds an active connection to the relay.
    pub online: bool,
}

/// Agent status including the targets the agent has advertised.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentDetail {
    /// The unique name or device ID of the agent.
    pub name: String,
    /// Whether the agent currently holds an active connection to the relay.
    pub online: bool,
    /// Exact-match `host:port` targets the agent accepts.
    pub targets: Vec<String>,
}

/// Level of persistence granted during host pairing approval.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum GrantDuration {
    /// Allowed for this session only (no persistent DB entry).
    Once,
    /// Permanently saved to the database.
    Always,
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
    /// Client request to connect to a named agent or device ID.
    ConnectRequest {
        /// Target agent name or 9-digit Device ID.
        agent: String,
        /// Destination host and port, or `None` for agent default.
        target: Option<HostPort>,
    },
    /// Relay instruction directing an agent to open a TCP target socket.
    OpenTarget {
        /// Stable session identifier for auditing and telemetry.
        session_id: String,
        /// Authenticated client name or Device ID initiating the connection.
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
    /// Peer request to enroll using a legacy one-time token.
    Enroll {
        /// Secret one-time enrollment token.
        token: String,
    },
    /// Relay confirmation of successful enrollment.
    EnrollAck {
        /// Enrolled peer name or assigned Device ID.
        name: String,
        /// Assigned peer role (`"agent"`, `"client"`, or `"node"`).
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
    /// Agent advertisement of the targets it is willing to open.
    AgentTargets {
        /// Exact-match `host:port` targets accepted by the agent.
        targets: Vec<String>,
    },
    /// Client query for agents including their advertised targets.
    ListAgentsDetailed {
        /// Authenticated client name.
        client_name: String,
    },
    /// Relay response carrying agent targets for clients that support discovery.
    AgentsDetailedResponse {
        /// Granted agent statuses with advertised targets.
        agents: Vec<AgentDetail>,
    },

    // --- AnyDesk-Style Rendezvous & Pairing Additions ---
    /// Request to register a zero-config peer and allocate or confirm a Device ID.
    RegisterDevice {
        /// Preferred device label or hostname.
        label: String,
        /// If re-registering an existing Device ID.
        existing_device_id: Option<String>,
    },
    /// Relay acknowledgement granting or confirming the Device ID.
    RegisterDeviceAck {
        /// Canonical 9-digit Device ID (e.g. "482913077").
        device_id: String,
    },
    /// Host updates its ephemeral pairing code on the relay.
    SetPairingCode {
        /// SHA-256 hash of the one-time pairing code.
        code_hash: String,
        /// TTL in seconds.
        ttl_secs: u32,
    },
    /// Client requests pairing with a target Device ID using an access code.
    PairRequest {
        /// Target 9-digit Device ID.
        target_device_id: String,
        /// Pairing code entered by the client operator.
        code: String,
        /// Client human-readable hostname or user identity.
        client_label: String,
        /// Optional client SSH public key (e.g. "ssh-ed25519 AAAA...").
        ssh_pubkey: Option<String>,
    },
    /// Relay routes pairing request to the host with a calculated SAS code.
    IncomingPairPrompt {
        /// Request session token.
        pair_session_id: String,
        /// Initiator client Device ID or name.
        client_id: String,
        /// Initiator label.
        client_label: String,
        /// 4-digit Short Authentication String computed for out-of-band visual verification.
        sas: String,
        /// Client SSH public key, if supplied.
        ssh_pubkey: Option<String>,
    },
    /// Host response accepting or denying the pairing request.
    PairPromptResponse {
        /// Request session token.
        pair_session_id: String,
        /// Decision by the host operator.
        approved: bool,
        /// Grant duration: once or always.
        duration: GrantDuration,
        /// Whether the host operator approved adding the SSH public key.
        install_ssh_key: bool,
    },
    /// Relay notifies client of pairing resolution.
    PairResult {
        /// Whether pairing succeeded.
        success: bool,
        /// Assigned host device ID.
        host_device_id: String,
        /// Error details if denied or failed.
        error: Option<ErrorCode>,
    },
    /// Relay announces a pending pairing request so the client can display the
    /// same SAS the host operator is asked to approve.
    PairPending {
        /// Request session token shared with the host prompt.
        pair_session_id: String,
        /// 4-digit Short Authentication String both operators compare.
        sas: String,
        /// Canonical host Device ID being paired with.
        host_device_id: String,
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

/// Formats a raw 9-digit string into AnyDesk-style spaced digits: `482 913 077`.
#[must_use]
pub fn format_device_id(raw: &str) -> String {
    let digits: String = raw.chars().filter(char::is_ascii_digit).collect();
    if digits.len() == 9 {
        format!("{} {} {}", &digits[0..3], &digits[3..6], &digits[6..9])
    } else {
        raw.to_string()
    }
}

/// Strips formatting whitespace and dashes from a Device ID string.
#[must_use]
pub fn normalize_device_id(raw: &str) -> String {
    raw.chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect()
}

/// Computes a Short Authentication String (SAS, 4 decimal digits) derived from two peer fingerprints.
#[must_use]
pub fn compute_sas(fp_a: &str, fp_b: &str, salt: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    if fp_a < fp_b {
        hasher.update(fp_a.as_bytes());
        hasher.update(fp_b.as_bytes());
    } else {
        hasher.update(fp_b.as_bytes());
        hasher.update(fp_a.as_bytes());
    }
    hasher.update(salt.as_bytes());
    let hash = hasher.finalize();
    let num = u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]]) % 10000;
    format!("{num:04}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_normalize_device_id() {
        let raw = "482913077";
        let formatted = format_device_id(raw);
        assert_eq!(formatted, "482 913 077");
        assert_eq!(normalize_device_id(&formatted), "482913077");
        assert_eq!(normalize_device_id(" 482-913-077 "), "482913077");
    }

    #[test]
    fn test_sas_computation_symmetric() {
        let sas1 = compute_sas("fp_aaa", "fp_bbb", "session123");
        let sas2 = compute_sas("fp_bbb", "fp_aaa", "session123");
        assert_eq!(sas1, sas2);
        assert_eq!(sas1.len(), 4);
    }
}
