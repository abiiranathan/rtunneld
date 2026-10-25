# rtunnel Protocol Specification

## 1. Physical and Framing Layer
All control exchanges run over multiplexed QUIC streams via ALPN negotiation:
- `rtunnel/1`: Standard authenticated tunnels. Unknown peer identities are rejected during the TLS handshake.
- `rtunnel-enroll/1`: Dedicated one-time token enrollment. Verifies signatures and pins the relay server identity while allowing unknown client identities to submit valid tokens.

### Control Frames
Every control message begins with a 2-byte big-endian length prefix followed by a Postcard-serialized `ControlMessage` payload:
- Header: `u16` in network byte order (2 bytes).
- Max size: 4096 bytes (`MAX_FRAME_SIZE`). Oversized frames are rejected before allocation.

## 2. Message Types
- `AgentHello { protocol_minor, agent_version, hostname }`
- `HelloAck { agent_name }`
- `ConnectRequest { agent, target: Option<HostPort> }`
- `OpenTarget { session_id, client_name, host, port }`
- `OpenResult { session_id, status: ResultStatus }`
- `ConnectResponse { session_id, status: ResultStatus }`
- `ListAgents { client_name }`
- `ListAgentsResponse { agents: Vec<AgentInfo> }`
- `Enroll { token }`
- `EnrollAck { name, role }`
- `Shutdown { reason }`
- `Revoked { reason }`
- `Error { code: ErrorCode, message }`

## 3. Stream Splicing & Teardown
When an `OpenResult::Ok` is delivered, the control stream transitions into a transparent bidirectional byte pipe:
- Half-close propagation: Stream `FIN` is converted into a socket write shutdown (`finish()` in QUIC, `shutdown(Write)` on TCP).
- Errors and resets immediately signal RST on both legs.
- 