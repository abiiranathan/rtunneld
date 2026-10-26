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
- `AgentTargets { targets: Vec<String> }`
- `ListAgentsDetailed { client_name }`
- `AgentsDetailedResponse { agents: Vec<AgentDetail> }`

## 2.1 Target Discovery (Protocol Minor 2)
`AgentTargets` is sent by an agent on a **dedicated bidirectional stream**
immediately after the `HelloAck` control handshake. The control stream is not
reused, so relays that predate discovery simply ignore the unaccepted stream.
A discovery-aware relay records the list, persists it in `agent_targets`, and
includes it in `AgentsDetailedResponse`.

Clients ask with `ListAgentsDetailed`. If the relay rejects the frame (revision 1
relay), the client retries with `ListAgents` on a new stream and receives an
empty target list. `ListAgentsResponse` and `AgentInfo` are unchanged, so old
clients continue to work against new relays.

The first target in the advertised list is the agent's default for target-less
`ConnectRequest`s.

## 3. Stream Splicing & Teardown
When an `OpenResult::Ok` is delivered, the control stream transitions into a transparent bidirectional byte pipe:
- Half-close propagation: Stream `FIN` is converted into a socket write shutdown (`finish()` in QUIC, `shutdown(Write)` on TCP).
- Errors and resets immediately signal RST on both legs.
- 