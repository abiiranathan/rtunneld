# rtunnel Protocol Specification

## 1. Physical and Framing Layer

All control exchanges run over multiplexed QUIC streams via ALPN negotiation:

- `rtunnel/1`: Authenticated tunnel sessions. The relay authenticates the peer
  against the SQLite peer store during the TLS handshake and rejects unknown or
  revoked identities. Agents use this ALPN for `AgentHello` and target
  sessions; clients may use it for `ConnectRequest` and agent listing.
- `rtunnel-enroll/1`: One-time token enrollment. The relay pins its own identity
  while allowing an unknown client identity to submit a valid token.
- `rtunnel-rendezvous/1`: AnyDesk-style peer discovery and pairing. Device ID
  registration, pairing-code publication, SAS pairing, grant listing, and
  connect requests travel over this ALPN without requiring a pre-enrolled peer.

The relay's ALPN preference order is:

1. `rtunnel-rendezvous/1`
2. `rtunnel/1`
3. `rtunnel-enroll/1`

rustls applies the server's preference, so a peer that offers several ALPNs
negotiates rendezvous first. A client should still offer only the ALPN it
intends to use; `rtunnel setup` deliberately offers rendezvous only because an
unregistered identity cannot use the authenticated tunnel handler.

### Control Frames

Every control message begins with a 2-byte big-endian length prefix followed by
a Postcard-serialized `ControlMessage` payload:

- Header: `u16` in network byte order (2 bytes).
- Max size: 4096 bytes (`MAX_FRAME_SIZE`). Oversized frames are rejected before
  allocation.

## 2. Message Types

- `Hello { protocol_minor, features }`
- `AgentHello { protocol_minor, agent_version, hostname }`
- `HelloAck { agent_name }`
- `RegisterDevice { label, existing_device_id }`
- `RegisterDeviceAck { device_id }`
- `SetPairingCode { code_hash, ttl_secs }`
- `PairRequest { target_device_id, code, client_label, ssh_pubkey }`
- `IncomingPairPrompt { pair_session_id, client_id, client_label, sas, ssh_pubkey }`
- `PairPromptResponse { pair_session_id, approved, duration, install_ssh_key }`
- `PairResult { success, host_device_id, error }`
- `PairPending { pair_session_id, sas, host_device_id }`
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

## 2.2 Rendezvous, Device IDs, and Pairing (Protocol Minors 3 and 4)

AnyDesk-style discovery separates identity registration and pairing from the
data path:

- **Identity registration** happens over `rtunnel-rendezvous/1`. A peer sends
  `RegisterDevice` on a fresh bidirectional stream and receives
  `RegisterDeviceAck` with a permanent 9-digit Device ID. The relay derives the
  identity from the pinned mTLS certificate fingerprint, not from the requested
  label. Registering the same fingerprint again returns the same Device ID.
  `rtunnel setup` uses this exchange.
- **Host pairing listener**: `rtunnel host` keeps one rendezvous connection
  open, registers its Device ID, and publishes its ephemeral access code with
  `SetPairingCode`. The relay tracks that connection in a rendezvous-host
  registry, so pairing prompts never depend on the target data path.
- **Target data path**: the same host runs an `rtunnel/1` tunnel connection
  (`AgentHello`) that advertises its allowlist and serves `OpenTarget` streams.
  A host therefore normally has two relay connections: rendezvous for pairing
  and tunnel for SSH bytes.
- **Access codes**: `SetPairingCode` carries only the SHA-256 hash of the
  6-digit code and a TTL (900 seconds for `rtunnel host`). The relay stores the
  hash, the expiry, and an attempt counter. Five consecutive failures lock the
  code until the host publishes a new one. A successful verification deletes
  the code, so it is single-use; `rtunnel host` publishes a replacement after
  every prompt and before the TTL expires.

Pairing proceeds as follows:

1. The client sends `PairRequest` on a rendezvous stream.
2. The relay normalizes the Device ID, checks that the host peer exists and is
   not revoked, verifies the code hash, and looks up the host's live rendezvous
   connection. A missing rendezvous host yields `AgentOffline`; an unknown
   Device ID yields `DeviceNotFound`.
3. Protocol minor 4 adds `PairPending { pair_session_id, sas, host_device_id }`.
   The relay sends it to the client **before** waiting for the host, so the
   client operator can compare the SAS while the host operator is deciding.
4. The relay opens a stream on the host rendezvous connection and sends
   `IncomingPairPrompt` with the same `pair_session_id` and `sas`.
5. The host operator answers `PairPromptResponse`. The relay checks that the
   echoed `pair_session_id` matches, then sends the client
   `PairResult { success, host_device_id, error }`.

Grant persistence:

- `GrantDuration::Always` writes a row to the `grants` table.
- `GrantDuration::Once` creates an in-memory grant with a 5-minute TTL. It is
  not persisted and does not survive a relay restart. Live once-grants are
  included in authorization checks and in `ListAgents` /
  `ListAgentsDetailed` results until they expire.

After a successful pairing the client sends `ConnectRequest` on the same
rendezvous connection. The rendezvous handler and the authenticated client
tunnel handler both accept `ConnectRequest`, `ListAgents`, and
`ListAgentsDetailed`, so discovery works over either ALPN.

## 3. Stream Splicing & Teardown

When an `OpenResult::Ok` is delivered, the control stream transitions into a
transparent bidirectional byte pipe:

- Half-close propagation: Stream `FIN` is converted into a socket write
  shutdown (`finish()` in QUIC, `shutdown(Write)` on TCP).
- Errors and resets immediately signal RST on both legs.
- A session ends when either leg closes; the relay drops its session state and
  does not reuse the stream.
- Target streams are only opened on the host's `rtunnel/1` tunnel connection.
  Pairing prompts are only opened on its `rtunnel-rendezvous/1` connection.

## 4. Versioning and Compatibility

`PROTOCOL_MINOR` is currently `4`:

- Revision 2 added agent target discovery (`AgentTargets`).
- Revision 3 added rendezvous Device IDs, SAS pairing, and dynamic grants.
- Revision 4 added the early `PairPending` notice so both operators can compare
  the SAS before either side approves the request.

Control messages are Postcard-serialized enums; unknown variants are not
forward-compatible. Consequently the relay and its peers must run builds that
understand the messages they exchange. The ALPN split keeps older tunnel-only
agents working, but interactive pairing and `rtunnel setup` require a relay that
advertises `rtunnel-rendezvous/1`. Upgrading a relay in place preserves
`/var/lib/rtunnel` and therefore its identity, Device IDs, and grants.
