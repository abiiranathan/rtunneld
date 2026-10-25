# Protocol overview

The protocol uses a compact, length-prefixed wire frame for all control messages. Each frame starts with a 16-bit big-endian length field followed by a `postcard` serialization of a `ControlMessage` enum.

## Frame format

- 2 bytes: payload length in network byte order
- N bytes: `ControlMessage` payload
- Absolute max: 4 KiB

`decode_frame` rejects oversized payloads and malformed buffers. Any trailing bytes after the first valid frame are treated as a protocol error.

## Control message model

The `proto` crate defines the following categories:

- `Hello`: initial capability exchange
- `HelloAck`: relay acknowledgement
- `Error`: status code and message
- `AgentHello`: agent registration and hostname announcement
- `ConnectRequest`: client requests to open a session to an agent
- `OpenTarget`: relay opens a target on the agent
- `OpenResult`: target open status
- `ConnectResponse`: client visible target result
- `ListAgents`: agent listing request
- `ListAgentsResponse`: available agents
- `Shutdown`: graceful shutdown notification
- `Revoked`: revocation notification

The full protocol is intentionally centralized in the `rtunnel-proto` crate so that both transport and authorization logic can be tested without sockets.
