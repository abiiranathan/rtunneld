# Operations guide

## State and storage

- Relay state directory: `/var/lib/rtunnel`
- Agent state directory: `/var/lib/rtunnel-agent`
- Client state directory: `~/.config/rtunnel`

## Diagnostics

Use the built-in `tracing` configuration to emit JSON logs when needed. The relay should record auth and session lifecycle events to an append-only JSONL audit log.

## Restart behavior

The agent reconnect loop is intentionally backed by exponential backoff in the transport layer. The relay should tolerate short outages while retaining the connection state until the peer reconnects.

## Planned packaging

This scaffold includes the deployment layout for Docker and systemd, but production service unit tuning, health checks, and actual relay bootstrapping remain part of the next implementation pass.
