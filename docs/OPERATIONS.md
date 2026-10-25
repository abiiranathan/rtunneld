# Operations Guide

## File Paths
- Relay State: `/var/lib/rtunnel` (`identity.key`, `identity.crt`, `rtunnel.db`, `audit.log`)
- Agent State: `/var/lib/rtunnel-agent` (`identity.key`, `identity.crt`, `config.toml`)
- Client State: `~/.config/rtunnel` (`identity.key`, `identity.crt`, `config.toml`)

## Audit Logging
The relay produces an append-only JSONL log at `<state_dir>/audit.log` recording:
- `session_open`, `session_close` (byte counts and duration)
- `auth_failure`
- `enroll`
- `grant_change`
- `revoke`
- 