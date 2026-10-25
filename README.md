# rtunnel

`rtunnel` is a self-hosted relay and tunnel project for opening encrypted SSH access to LAN hosts without publishing inbound ports. The project is organized as a Cargo workspace and follows the architecture described in `SPEC.md`.

## Workspace layout

- `crates/proto`: wire framing and protocol definitions
- `crates/identity`: certificate and fingerprint helpers
- `crates/transport`: transport limits, reconnect backoff, and stream splicing
- `crates/relay`: relay library and `rtunneld` binary
- `crates/agent`: `rtunnel-agent` binary
- `crates/client`: `rtunnel` client binary

## Quick status

The workspace is buildable and tested at the project scaffold level:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings -W clippy::pedantic
cargo test --workspace --all-targets
```

## Architecture summary

The design is a QUIC relay in front of an SSH endpoint. The client and agent both dial outbound to the cloud relay. The relay authenticates peers using pinned identity fingerprints and forwards raw stream bytes between the client-side proxy and the target agent.

## Deployment

See the docs in `docs/` and `deploy/` for operational and packaging guidance.
