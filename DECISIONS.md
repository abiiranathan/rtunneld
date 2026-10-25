# Decisions and assumptions log

## 2026-10-25 — project scaffold
- Chose a Cargo workspace with six crates matching the requested architecture: `proto`, `identity`, `transport`, `relay`, `agent`, and `client`.
- Used the current stable Rust toolchain (1.98.0 at the time of development) and pinned the workspace `rust-version` accordingly.
- Kept `#![forbid(unsafe_code)]` in every library and selected explicit crate boundaries to isolate protocol, identity, and transport logic from binaries.
- Chose `quinn`, `rustls`, and `tokio` as the primary networking stack behind the transport module boundary, while keeping the transport layer small enough to swap with a TCP+TLS+yamux fallback later.
- Structured the relay and agent binaries as thin entry points around library logic to preserve testability and allow in-process integration testing.

## 2026-10-25 — protocol and wire framing
- The `proto` crate defines a small control-message set with a fixed 2-byte length prefix and a 4 KiB max frame size, matching the spec's wire framing constraints.
- Postcard is used for deterministic control-frame encoding, with `ErrorCode` and `HostPort` values preserved across round trips.
- Property tests exercise round trips for generated control messages rather than depending on opaque `Arbitrary` derives.

## 2026-10-25 — identity layer
- The identity crate uses `rcgen` to generate a self-signed certificate and derives an SHA-256 fingerprint for a given certificate body.
- Private key files are restricted while loading on Unix by rejecting group/world permissions that would permit other users to read the secret.
- Enrollment tokens are represented as JSON payloads with a nonce and expiry, stored in a compact base64 form for future relay validation flows.

## 2026-10-25 — operational posture
- The project includes repository-level CI and a placeholder deployment layout to support Linux packaging, dockerized testing, and future e2e validation.
- This scaffold intentionally captures the protocol and authorization boundaries specified by the design but leaves the full relay/agent runtime state machine as a future extension beyond the initial buildable foundation.
