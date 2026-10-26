# Agent Build Prompt: Rust QUIC Relay for SSH Access to LAN Servers

## 1. Role and objective

You are a senior Rust systems engineer. Build `rtunnel` (working name, defined once in the workspace so it can be renamed), a self-hosted system that lets me SSH into servers on a private LAN from anywhere through a cloud relay I control.

Do not implement SSH. This is a transport and rendezvous layer that carries opaque bytes between the standard `ssh` client and a target `sshd`. SSH's own encryption stays end-to-end, so the relay only ever sees ciphertext.

Work autonomously, one milestone at a time (Section 14), and deliver a tested, documented Cargo workspace.

## 2. Goals and non-goals

**Goals**

- Reach a LAN server from anywhere with no inbound ports opened on the LAN: the agent and the client both dial out to the relay.
- Mutual authentication with pinned ed25519 identities. No passwords, no CA, no DNS-name trust.
- Strict default-deny authorization (which client may reach which agent, and which targets an agent will dial).
- Survive flaky networks: fast dead-peer detection, automatic agent reconnect, bounded memory under load.
- Operable: enrollment, revocation, audit log, systemd and Docker packaging.

**Non-goals (do not build)**

- An SSH client or server, terminal handling, or remote desktop.
- NAT hole punching or peer-to-peer paths (the relay is always in the data path).
- A web UI, multi-tenancy, or any database server dependency.
- Anything not listed in this document unless I ask.

## 3. Architecture

```
[dev PC]                      [cloud relay]                     [LAN]
ssh ─ProxyCommand─► rtunnel ──QUIC──► rtunneld ◄──QUIC── rtunnel-agent ──TCP──► sshd / other hosts
                 (both legs dial outbound; the relay splices streams)
```

- `rtunnel-agent` runs on a LAN host (systemd). It holds one long-lived QUIC connection to the relay. For each stream the relay opens, it dials an allowed TCP target and splices bytes.
- `rtunnel` (client CLI) runs on my PC as an OpenSSH `ProxyCommand`. It connects to the relay, requests an agent by name, then bridges stdin/stdout to the stream.
- `rtunneld` (relay) runs on a cloud instance. It authenticates both sides, enforces authorization, pairs a client stream with a new stream to the agent, and copies bytes between them. It never dials anything itself.

Transport is QUIC (`quinn`) for stream multiplexing, per-stream flow control, and built-in keepalive and idle detection. Keep the transport behind a small trait or module boundary so a TCP+TLS+yamux fallback can be added later for networks that block UDP.

## 4. Configuration defaults and placeholders

| Item                 | Default                                                                                                   |
| -------------------- | --------------------------------------------------------------------------------------------------------- |
| Project name         | `rtunnel`                                                                                                 |
| Relay listen address | `0.0.0.0:4433/udp`                                                                                        |
| Relay state dir      | `/var/lib/rtunnel` (SQLite db, relay key, audit log)                                                      |
| Client state dir     | `~/.config/rtunnel`                                                                                       |
| Agent state dir      | `/var/lib/rtunnel-agent`                                                                                  |
| Rust toolchain       | Current stable. Set `rust-version` in Cargo.toml to that version.                                         |
| License              | MIT                                                                                                       |
| Build targets        | Relay: Linux x86\_64/aarch64. Agent: Linux x86\_64/aarch64 (musl, static). Client: Linux, macOS, Windows. |

## 5. Workspace layout

```
rtunnel/
├─ Cargo.toml                # workspace, shared lints, pinned deps
├─ crates/
│  ├─ proto/                 # frame types, codec, error codes, constants (no I/O)
│  ├─ identity/              # key gen/load, self-signed cert, fingerprints, rustls verifiers
│  ├─ transport/             # quinn endpoint/config builders, stream helpers, splice
│  ├─ relay/                 # rtunneld binary + lib (registry, authz, store, audit)
│  ├─ agent/                 # rtunnel-agent binary + lib
│  └─ client/                # rtunnel binary + lib
├─ tests/                    # cross-crate integration tests
├─ deploy/                   # systemd units, Dockerfile, docker-compose.yml
├─ scripts/e2e.sh            # real-sshd end-to-end check
├─ docs/                     # README, PROTOCOL.md, SECURITY.md, OPERATIONS.md
└─ DECISIONS.md              # running log of choices and assumptions
```

## 6. Technology stack

Use current releases and pin exact versions. Do not rely on memory for API details: quinn and rustls change between releases, so read the docs for the versions you pin (`cargo doc`, docs.rs).

- `tokio` (multi-thread), `tokio-util`, `bytes`
- `quinn` with `rustls`. Choose one crypto provider (`ring` or `aws-lc-rs`) and use it everywhere.
- `rcgen` (self-signed cert from an ed25519 key), `sha2`, `zeroize`, `rand`
- `serde` + `postcard` for control frames
- `rusqlite` (bundled) for the relay store
- `clap` (derive), `toml` + `serde` for config, `directories`
- `tracing`, `tracing-subscriber` (with a JSON output option), `thiserror` for library errors, `anyhow` only in binaries
- Dev: `proptest`, `tempfile`, `assert_cmd`, and a `cargo-fuzz` target for the frame decoder

Justify any additional dependency in DECISIONS.md.

## 7. Identity, enrollment, authorization

**Identity**

- Every agent, client, and the relay owns an ed25519 keypair (PKCS#8 PEM). On Unix, create it with mode 0600 and refuse to load a key file that is group- or world-readable.
- Generate a self-signed X.509 certificate from the key and use it for TLS in both directions (mutual TLS).
- A peer's identity is the SHA-256 of its certificate's SubjectPublicKeyInfo, hex-encoded (the fingerprint). Implement custom rustls `ServerCertVerifier` and `ClientCertVerifier` that validate handshake signatures through the crypto provider and then pin by fingerprint. Never fall back to chain or hostname validation, and never use an accept-everything verifier outside the enrollment path described below.

**ALPN**

- `rtunnel/1`: normal authenticated sessions. Unknown client fingerprints are rejected during the handshake.
- `rtunnel-enroll/1`: enrollment only. It accepts unknown client certificates but permits exactly one message (`Enroll`), under tight rate limits.

**Enrollment**

1. Admin runs `rtunneld token create --role agent|client --name <name> --ttl 15m`. It prints a single-use token and an enrollment URI of the form `rtunnel://<host>:<port>/?fp=<relay fingerprint>&token=<token>`.
2. The peer runs `rtunnel-agent enroll <uri>` or `rtunnel enroll <uri>`. It generates a key if absent, connects with the enrollment ALPN, pins the relay fingerprint from the URI, and sends the token.
3. The relay consumes the token atomically (single use, expiry enforced, tokens stored only as SHA-256 hashes, compared in constant time), then records the peer's fingerprint, role, and name.
4. The peer writes its config with the relay address and the pinned relay fingerprint.

Names match `[a-z0-9-]{1,63}` and are unique.

**Authorization**

- Default deny. A `grants` table maps client name to agent name. A client may only connect to agents it is granted. Admin commands: `rtunneld grant add|remove|list`.
- Defense in depth: the agent config has `allowed_targets`, an exact-match list of `host:port` strings (default `127.0.0.1:22`). The agent refuses everything else, regardless of what the relay says.
- Revocation: `rtunneld revoke <name|fingerprint>` marks the peer revoked. The relay must close that peer's live connections and sessions within 5 seconds (poll a revision counter) and refuse future handshakes.

## 8. Wire protocol

Document it in `docs/PROTOCOL.md` and implement it in `crates/proto`.

**Framing.** Control messages are a `u16` big-endian length followed by a postcard-encoded enum, with a hard maximum frame size of 4 KiB checked before any allocation. Unknown variants, trailing bytes, or oversized frames are protocol errors: close the stream with an application error code (named constants, never bare integers).

**Versioning.** The ALPN carries the major version. `Hello` carries a minor version and a feature list for forward compatibility.

**Flows**

1. *Agent registration.* After the handshake the agent opens a bidirectional control stream and sends `AgentHello { protocol_minor, agent_version, hostname }`. The relay replies `HelloAck { agent_name }` or `Error { code, message }`. The control stream stays open for the connection lifetime and carries relay-to-agent notices (`Shutdown`, `Revoked`). If a second connection arrives for the same agent, the newer one wins and the older is closed with code `Superseded`.
2. *Client connect.* The client opens a bidirectional stream and sends `ConnectRequest { agent, target: Option<HostPort> }`. A missing target means the agent's first allowed target.
3. *Relay to agent.* After authorization, the relay opens a new bidirectional stream on the agent connection and sends `OpenTarget { session_id, client_name, host, port }`. The agent validates against `allowed_targets`, dials TCP with a 5 s timeout, and replies `OpenResult::Ok` or `OpenResult::Err(code)`.
4. *Relay to client.* The relay forwards the result as `ConnectResponse`. On `Ok`, both streams switch to raw bytes with no further framing, and the relay splices them.
5. *Listing.* `ListAgents` (client to relay) returns granted agents with an `online` flag.

**Error codes** (enum, stable numbering): `Unauthorized`, `AgentOffline`, `TargetNotAllowed`, `TargetUnreachable`, `Timeout`, `RateLimited`, `ProtocolViolation`, `Superseded`, `Revoked`, `Internal`. Do not leak internal details in messages sent to peers.

**Stream teardown.** Propagate half-close faithfully: a FIN on one leg becomes `finish()` on the other leg or a TCP write shutdown, and the reverse direction keeps flowing until it also ends. A reset on one leg resets the other. A clean `ssh` exit must leave no lingering tasks or sockets.

## 9. Component behavior

**Relay (`rtunneld`)**

- Subcommands: `init` (create state dir and relay key, print the relay fingerprint), `install` (install the running binary, embedded systemd unit, and state), `serve`, `token create|list|revoke`, `grant add|remove|list`, `peers list`, `revoke`.
- SQLite store (WAL mode) for peers, tokens, and grants, with schema migrations. In-memory registry of online agents (name to connection handle).
- Enable QUIC address validation (Retry) for unvalidated clients. Authenticate before allocating per-session resources.
- Handle SIGTERM with graceful shutdown: stop accepting, notify agents, drain sessions for up to 30 s.

**Agent (`rtunnel-agent`)**

- Subcommands: `enroll <uri>`, `run`, `install [uri]`.
- Reconnect loop with exponential backoff: base 1 s, factor 2, cap 60 s, full jitter, reset after a connection has been stable for 60 s.
- Per stream: validate, dial (with TCP\_NODELAY), splice. Cap concurrent sessions (default 64).
- Ship a hardened systemd unit (`StateDirectory`, `NoNewPrivileges`, `ProtectSystem=strict`, restricted address families, `Restart=always`).

**Client (`rtunnel`)**

- Subcommands: `enroll <uri>`, `connect <agent> [host:port]`, `agents`, `ssh-config <agent> [host:port] [--write]`, `install [uri]`.
- `connect` is the `ProxyCommand` entry point. **stdout carries only tunnel bytes. All logs and errors go to stderr.** On failure, exit non-zero with a one-line, human-readable error. When the stream ends, exit cleanly.
- `ssh-config` prints a ready-to-paste snippet, for example:

```
Host clinic-a-gw
    ProxyCommand rtunnel connect clinic-a
Host clinic-a-db1
    ProxyCommand rtunnel connect clinic-a db1.lan:22
```

- Must work on Windows (stdin/stdout piping) as well as Unix.

## 10. Reliability, limits, and security

- QUIC transport config: keep-alive 10 s, max idle timeout 30 s, bounded stream and connection receive windows (defaults 1 MiB and 8 MiB), max concurrent bidirectional streams 64 per agent connection and 16 per client connection. Put every number in a `limits` module as a named, documented constant, overridable via config where sensible.
- Backpressure: copy loops use fixed-size buffers (32 KiB) and never queue unbounded data. One stalled or slow session must not delay others. Prove it with a test.
- Pre-auth hardening: 5 s handshake timeout, per-IP token-bucket rate limiting (stricter on the enrollment ALPN), a cap on concurrent unauthenticated connections, and no work done before the handshake completes.
- The relay never opens outbound connections on behalf of peers (no SSRF surface).
- `#![forbid(unsafe_code)]` in every crate. No secrets, tokens, or payload bytes in logs. Zeroize key material where practical. Validate hostnames (max 253 bytes, no control characters) and all lengths before allocating.
- Run `cargo audit` and `cargo deny` in CI config. Write `docs/SECURITY.md` with the threat model: what a malicious relay, a stolen client key, a stolen agent key, and a network attacker can and cannot do.

## 11. Observability

- `tracing` with structured fields and a `--log-format json` option. Document log levels.
- Append-only JSONL audit log on the relay: `session_open`, `session_close` (client, agent, target, bytes up/down, duration, close reason), `auth_failure`, `enroll`, `grant_change`, `revoke`. Never log payloads.
- Optional: a localhost-only `/metrics` endpoint behind a cargo feature (online agents, active sessions, bytes transferred, handshake failures).

## 12. Code quality rules

These apply to all code, including tests and docs.

- Idiomatic, readable Rust that passes `cargo fmt --check` and `cargo clippy --all-targets -- -D warnings -W clippy::pedantic`. Allow an individual pedantic lint only with a comment explaining why.
- Rustdoc on every public item: full sentences ending in periods, covering purpose, parameters, return value, `# Errors`, `# Panics` where applicable, and concurrency safety (for example, 'Safe for concurrent use by multiple tasks.'). Document every constant and every struct or enum field. Rustdoc requires field docs on the line above the field, so use `///` there.
- Inline comments explain the why of non-trivial logic.
- No `unwrap`, `expect`, `panic!`, or indexing that can panic in non-test code, except to assert a provable invariant, with a comment stating the invariant. Never ignore a `Result`. Use `thiserror` enums in libraries with actionable messages, and `anyhow` context only in binaries.
- No magic numbers: named constants only.
- Prefer clear code over clever code. Prefer message passing and small `Arc`-shared structs over lock-heavy designs. When a lock is needed, never hold it across an `.await`.
- Structure for testability: I/O at the edges, protocol and authorization logic as pure functions or traits that can be tested without sockets.

## 13. Testing requirements

- **Unit tests:** codec round trips, limits, authorization decisions, token lifecycle, backoff schedule, config parsing.
- **Property and fuzz tests:** `proptest` round trips for every frame type. A decoder fed arbitrary bytes must never panic or over-allocate. Provide a `cargo-fuzz` target.
- **Integration tests** (in-process relay, agent, and client on `127.0.0.1:0` with temp dirs and a local TCP echo server):
  - 100 MiB transfer through the tunnel with hash verification.
  - 50 concurrent sessions.
  - Unauthorized client, ungranted agent, and disallowed target are each rejected with the correct error code.
  - Revoking a peer kills its live sessions within 5 s.
  - The agent reconnects automatically after the relay restarts, and a new session works afterward.
  - Half-close semantics are preserved in both directions.
  - A stalled consumer on one session does not stall another.
  - Packet loss and delay: add a small UDP forwarding proxy to the test harness (for example 5% loss, 100 ms delay) and confirm sessions still complete.
- **End-to-end:** `deploy/docker-compose.yml` with a relay, an agent plus a real `sshd`, and a client container, and `scripts/e2e.sh` that runs a real `ssh` session through the tunnel and checks the output.

## 14. Milestones

Complete each milestone fully, run the whole check suite (`fmt`, `clippy`, `test`), commit with a conventional-commit message, then continue. At each milestone, append decisions and assumptions to `DECISIONS.md`.

| #             | Milestone            | Acceptance criteria                                                                                                                                                                                                           |
| ------------- | -------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| M0            | Scaffold             | Workspace builds, lints configured, CI config, `DECISIONS.md`, dependency versions pinned.                                                                                                                                    |
| M1            | `proto` crate        | All frames and error codes implemented, `PROTOCOL.md` written, property tests and fuzz target pass.                                                                                                                           |
| M2            | `identity` crate     | Key generation, cert, fingerprint, and pinning verifiers pass tests, including wrong-fingerprint rejection.                                                                                                                   |
| M3            | Core data path       | Relay with a minimal static peer and grant store behind a trait (replaced in M4), agent, and client. Echo-server integration tests pass (transfer, concurrency, half-close). A manual `ssh` session through the tunnel works. |
| M4            | Enrollment and store | SQLite store, tokens, grants, revocation, and all admin subcommands. Revocation test passes.                                                                                                                                  |
| M5            | Reliability          | Reconnect and backoff, limits, rate limiting, graceful shutdown. Loss/delay tests and the backpressure test pass.                                                                                                             |
| M6            | Observability        | Audit log, JSON logging, optional metrics feature.                                                                                                                                                                            |
| M7            | Packaging and docs   | Systemd units, Dockerfile, compose e2e script green, cross-compile instructions, README with a 10-minute quickstart, `SECURITY.md`, `OPERATIONS.md`.                                                                          |
| M8 (optional) | UDP-blocked fallback | Only after M7 and my approval: TCP+TLS+yamux transport behind the existing transport boundary.                                                                                                                                |

## 15. Working agreements

- Make reasonable decisions and record them in `DECISIONS.md` instead of stopping to ask. Ask me only when blocked, or when a choice would change the security model or the wire protocol.
- Do not add features, flags, or crates beyond this spec without recording the reason.
- When I report a bug later: explain the root cause, then give the minimal fix as a code snippet. Do not generate unrelated new code, do not rename functions, and never add suffixes like `_fixed` or `_updated`. Keep public APIs stable.
- Verify claims by running the code. Do not report a milestone as done without the commands and results that show it.
- Keep each commit focused, and keep the final tree free of dead code, stray TODOs, and commented-out blocks.

## 16. Definition of done

- Milestones M0 to M7 are complete and every acceptance criterion is demonstrated.
- The check suite is green, and `cargo audit` and `cargo deny` report no unresolved issues.
- A new user can follow the README quickstart to stand up a relay, enroll an agent and a client, and `ssh` into a LAN host in about ten minutes.
- The final message summarizes what was built, the exact commands to run it, deviations from this spec, known limitations, and recommended next steps.
