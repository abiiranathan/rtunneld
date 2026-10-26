# Decisions and Assumptions Log

## 2026-10-26 — Self-Contained Installation
- **Embedded Units**: `rtunneld` and `rtunnel-agent` embed their hardened systemd units at build time and expose an `install` subcommand. A downloaded binary can copy itself, initialize or enroll, render the unit, and enable the service without a source checkout or a copy of `deploy/`.
- **Custom State Paths**: Units keep `StateDirectory=` when the state directory is a direct child of `/var/lib`; otherwise the installer removes it and injects `ReadWritePaths=` so `ProtectSystem=strict` continues to work.
- **Bootstrap Scripts**: The scripts no longer build or copy the source tree on the target. They resolve a local release binary or download a checksum-verified release tarball, then delegate to the binary's `install` command. `scripts/install.conf` supplies overridable repo/version/path defaults.
- **Client Onboarding**: `rtunnel install` copies the CLI to `~/.local/bin` (or `/usr/local/bin` for root), configures the OpenSSH include, and can enroll directly. `rtunnel ssh-config --write` writes the host snippet into `~/.ssh/rtunnel.d/`.
- **Release Assets**: A tag-driven workflow publishes static musl tarballs for `x86_64` and `aarch64`, plus a `SHA256SUMS` file consumed by the bootstrapper.

## 2026-10-25 — Complete Implementation Architecture
- **SPKI Fingerprints**: Fingerprints are derived by parsing ASN.1 DER to isolate the SubjectPublicKeyInfo sequence, matching both certificate DER structures and raw ed25519 public key encodings.
- **Stream Splicing**: Splicing utilizes 32 KiB buffers with zero-copy stream pumps. QUIC FIN events propagate directly to TCP write shutdowns, ensuring full half-close fidelity for SSH.
- **Client Stdout Preservation**: `rtunnel connect` emits only tunnel bytes to stdout; all diagnostic logs, connection banners, and errors are routed to stderr to maintain seamless OpenSSH `ProxyCommand` compatibility.
- **Token Hashing**: Enrollment tokens are stored as SHA-256 hashes and consumed within atomic SQLite transactions to eliminate replay vulnerabilities.
- **Supervision & Revocation**: The relay scans the SQLite store on a 1-second cadence, evicting connections and active streams belonging to revoked peers within 5 seconds.