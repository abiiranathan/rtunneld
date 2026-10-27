# Decisions and Assumptions Log

## 2026-10-27 — Release Version Derived From the Git Tag
- **Problem**: `git semver` only creates and pushes tags; it does not edit `Cargo.toml`. The `v0.6.0` release therefore shipped new code that still reported `0.4.0` from `CARGO_PKG_VERSION`, making a successful upgrade look like a failed one.
- **Single Workspace Version**: All crates now use `version.workspace = true`, with the value in `[workspace.package]`.
- **Build-Time Resolution**: A shared `build-support/version.rs` included by the relay, client, and agent build scripts sets `RTUNNEL_VERSION`. It resolves in order: `RTUNNEL_BUILD_VERSION`, the GitHub tag ref (`GITHUB_REF_TYPE=tag`), the exact local git tag, then `CARGO_PKG_VERSION` for source archives without git metadata. The `v` prefix is stripped and only semantic versions are accepted.
- **Consumers**: Clap's `version` and the `AgentHello.agent_version` field use `RTUNNEL_VERSION`, so `--version` and relay-side agent listings always agree with the release asset.

## 2026-10-26 — Agent Target Discovery and One-Step Onboarding
- **Separate Advertisement Stream**: Agents send `AgentTargets` on a dedicated bidirectional stream after `HelloAck` instead of extending `AgentHello`. Postcard is not self-describing, so appending a field to an enum variant would break old readers. An unaccepted stream is harmless to revision 1 relays, which makes rolling upgrades safe in both directions.
- **Parallel Query Message**: Target-aware clients use `ListAgentsDetailed`/`AgentsDetailedResponse`. If a revision 1 relay rejects the unknown frame, the client falls back to `ListAgents` and reports empty targets. `AgentInfo` and `ListAgentsResponse` are untouched so old clients still decode new relay responses.
- **Persisted Targets**: The relay stores the last advertised list in an `agent_targets` table. `rtunnel agents` can therefore show targets for an offline agent, and `rtunnel ssh-config --all --write` works before the agent reconnects.
- **Generated Host Names**: The target-less `Host <agent>` entry uses the agent's default (first) target. Additional targets get deterministic aliases derived from `host` and, for non-standard ports, `host-port`. Aliases never shadow the agent name; collisions are prefixed with the agent name and numbered.
- **Automatic Onboarding**: `rtunnel install <uri>` enrolls and immediately writes host entries for every granted agent. `--no-ssh-hosts` opts out. The same work is available on demand through `rtunnel ssh-config --all --write`.
- **Pairing Command**: `rtunneld pair --agent <name> --client <name> --relay-host <host>` issues both tokens and the grant atomically, replacing the three manual admin commands. `token create` now requires an explicit `--relay-host` because defaulting to `127.0.0.1` produced unusable enrollment URIs on remote agents.
- **Runtime Allowlist Management**: `rtunnel-agent targets list|add|remove|set` edits the existing config without re-enrollment. The first entry remains the default target; the command prints the restart step.

## 2026-10-26 — Native Windows Client
- **Scope**: Windows support covers the `rtunnel` client only. The relay and agent remain Linux-only because their installation and supervision model is systemd-based.
- **Platform Naming and Paths**: `rtunnel_install::executable_name` appends `.exe` on Windows, and the client installs to `%LOCALAPPDATA%\Programs\rtunnel` instead of `~/.local/bin`.
- **User PATH**: On Windows, `rtunnel install` appends the install directory to `HKCU\Environment\Path` through `winreg`, preserving the existing value type and skipping duplicates case-insensitively. The PowerShell bootstrapper broadcasts `WM_SETTINGCHANGE` so new terminals inherit the update. `--no-path` opts out.
- **OpenSSH Include**: Windows OpenSSH does not reliably expand `~`, so the generated include line is absolute (`Include "C:/Users/.../.ssh/rtunnel.d/*"`). Unix keeps the portable `~/.ssh/rtunnel.d/*` form.
- **Release Asset**: The tag workflow publishes `rtunnel-x86_64-pc-windows-msvc.zip` and `rtunnel-aarch64-pc-windows-msvc.zip`, each containing `rtunnel.exe`, with `.sha256` entries included in `SHA256SUMS`. `scripts/install.ps1` mirrors `install.sh` and uses `-BinaryPath`/`RTUNNEL_BIN` for offline installs.
- **CI**: A `windows-latest` job runs formatting, PowerShell parser checks, clippy, and the full workspace test suite.

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