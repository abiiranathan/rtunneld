# rtunnel

`rtunnel` provides secure, zero-trust SSH access to servers located on private LANs without opening inbound firewall ports, configuring public NAT routes, or exposing public IPs.

- **Mutual TLS with Pinned ed25519 Identities**: No Certificate Authorities, passwords, or DNS-name trust.
- **End-to-End Encryption**: The relay only splices raw streams; SSH encryption remains strictly end-to-end between client and server.
- **Strict Default-Deny Authorization**: Client-to-agent access grants on the relay, combined with exact-match target whitelisting on the agent.
- **Resilient Transport**: Multiplexed QUIC over UDP (`quinn`) with keepalives, dead-peer detection, exponential backoff, and full half-close fidelity.

---

## Workspace Layout

- `crates/proto`: Frame encoding, Postcard serialization, error codes, and bounds checking.
- `crates/identity`: ed25519 keys, X.509 SPKI fingerprint extraction, and custom rustls pinning verifiers.
- `crates/install`: self-installation helpers and systemd unit rendering shared by the binaries.
- `crates/transport`: QUIC endpoint builders, 32 KiB copy pumps, rate limiting, and backoff.
- `crates/relay`: `rtunneld` daemon, SQLite store (WAL mode), access grants, revocation watcher, and audit log.
- `crates/agent`: `rtunnel-agent` daemon, TCP dialer with `TCP_NODELAY`, and target filtering.
- `crates/client`: `rtunnel` CLI and OpenSSH `ProxyCommand` bridge (clean stdout piping).
- `tests`: Multi-peer integration tests covering transfer hash integrity, concurrency, half-close, and revocation.

---

## Quick Install (Prebuilt Binaries)

Targets need neither a source checkout nor a Rust toolchain. The bootstrapper downloads the requested release, verifies its SHA-256 checksum when available, and runs the binary's built-in `install` command. The hardened systemd units are embedded in the binaries, so nothing from `deploy/` has to be copied to a target. The relay and agent are Linux-only; the client is also available for Windows (see [Windows Client](#windows-client)).

### 1. Relay (public host)

```bash
curl -fsSL https://raw.githubusercontent.com/abiiranathan/rtunneld/main/scripts/install.sh \
  | sudo bash -s -- relay --listen 0.0.0.0:4433
```

The relay is initialized if needed, installed to `/usr/local/bin/rtunneld`, and enabled as `rtunneld.service`. The command prints the relay fingerprint and the exact token commands to run next.

### 2. Issue Tokens and Grants (relay host)

```bash
# Create an agent token
sudo rtunneld token create --role agent --name clinic-a --ttl 15m \
  --relay-host relay.example.com --relay-port 4433

# Create a client token
sudo rtunneld token create --role client --name laptop --ttl 15m \
  --relay-host relay.example.com --relay-port 4433

# Authorize laptop to connect to clinic-a
sudo rtunneld grant add laptop clinic-a
```

### 3. Agent (LAN host)

Use the enrollment URI printed by `token create`:

```bash
curl -fsSL https://raw.githubusercontent.com/abiiranathan/rtunneld/main/scripts/install.sh \
  | sudo bash -s -- agent "rtunnel://relay.example.com:4433/?fp=<relay_fp>&token=<agent_token>" \
      --allowed-target 127.0.0.1:22
```

The agent is installed to `/usr/local/bin/rtunnel-agent`, enrolled, and enabled as `rtunnel-agent.service`.

### 4. Client (dev machine)

```bash
curl -fsSL https://raw.githubusercontent.com/abiiranathan/rtunneld/main/scripts/install.sh \
  | bash -s -- client "rtunnel://relay.example.com:4433/?fp=<relay_fp>&token=<client_token>"
```

The client installer:

- installs `rtunnel` to `~/.local/bin` (or `/usr/local/bin` when run as root),
- creates `~/.ssh/rtunnel.d` and ensures `~/.ssh/config` contains `Include ~/.ssh/rtunnel.d/*`,
- enrolls the client when a URI is supplied.

Generate the SSH host entry and connect:

```bash
rtunnel ssh-config clinic-a --write
ssh user@clinic-a
```

`rtunnel ssh-config clinic-a` prints the same snippet if you prefer to place it manually.

### Windows Client

The relay and agent are Linux-only. The client runs on Windows 10/11 with the
bundled Windows OpenSSH client. Run PowerShell as your normal user (no
administrator prompt is needed):

```powershell
# Download and run the installer. Pass the enrollment URI printed by
# `rtunneld token create --role client`.
$installer = Join-Path $env:TEMP "install-rtunnel.ps1"
Invoke-WebRequest -UseBasicParsing `
  https://raw.githubusercontent.com/abiiranathan/rtunneld/main/scripts/install.ps1 `
  -OutFile $installer
powershell -ExecutionPolicy Bypass -File $installer `
  "rtunnel://relay.example.com:4433/?fp=<relay_fp>&token=<client_token>"
```

The Windows installer:

- installs `rtunnel.exe` to `%LOCALAPPDATA%\Programs\rtunnel`,
- adds that directory to your user `PATH` (use `-NoPath` to skip),
- adds an absolute `Include` for `%USERPROFILE%\.ssh\rtunnel.d\*` to
  `%USERPROFILE%\.ssh\config` (use `-NoSshConfig` to skip),
- verifies the release SHA-256 checksum when `SHA256SUMS` is available,
- enrolls the client when a URI is supplied.

Open a new terminal after installation so the updated `PATH` takes effect, then
generate the SSH host entry and connect:

```powershell
rtunnel ssh-config clinic-a --write
ssh user@clinic-a
```

Use `-Version v0.2.0` to pin a release, `-BinaryPath .\rtunnel.exe` to install a
binary you already built, and `-DownloadBase <url>` to use a mirror. The
environment variables used by `install.sh` (`RTUNNEL_VERSION`, `RTUNNEL_REPO`,
`RTUNNEL_TARGET`, `RTUNNEL_BIN`, `RTUNNEL_BIN_DIR`, `RTUNNEL_DOWNLOAD_BASE`) are
also honored.

### Pinning a Version or Using a Local Binary

The bootstrapper uses GitHub releases. Override the release or target when needed:

```bash
# Install a specific release
sudo RTUNNEL_VERSION=v0.2.0 bash -s -- relay < scripts/install.sh

# Install a binary you already built or downloaded
sudo RTUNNEL_BIN=/path/to/rtunneld ./scripts/install-relay.sh

# Force a different release asset
sudo RTUNNEL_TARGET=aarch64-unknown-linux-musl bash -s -- relay < scripts/install.sh
```

Checkout users can also edit [`scripts/install.conf`](scripts/install.conf). The scripts load it automatically and every value can still be overridden from the environment.

### Direct Binary Usage

Each binary can install itself without any script:

```bash
sudo ./rtunneld install --listen 0.0.0.0:4433
sudo ./rtunnel-agent install "rtunnel://relay.example.com:4433/?fp=<relay_fp>&token=<agent_token>" \
  --allowed-target 127.0.0.1:22
./rtunnel install "rtunnel://relay.example.com:4433/?fp=<relay_fp>&token=<client_token>"
```

On Windows, run the client installer directly:

```powershell
.\rtunnel.exe install "rtunnel://relay.example.com:4433/?fp=<relay_fp>&token=<client_token>"
```

Use `--no-start` to write the unit without enabling or starting it. Use `--bin-dir` to install the executable somewhere other than the default. Use `--no-path` (client, Windows) to leave the user `PATH` untouched.

---

## Deployment with Docker & Docker Compose

A production-ready `Dockerfile` and `docker-compose.yml` are provided in `deploy/`.

### 1. Build the Docker Image

```bash
docker compose -f deploy/docker-compose.yml build
```

### 2. Initialize Relay State & Generate Identity

```bash
docker compose -f deploy/docker-compose.yml run --rm relay \
  /usr/local/bin/rtunneld init --state-dir /var/lib/rtunnel
```

### 3. Start the Relay Daemon

```bash
docker compose -f deploy/docker-compose.yml up -d relay
```

The relay is now listening on UDP port `4433`.

### 4. Create Single-Use Enrollment Tokens

```bash
# Generate agent token
docker compose -f deploy/docker-compose.yml exec relay \
  /usr/local/bin/rtunneld token create \
    --role agent \
    --name clinic-a \
    --ttl 15m \
    --relay-host relay.example.com \
    --relay-port 4433

# Generate client token
docker compose -f deploy/docker-compose.yml exec relay \
  /usr/local/bin/rtunneld token create \
    --role client \
    --name laptop \
    --ttl 15m \
    --relay-host relay.example.com \
    --relay-port 4433

# Grant client permission to connect to agent
docker compose -f deploy/docker-compose.yml exec relay \
  /usr/local/bin/rtunneld grant add laptop clinic-a
```

### 5. Enroll and Run the Agent via Docker

```bash
# 1. Enroll the agent container
docker compose -f deploy/docker-compose.yml run --rm agent \
  /usr/local/bin/rtunnel-agent enroll "rtunnel://relay.example.com:4433/?fp=<relay_fp>&token=<agent_token>" \
    --allowed-target "sshd-host:22"

# 2. Start the agent daemon
docker compose -f deploy/docker-compose.yml up -d agent
```

---

## Native Install from a Checkout

If you are building locally, the install scripts use `target/release` when it exists:

```bash
cargo build --release --workspace

sudo ./scripts/install-relay.sh --listen 0.0.0.0:4433
sudo ./scripts/install-agent.sh "rtunnel://relay.example.com:4433/?fp=<relay_fp>&token=<agent_token>" \
  --allowed-target 127.0.0.1:22
./scripts/install-client.sh "rtunnel://relay.example.com:4433/?fp=<relay_fp>&token=<client_token>"
```

If no local release binary is present, the scripts download the matching prebuilt release instead of building on the target.

---

## Admin Commands (`rtunneld`)

```bash
# List all active peers
rtunneld peers list

# List authorized access grants
rtunneld grant list

# Revoke a peer (terminates active sessions within 5 seconds)
rtunneld revoke clinic-a

# List active enrollment tokens
rtunneld token list
```

---

## Testing & Quality Assurance

Run the test suite:

```bash
# Formatting
cargo fmt --check

# Strict pedantic lint checks
cargo clippy --workspace --all-targets -- -D warnings -W clippy::pedantic

# Cross-crate integration tests (concurrency, data transfer, half-close, revocation)
cargo test --workspace --all-targets
```
