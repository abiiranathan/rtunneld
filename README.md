# rtunnel

`rtunnel` provides secure, zero-trust SSH access to machines located on private LANs without opening inbound firewall ports, configuring public NAT routes, or exposing public IPs.

- **AnyDesk-Style Experience**: Connect using a 9-digit Device ID (`482 913 077`) and an ephemeral 6-digit access code with interactive visual verification (SAS).
- **Dedicated Headless Agent (`rtunnel-agent`)**: Unattended daemon for servers, IoT devices, and bastion hosts with strict destination allowlists (`allowed_targets`).
- **Mutual TLS with Pinned ed25519 Identities**: No Certificate Authorities, passwords, or DNS-name trust.
- **End-to-End Encryption**: The relay only splices raw streams; SSH encryption remains strictly end-to-end between client and server.
- **Strict Default-Deny Authorization**: Explicit operator approval on the host or pre-authorized cryptographic tokens required before any connection is permitted.
- **Cross-Platform Host Support**: Runs as a managed service on Linux (`systemd`), macOS (`launchd`), and Windows (`sc.exe`).
- **Resilient Transport**: Multiplexed QUIC over UDP (`quinn`) with keepalives, dead-peer detection, exponential backoff, and full half-close fidelity.

---

## Architecture

`rtunnel` is a **rendezvous relay**, not a VPN. Both the connecting workstation and the remote host dial **outbound** to the cloud relay over QUIC/UDP. The relay authenticates both peers, checks authorization, and splices their streams together. The host or agent is the only component that dials the private target destination, and SSH encryption remains strictly end-to-end between the client's OpenSSH and the target's sshd.

```mermaid
flowchart LR
    subgraph Client["Connecting Workstation"]
        direction TB
        SSH["OpenSSH client"]
        RC["rtunnel connect 482 913 077"]
        SSH -->|"stdin / stdout"| RC
    end

    subgraph RelayHost["Cloud Relay Host (rtunneld)"]
        direction TB
        Relay["QUIC listener :4433/udp<br/>mTLS + Device ID Routing"]
        DB[("SQLite Store<br/>peers · grants · codes")]
        Relay --- DB
    end

    subgraph PrivateLAN["Target Host LAN"]
        direction TB
        Host["rtunnel host / rtunnel-agent<br/>Device ID / Agent Name"]
        Target["Local sshd :22"]
        Host -->|"TCP localhost:22"| Target
    end

    User(["ssh user@482913077"]) --> SSH
    RC <-->|"QUIC :4433 outbound"| Relay
    Host <-->|"QUIC :4433 outbound"| Relay
    Relay ==>|"splices streams (ciphertext only)"| Host
```

### Pairing and Connection Lifecycle

```mermaid
sequenceDiagram
    autonumber
    participant C as Connecting Client
    participant R as Cloud Relay (rtunneld)
    participant H as Target Host / Agent
    participant S as Local sshd

    Note over H,R: Host dials out, registers Device ID & updates code
    H->>R: ALPN: rtunnel-rendezvous/1, SetPairingCode(hash)
    
    Note over C,R: Client requests pairing with Device ID & Code
    C->>R: PairRequest { target: 482913077, code: 834291 }
    R->>R: Verify code hash & enforce attempt limit
    R->>H: IncomingPairPrompt { SAS, client_id }
    Note over H: Host operator approves (Allow Once / Always)
    H-->>R: PairPromptResponse { approved: true, duration: Always }
    R-->>C: PairResult { success: true }

    Note over C,S: Direct End-to-End SSH
    C->>R: ConnectRequest { target: 482913077 }
    R->>H: OpenTarget { localhost:22 }
    H->>S: TCP connect localhost:22
    Note over R: Splice QUIC streams (ciphertext only)
    C->>S: End-to-end encrypted SSH session (via relay splice)
    S-->>C: End-to-end encrypted SSH session (via relay splice)
```

---

## Workspace Layout

- `crates/proto`: Frame encoding, Postcard serialization, error codes, Device ID formatting, and SAS computation.
- `crates/identity`: ed25519 keys, X.509 SPKI fingerprint extraction, and custom rustls pinning verifiers.
- `crates/install`: Cross-platform background service installation (`systemd`, `launchd`, `sc.exe`) and OpenSSH configuration.
- `crates/transport`: QUIC endpoint builders, 32 KiB copy pumps, rate limiting, and backoff.
- `crates/relay`: `rtunneld` daemon, SQLite store (WAL mode), Device ID allocator, pairing coordinator, and audit log.
- `crates/agent`: `rtunnel-agent` headless daemon, TCP dialer with `TCP_NODELAY`, and target filtering.
- `crates/client`: `rtunnel` unified CLI, interactive host daemon, and OpenSSH `ProxyCommand` bridge.
- `tests`: Multi-peer integration tests covering Device ID pairing, transfer hash integrity, concurrency, half-close, and revocation.

---

## 1. Deploying the Cloud Relay (`rtunneld`)

The rendezvous relay (`rtunneld`) is the single cloud-facing component of the system. It runs on any Linux cloud instance or dedicated server with a publicly accessible IP or domain and an open UDP port (`4433` by default).

### 1.1 Firewall Prerequisites

Ensure UDP port `4433` is open for inbound traffic:

```bash
# UFW (Ubuntu/Debian)
sudo ufw allow 4433/udp
sudo ufw reload

# Firewalld (RHEL/Fedora/CentOS)
sudo firewall-cmd --permanent --add-port=4433/udp
sudo firewall-cmd --reload
```

### 1.2 Installation Options

#### Option A: One-Line Bootstrap Installer (Recommended)
The standalone installation script downloads the verified precompiled static binary (`musl`), initializes state in `/var/lib/rtunnel`, generates the relay's ed25519 identity keypair, writes the hardened `systemd` service unit, and starts the daemon immediately:

```bash
curl -fsSL https://raw.githubusercontent.com/abiiranathan/rtunneld/main/scripts/install.sh \
  | sudo bash -s -- relay --listen 0.0.0.0:4433
```

#### Option B: Direct Binary Self-Install
If you downloaded or built the `rtunneld` binary manually:

```bash
chmod +x rtunneld
sudo ./rtunneld install --listen 0.0.0.0:4433
```

Use `--no-start` to write the unit file without immediately enabling or starting the service.

#### Option C: Docker & Docker Compose
A production-ready `Dockerfile` and `docker-compose.yml` are provided in `deploy/`:

```bash
# 1. Initialize relay state and generate keypair
docker compose -f deploy/docker-compose.yml run --rm relay \
  /usr/local/bin/rtunneld init --state-dir /var/lib/rtunnel

# 2. Start the relay daemon
docker compose -f deploy/docker-compose.yml up -d relay
```

### 1.3 Verifying Relay Health & Audit Log

```bash
# Check systemd status
sudo systemctl status rtunneld.service

# View the real-time append-only security audit log
sudo tail -f /var/lib/rtunnel/audit.log
```

---

## 2. Quick Start: Connecting Machines (Under 3 Minutes)

Connecting two machines interactively takes three quick steps:

### Step 1: Run Setup (Both Machines)

Run setup once on both the host machine and the connecting workstation:

```bash
# Linux / macOS
rtunnel setup --relay-host relay.example.com
```

```powershell
# Windows PowerShell
rtunnel.exe setup --relay-host relay.example.com
```

Setup generates an ed25519 keypair, connects to the relay, and assigns a persistent 9-digit **Device ID** (e.g. `482 913 077`).

---

### Step 2: Start the Host (Remote LAN Machine)

On the machine you want to access:

```bash
rtunnel host
```

It prints your Device ID and a single-use 6-digit access code:

```text
=== rtunnel Host Daemon Running ===
Device ID:   482 913 077
Access Code: 834 291 (valid for 15 minutes)
Ready for inbound connections. Press Ctrl+C to exit.
```

*(To run it continuously in the background across reboots, see [Host Service Installation](#3-host-service-installation).)*

---

### Step 3: Connect (Connecting Workstation)

From your laptop or workstation:

```bash
rtunnel connect 482913077 --code 834291
```

The host prompts the local operator:

```text
--------------------------------------------------
INCOMING PAIRING REQUEST
Connecting Device: nathan-macbook (914 205 183)
Authentication Code (SAS): [4192]
--------------------------------------------------
Authorize this device? [1] Allow Once, [2] Always Allow, [3] Deny: 2
```

Both machines display matching 4-digit SAS codes (`4192`) to verify the relay did not tamper with identities. Once approved:

```bash
ssh user@482913077
```

Subsequent connections to the same host require no access code or pairing prompt.

---

## 3. Host Service Installation

Run `rtunnel host` as a managed background service so it stays online across reboots:

### Linux (`systemd`)
```bash
sudo rtunnel service install
```

### macOS (`launchd`)
```bash
sudo rtunnel service install
```

### Windows (`Windows Service`)
Run PowerShell as Administrator:
```powershell
rtunnel.exe service install
```

### Managing the Service
```bash
rtunnel service start
rtunnel service stop
```

---

## 4. Deploying the Headless Agent (`rtunnel-agent`)

For unattended servers, automated CI/CD runners, bastion hosts, or air-gapped infrastructure where interactive host-side pairing prompts (`rtunnel host`) are impractical, use the dedicated **`rtunnel-agent`** daemon.

The agent runs as a hardened systemd service, dials outbound to the relay over QUIC, and enforces a strict local destination allowlist (`allowed_targets`). It will refuse any connection to destinations not explicitly configured, protecting your internal LAN against SSRF.

### 4.1 Prerequisites: Generate an Agent Token

On the relay host, issue an enrollment URI for the agent:

```bash
sudo rtunneld token create --role agent --name clinic-a \
  --relay-host relay.example.com --relay-port 4433 --ttl 15m
```

This outputs a single-use enrollment URI:
```text
Enrollment URI: rtunnel://relay.example.com:4433/?fp=<relay_fingerprint>&token=<token>
```

*(Alternatively, use `rtunneld pair` to issue agent and client tokens simultaneously; see [Section 5.1](#51-pairing-via-pre-shared-tokens).)*

---

### 4.2 Installation Options

#### Option A: One-Line Bootstrap Installer (Recommended)
Downloads the prebuilt agent binary, installs it to `/usr/local/bin`, writes `/etc/systemd/system/rtunnel-agent.service`, enrolls the agent, and starts the service:

```bash
curl -fsSL https://raw.githubusercontent.com/abiiranathan/rtunneld/main/scripts/install.sh \
  | sudo bash -s -- agent "rtunnel://relay.example.com:4433/?fp=<relay_fp>&token=<token>" \
    --allowed-target 127.0.0.1:22
```

If you have a cloned checkout:
```bash
sudo ./scripts/install-agent.sh "rtunnel://relay.example.com:4433/?fp=<relay_fp>&token=<token>" \
  --allowed-target 127.0.0.1:22
```

#### Option B: Direct Binary Self-Install
If you built or downloaded the `rtunnel-agent` binary manually:

```bash
chmod +x rtunnel-agent
sudo ./rtunnel-agent install "rtunnel://relay.example.com:4433/?fp=<relay_fp>&token=<token>" \
  --allowed-target 127.0.0.1:22
```

#### Option C: Pre-Installation without an Enrollment URI
To pre-bake `rtunnel-agent` into VM images, cloud-init scripts, or golden templates without immediately enrolling or starting the service:

```bash
# 1. Install binary and systemd unit without starting
sudo ./rtunnel-agent install --no-start --allowed-target 127.0.0.1:22

# 2. Later, when an enrollment URI is provided:
sudo rtunnel-agent enroll "rtunnel://relay.example.com:4433/?fp=<relay_fp>&token=<token>" \
  --allowed-target 127.0.0.1:22

# 3. Enable and start the service
sudo systemctl daemon-reload
sudo systemctl enable --now rtunnel-agent.service
```

#### Option D: Docker & Docker Compose
To run `rtunnel-agent` inside a container (e.g. adjacent to containerized services):

```bash
# 1. Enroll the agent inside the container volume
docker compose -f deploy/docker-compose.yml run --rm agent \
  /usr/local/bin/rtunnel-agent enroll "rtunnel://relay.example.com:4433/?fp=<relay_fp>&token=<token>" \
  --allowed-target "sshd-host:22"

# 2. Start the container daemon
docker compose -f deploy/docker-compose.yml up -d agent
```

---

### 4.3 Installation Flags & File Locations

`rtunnel-agent install` accepts the following options:

| Flag               | Default                  | Description                                                                                          |
| ------------------ | ------------------------ | ---------------------------------------------------------------------------------------------------- |
| `[uri]`            | *None*                   | Optional one-time enrollment URI. If supplied, the agent enrolls immediately before service start.   |
| `--allowed-target` | `127.0.0.1:22`           | Permitted `host:port` destination. Can be specified multiple times. The first target is the default. |
| `--bin-dir`        | `/usr/local/bin`         | Destination directory for the `rtunnel-agent` executable.                                            |
| `--state-dir`      | `/var/lib/rtunnel-agent` | Directory storing `identity.key`, `identity.crt`, and `config.toml`.                                 |
| `--no-start`       | `false`                  | Writes unit and copies binary without enabling or starting the systemd service.                      |

**Standard File Layout:**
- Binary: `/usr/local/bin/rtunnel-agent`
- Unit File: `/etc/systemd/system/rtunnel-agent.service`
- Configuration: `/var/lib/rtunnel-agent/config.toml`
- Identity Key & Cert: `/var/lib/rtunnel-agent/identity.key` (mode `0600`), `/var/lib/rtunnel-agent/identity.crt`

---

### 4.4 Managing Allowed Targets (`targets`)

The agent enforces an exact-match allowlist for targets it will dial. You can view or update these targets at any time without re-enrolling the agent:

```bash
# List currently configured targets (first is the default)
sudo rtunnel-agent targets list

# Append an additional target (e.g. a database or internal host)
sudo rtunnel-agent targets add 192.168.1.50:22

# Remove a target from the allowlist
sudo rtunnel-agent targets remove 127.0.0.1:22

# Replace the entire allowlist at once
sudo rtunnel-agent targets set 127.0.0.1:22 192.168.1.100:80 10.0.0.5:5432

# Apply changes by restarting the service
sudo systemctl restart rtunnel-agent.service
```

When connected to a modern relay, the agent automatically advertises its allowed targets upon reconnection so clients can discover them via `rtunnel agents` and `rtunnel ssh-config --all --write`.

---

### 4.5 Service Verification & Health Checks

Verify that the agent service is active and connected to the relay:

```bash
# Check service status
sudo systemctl status rtunnel-agent.service

# Inspect live logs (connection status, control session, session opens)
sudo journalctl -u rtunnel-agent.service -f
```

---

### 4.6 Standalone / Foreground Execution

For troubleshooting, network testing, or container entrypoints, run the agent in the foreground:

```bash
# 1. Enroll state directory
rtunnel-agent --state-dir /var/lib/rtunnel-agent enroll \
  "rtunnel://relay.example.com:4433/?fp=<relay_fp>&token=<token>" \
  --allowed-target 127.0.0.1:22

# 2. Run the connector loop
rtunnel-agent --state-dir /var/lib/rtunnel-agent run
```

---

## 5. Headless Client Setup & Administration

### 5.1 Pairing via Pre-Shared Tokens

To enroll both a headless agent and a client workstation in a single administrative step:

```bash
# On the relay host:
sudo rtunneld pair --agent clinic-a --client laptop \
  --relay-host relay.example.com --relay-port 4433
```

This atomically creates both single-use enrollment tokens and records the client-to-agent access grant in SQLite:
```text
Agent enrollment URI:  rtunnel://relay.example.com:4433/?fp=...&token=<agent_token>
Client enrollment URI: rtunnel://relay.example.com:4433/?fp=...&token=<client_token>
Granted 'laptop' access to 'clinic-a'.
```

Then install each component:

```bash
# 1. On the agent host:
sudo rtunnel-agent install "rtunnel://relay.example.com:4433/?fp=...&token=<agent_token>" \
  --allowed-target 127.0.0.1:22

# 2. On the client workstation:
rtunnel install "rtunnel://relay.example.com:4433/?fp=...&token=<client_token>"
```

---

### 5.2 Client Workstation Installation (`rtunnel install`)

`rtunnel install` installs the binary, sets up `~/.ssh/config` snippet loading, enrolls using the URI, and automatically generates OpenSSH host aliases for every granted agent:

```bash
# Unix (Linux / macOS)
rtunnel install "rtunnel://relay.example.com:4433/?fp=...&token=<client_token>"

# Windows (PowerShell)
.\scripts\install-client.ps1 "rtunnel://relay.example.com:4433/?fp=...&token=<client_token>"
```

Once installed, connect via standard OpenSSH:
```bash
ssh user@clinic-a
```

To regenerate OpenSSH config blocks for newly granted or advertised agent targets:
```bash
rtunnel ssh-config --all --write
```

---

### 5.3 Manual Token & Grant Commands

If managing tokens and permissions individually:

```bash
# Create individual single-use tokens
sudo rtunneld token create --role agent --name clinic-a --ttl 15m --relay-host relay.example.com
sudo rtunneld token create --role client --name laptop --ttl 15m --relay-host relay.example.com

# Authorize or revoke client-to-agent access grants
sudo rtunneld grant add laptop clinic-a
sudo rtunneld grant remove laptop clinic-a
sudo rtunneld grant list

# List registered peers or immediately revoke an identity
sudo rtunneld peers list
sudo rtunneld revoke clinic-a
```

When a peer is revoked, all active tunnel sessions terminate within 5 seconds and future handshakes are rejected.

---

## 6. Security & Threat Model

1. **Short Authentication String (SAS)**: Prevents relay MITM attacks. Even if an untrusted or compromised relay operator substitutes public keys, the 4-digit verification code will mismatch.
2. **Brute-Force & Enumeration Resistance**: Ephemeral access codes are rate-limited with progressive lockout after 5 incorrect attempts, and codes expire after 15 minutes.
3. **Zero Plaintext Exposure**: The relay only copies ciphertext frames; SSH keys, passwords, and sessions remain strictly end-to-end encrypted.
4. **Default-Deny**: A Device ID alone never grants access. First contact requires an explicit operator approval and an active access code.
5. **SSRF Defense-in-Depth**: `rtunnel-agent` restricts connections strictly to its local `allowed_targets` allowlist. Even a compromised relay cannot coerce the agent to dial arbitrary internal IPs.
6. **Strict File Permissions**: Identity private keys are stored with `0600` modes on Unix, and daemons refuse to run if key files are group- or world-readable.

---

## 7. Testing & Quality Assurance

Run the complete test suite:

```bash
# Check formatting
cargo fmt --check

# Strict pedantic lint checks
cargo clippy --workspace --all-targets -- -D warnings -W clippy::pedantic

# Cross-crate integration tests (Device ID pairing, SAS verification, transfer integrity, half-close, revocation)
cargo test --workspace --all-targets
```
