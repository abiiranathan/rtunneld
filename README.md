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
- `crates/transport`: QUIC endpoint builders, 32 KiB copy pumps, rate limiting, and backoff.
- `crates/relay`: `rtunneld` daemon, SQLite store (WAL mode), access grants, revocation watcher, and audit log.
- `crates/agent`: `rtunnel-agent` daemon, TCP dialer with `TCP_NODELAY`, and target filtering.
- `crates/client`: `rtunnel` CLI and OpenSSH `ProxyCommand` bridge (clean stdout piping).
- `tests`: Multi-peer integration tests covering transfer hash integrity, concurrency, half-close, and revocation.

---

## Deployment with Docker & Docker Compose

A production-ready `Dockerfile` and `docker-compose.yml` are provided in `deploy/`.

### 1. Build the Docker Image
```bash
docker compose -f deploy/docker-compose.yml build
```

### 2. Initialize Relay State & Generate Identity
Initialize the persistent volume and generate the relay's ed25519 identity keys:
```bash
docker compose -f deploy/docker-compose.yml run --rm relay \
  /usr/local/bin/rtunneld init --state-dir /var/lib/rtunnel
```

### 3. Start the Relay Daemon
Run the relay in the background:
```bash
docker compose -f deploy/docker-compose.yml up -d relay
```
The relay is now listening on UDP port `4433`.

### 4. Create Single-Use Enrollment Tokens
Generate one-time tokens for an agent and client (replace `relay.example.com` with your relay's public IP or hostname):
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
On your target LAN server, run the agent using the enrollment URI from step 4:
```bash
# 1. Enroll the agent container
docker compose -f deploy/docker-compose.yml run --rm agent \
  /usr/local/bin/rtunnel-agent enroll "rtunnel://relay.example.com:4433/?fp=<relay_fp>&token=<agent_token>" \
    --allowed-target "sshd-host:22"

# 2. Start the agent daemon
docker compose -f deploy/docker-compose.yml up -d agent
```

---

## Native Quickstart (Without Docker)

### 1. Initialize and Start the Relay (Cloud Host)
```bash
sudo ./scripts/install-relay.sh
```
Or manually:
```bash
rtunneld init --state-dir /var/lib/rtunnel
rtunneld serve --state-dir /var/lib/rtunnel --listen 0.0.0.0:4433
```

### 2. Issue Tokens & Grants (Relay)
```bash
# Create agent token
rtunneld token create --role agent --name clinic-a --ttl 15m --relay-host relay.example.com

# Create client token
rtunneld token create --role client --name laptop --ttl 15m --relay-host relay.example.com

# Authorize laptop to connect to clinic-a
rtunneld grant add laptop clinic-a
```

### 3. Enroll and Run the Agent (LAN Server)
```bash
rtunnel-agent enroll "rtunnel://relay.example.com:4433/?fp=<relay_fp>&token=<agent_token>" \
  --allowed-target 127.0.0.1:22

rtunnel-agent run
```

### 4. Enroll Client and Connect (Dev Machine)
```bash
# Install the client CLI
./scripts/install-client.sh

# Enroll with your client token
rtunnel enroll "rtunnel://relay.example.com:4433/?fp=<relay_fp>&token=<client_token>"

# Generate OpenSSH config snippet
rtunnel ssh-config clinic-a
```

Add the generated snippet to your `~/.ssh/config`:
```sshconfig
Host clinic-a
    ProxyCommand rtunnel connect clinic-a
```

Now connect through standard OpenSSH:
```bash
ssh user@clinic-a
```

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
