#!/usr/bin/env bash
# scripts/install-relay.sh: Install and configure rtunneld as a systemd service.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Ensure root privileges
if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must be run as root (use sudo)." >&2
    exit 1
fi

BIN_DEST="/usr/local/bin/rtunneld"
STATE_DIR="/var/lib/rtunnel"
SERVICE_SRC="$REPO_DIR/deploy/systemd/rtunneld.service"
SERVICE_DEST="/etc/systemd/system/rtunneld.service"
LISTEN_ADDR="${RTUNNEL_LISTEN_ADDR:-0.0.0.0:4433}"

echo "=== Installing rtunnel Relay Service ==="

# 1. Locate or build the binary
if [[ -f "$REPO_DIR/target/release/rtunneld" ]]; then
    echo "Using compiled binary from target/release/rtunneld..."
    install -m 0755 "$REPO_DIR/target/release/rtunneld" "$BIN_DEST"
elif command -v cargo >/dev/null 2>&1; then
    echo "Building rtunneld in release mode..."
    (cd "$REPO_DIR" && cargo build --release -p rtunnel-relay)
    install -m 0755 "$REPO_DIR/target/release/rtunneld" "$BIN_DEST"
elif [[ -f "/usr/local/bin/rtunneld" ]]; then
    echo "rtunneld binary already installed at $BIN_DEST."
else
    echo "ERROR: rtunneld binary not found and cargo is not installed." >&2
    exit 1
fi

# 2. Prepare the state directory
echo "Configuring state directory at $STATE_DIR..."
mkdir -p "$STATE_DIR"
chmod 0700 "$STATE_DIR"

# 3. Initialize relay keys and SQLite database if not already done
if [[ ! -f "$STATE_DIR/identity.key" ]]; then
    echo "Initializing relay state and generating ed25519 identity..."
    "$BIN_DEST" init --state-dir "$STATE_DIR"
else
    echo "Existing relay identity found in $STATE_DIR. Preserving keys."
fi

# 4. Install systemd unit file
echo "Installing systemd unit to $SERVICE_DEST..."
if [[ -f "$SERVICE_SRC" ]]; then
    cp "$SERVICE_SRC" "$SERVICE_DEST"
else
    # Fallback inline generation if running standalone
    cat <<EOF > "$SERVICE_DEST"
[Unit]
Description=rtunnel relay daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$BIN_DEST serve --state-dir $STATE_DIR --listen $LISTEN_ADDR
StateDirectory=rtunnel
RuntimeDirectory=rtunnel
UMask=0077
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
fi

chmod 0644 "$SERVICE_DEST"

# 5. Enable and start the service
echo "Reloading systemd, enabling and starting rtunneld..."
systemctl daemon-reload
systemctl enable rtunneld.service
systemctl restart rtunneld.service

# 6. Verify service status
sleep 1
if systemctl is-active --quiet rtunneld.service; then
    echo ""
    echo "=========================================================="
    echo " SUCCESS: rtunneld is active and enabled to start at boot!"
    echo "=========================================================="
    systemctl status rtunneld.service --no-pager -n 5
    echo ""
    echo "Relay details:"
    "$BIN_DEST" peers list --state-dir "$STATE_DIR" || true
else
    echo "ERROR: rtunneld failed to start. Check logs with: journalctl -u rtunneld -e" >&2
    exit 1
fi
