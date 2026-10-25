#!/usr/bin/env bash
# scripts/install-agent.sh: Install and configure rtunnel-agent as a systemd service.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must be run as root (use sudo)." >&2
    exit 1
fi

BIN_DEST="/usr/local/bin/rtunnel-agent"
STATE_DIR="/var/lib/rtunnel-agent"
SERVICE_SRC="$REPO_DIR/deploy/systemd/rtunnel-agent.service"
SERVICE_DEST="/etc/systemd/system/rtunnel-agent.service"

echo "=== Installing rtunnel Agent Service ==="

# 1. Locate or build binary
if [[ -f "$REPO_DIR/target/release/rtunnel-agent" ]]; then
    install -m 0755 "$REPO_DIR/target/release/rtunnel-agent" "$BIN_DEST"
elif command -v cargo >/dev/null 2>&1; then
    (cd "$REPO_DIR" && cargo build --release -p rtunnel-agent)
    install -m 0755 "$REPO_DIR/target/release/rtunnel-agent" "$BIN_DEST"
fi

# 2. State directory
mkdir -p "$STATE_DIR"
chmod 0700 "$STATE_DIR"

# 3. Check for enrollment token parameter
if [[ $# -ge 1 && "$1" =~ ^rtunnel:// ]]; then
    ENROLL_URI="$1"
    echo "Enrolling agent with URI: $ENROLL_URI..."
    "$BIN_DEST" --state-dir "$STATE_DIR" enroll "$ENROLL_URI"
fi

if [[ ! -f "$STATE_DIR/config.toml" ]]; then
    echo "WARNING: Agent is not enrolled yet."
    echo "Run: sudo rtunnel-agent --state-dir $STATE_DIR enroll \"rtunnel://...\""
fi

# 4. Install systemd unit
if [[ -f "$SERVICE_SRC" ]]; then
    cp "$SERVICE_SRC" "$SERVICE_DEST"
fi
chmod 0644 "$SERVICE_DEST"

systemctl daemon-reload
systemctl enable rtunnel-agent.service

if [[ -f "$STATE_DIR/config.toml" ]]; then
    systemctl restart rtunnel-agent.service
    echo "rtunnel-agent service started and enabled at boot."
fi
