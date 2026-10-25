#!/usr/bin/env bash
# scripts/install-client.sh: Install rtunnel client CLI and configure user environment.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Determine installation prefix: system-wide if root, user-local if non-root
if [[ $EUID -eq 0 ]]; then
    BIN_DEST="/usr/local/bin/rtunnel"
    SUDO=""
else
    # Check if user has sudo or prefers ~/.local/bin
    if command -v sudo >/dev/null 2>&1; then
        BIN_DEST="/usr/local/bin/rtunnel"
        SUDO="sudo"
    else
        BIN_DEST="$HOME/.local/bin/rtunnel"
        mkdir -p "$HOME/.local/bin"
        SUDO=""
    fi
fi

echo "=== Installing rtunnel Client CLI ==="

# 1. Locate or build the binary
if [[ -f "$REPO_DIR/target/release/rtunnel" ]]; then
    echo "Using compiled binary from target/release/rtunnel..."
    $SUDO install -m 0755 "$REPO_DIR/target/release/rtunnel" "$BIN_DEST"
elif command -v cargo >/dev/null 2>&1; then
    echo "Building rtunnel client in release mode..."
    (cd "$REPO_DIR" && cargo build --release -p rtunnel-client)
    $SUDO install -m 0755 "$REPO_DIR/target/release/rtunnel" "$BIN_DEST"
elif [[ -f "$BIN_DEST" ]]; then
    echo "rtunnel binary already installed at $BIN_DEST."
else
    echo "ERROR: rtunnel binary not found and cargo is not installed." >&2
    exit 1
fi

# 2. Set up user state directory
USER_HOME="${HOME:-$(getent passwd "$USER" | cut -d: -f6)}"
CONFIG_DIR="$USER_HOME/.config/rtunnel"
mkdir -p "$CONFIG_DIR"
chmod 0700 "$CONFIG_DIR"

# 3. Configure OpenSSH environment
SSH_DIR="$USER_HOME/.ssh"
SSH_CONFIG="$SSH_DIR/config"
RTUNNEL_SSH_DIR="$SSH_DIR/rtunnel.d"

mkdir -p "$SSH_DIR" "$RTUNNEL_SSH_DIR"
chmod 0700 "$SSH_DIR" "$RTUNNEL_SSH_DIR"
touch "$SSH_CONFIG"
chmod 0600 "$SSH_CONFIG"

# Ensure ~/.ssh/config includes the rtunnel snippet directory
INCLUDE_DIRECTIVE="Include ~/.ssh/rtunnel.d/*"
if ! grep -Fxq "$INCLUDE_DIRECTIVE" "$SSH_CONFIG"; then
    echo "Adding '$INCLUDE_DIRECTIVE' to $SSH_CONFIG..."
    # Prepend Include to the top of ~/.ssh/config
    TEMP_CONF=$(mktemp)
    echo -e "$INCLUDE_DIRECTIVE\n\n$(cat "$SSH_CONFIG")" > "$TEMP_CONF"
    mv "$TEMP_CONF" "$SSH_CONFIG"
    chmod 0600 "$SSH_CONFIG"
fi

echo ""
echo "=========================================================="
echo " SUCCESS: rtunnel client installed to $BIN_DEST"
echo "=========================================================="
echo ""
echo "Quickstart next steps:"
echo "1. Enroll your client:"
echo "   rtunnel enroll \"rtunnel://<relay-host>:4433/?fp=<relay-fp>&token=<token>\""
echo ""
echo "2. Add an SSH alias for an agent (e.g. 'lan-box'):"
echo "   rtunnel ssh-config lan-box > ~/.ssh/rtunnel.d/lan-box.conf"
echo ""
echo "3. Connect directly via standard OpenSSH:"
echo "   ssh user@lan-box"
echo ""
