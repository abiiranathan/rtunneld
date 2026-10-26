#!/usr/bin/env bash
# scripts/install-client.sh: Install the rtunnel CLI and configure OpenSSH.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$SCRIPT_DIR/install.sh" client "$@"
