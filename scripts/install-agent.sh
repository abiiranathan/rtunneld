#!/usr/bin/env bash
# scripts/install-agent.sh: Install and start the rtunnel agent.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$SCRIPT_DIR/install.sh" agent "$@"
