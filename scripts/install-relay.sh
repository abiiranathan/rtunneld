#!/usr/bin/env bash
# scripts/install-relay.sh: Install and start the rtunnel relay.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$SCRIPT_DIR/install.sh" relay "$@"
