#!/usr/bin/env bash
# rtunnel bootstrap installer.
#
# This script is intentionally standalone: it downloads the requested prebuilt
# release, verifies its checksum when possible, and hands control to the
# binary's own `install` subcommand. Targets therefore need neither a source
# checkout nor a Rust toolchain.
set -euo pipefail

SCRIPT_PATH="${BASH_SOURCE[0]:-}"
SCRIPT_DIR=""
if [[ -n "$SCRIPT_PATH" && -f "$SCRIPT_PATH" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "$SCRIPT_PATH")" && pwd)"
    if [[ -f "$SCRIPT_DIR/install.conf" ]]; then
        # shellcheck source=install.conf
        . "$SCRIPT_DIR/install.conf"
    fi
fi

# Environment values win over install.conf values, which win over these
# built-in defaults. This ordering lets the config file be useful in a
# checkout while keeping the script standalone when it is piped from curl.
RTUNNEL_REPO="${RTUNNEL_REPO:-abiiranathan/rtunneld}"
RTUNNEL_VERSION="${RTUNNEL_VERSION:-latest}"
RTUNNEL_TARGET="${RTUNNEL_TARGET:-}"
RTUNNEL_DOWNLOAD_BASE="${RTUNNEL_DOWNLOAD_BASE:-}"
RTUNNEL_BIN="${RTUNNEL_BIN:-}"
RTUNNEL_BIN_DIR="${RTUNNEL_BIN_DIR:-}"
RTUNNEL_RELAY_STATE_DIR="${RTUNNEL_RELAY_STATE_DIR:-/var/lib/rtunnel}"
RTUNNEL_AGENT_STATE_DIR="${RTUNNEL_AGENT_STATE_DIR:-/var/lib/rtunnel-agent}"
RTUNNEL_LISTEN_ADDR="${RTUNNEL_LISTEN_ADDR:-0.0.0.0:4433}"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/rtunnel-install.XXXXXX")"
cleanup() {
    if [[ -n "$TMP_DIR" ]]; then
        rm -rf "$TMP_DIR"
    fi
}
trap cleanup EXIT

log() {
    printf '==> %s\n' "$*" >&2
}

warn() {
    printf 'warning: %s\n' "$*" >&2
}

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

usage() {
    cat >&2 <<'EOF'
Usage: install.sh <relay|agent|client> [options]

Components:
  relay    Install rtunneld, initialize its state, and start the systemd unit.
  agent    Install rtunnel-agent and optionally enroll it with a relay URI.
  client   Install the rtunnel CLI, configure ~/.ssh/config, and optionally enroll.

Examples:
  install.sh relay --listen 0.0.0.0:4433
  install.sh agent "rtunnel://relay.example.com:4433/?fp=...&token=..." --allowed-target 127.0.0.1:22
  install.sh client "rtunnel://relay.example.com:4433/?fp=...&token=..."

Environment:
  RTUNNEL_VERSION         Release tag to install (default: latest).
  RTUNNEL_BIN             Use a local binary instead of downloading.
  RTUNNEL_BIN_DIR         Override the binary installation directory.
  RTUNNEL_TARGET          Override the release asset target triple.
  RTUNNEL_DOWNLOAD_BASE   Override the release download base URL.
  RTUNNEL_REPO            GitHub repository (default: abiiranathan/rtunneld).
EOF
}

detect_target() {
    if [[ -n "$RTUNNEL_TARGET" ]]; then
        printf '%s\n' "$RTUNNEL_TARGET"
        return
    fi

    local os arch
    os="$(uname -s)"
    arch="$(uname -m)"

    case "$os:$arch" in
        Linux:x86_64 | Linux:amd64)
            printf '%s\n' "x86_64-unknown-linux-musl"
            ;;
        Linux:aarch64 | Linux:arm64)
            printf '%s\n' "aarch64-unknown-linux-musl"
            ;;
        *)
            die "no prebuilt binary for $os/$arch; set RTUNNEL_BIN or build from source"
            ;;
    esac
}

download_base() {
    if [[ -n "$RTUNNEL_DOWNLOAD_BASE" ]]; then
        printf '%s\n' "${RTUNNEL_DOWNLOAD_BASE%/}"
        return
    fi

    if [[ "$RTUNNEL_VERSION" == "latest" ]]; then
        printf 'https://github.com/%s/releases/latest/download\n' "$RTUNNEL_REPO"
    else
        local tag="$RTUNNEL_VERSION"
        [[ "$tag" == v* ]] || tag="v$tag"
        printf 'https://github.com/%s/releases/download/%s\n' "$RTUNNEL_REPO" "$tag"
    fi
}

fetch() {
    local url="$1"
    local dest="$2"

    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$url" -o "$dest"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$dest" "$url"
    else
        die "curl or wget is required to download rtunnel"
    fi
}

fetch_optional() {
    local url="$1"
    local dest="$2"

    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$url" -o "$dest" 2>/dev/null
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$dest" "$url" 2>/dev/null
    else
        return 1
    fi
}

verify_asset() {
    local archive="$1"
    local asset_name="$2"
    local sums="$3"
    local expected actual

    expected="$(awk -v name="$asset_name" '$2 == name { print $1; exit }' "$sums")"
    if [[ -z "$expected" ]]; then
        warn "no checksum for $asset_name; skipping verification"
        return
    fi

    if command -v sha256sum >/dev/null 2>&1; then
        actual="$(sha256sum "$archive" | awk '{ print $1 }')"
    elif command -v shasum >/dev/null 2>&1; then
        actual="$(shasum -a 256 "$archive" | awk '{ print $1 }')"
    else
        warn "sha256sum or shasum not found; skipping verification"
        return
    fi

    [[ "$expected" == "$actual" ]] || die "checksum verification failed for $asset_name"
}

download_binary() {
    local name="$1"
    local target asset base

    target="$(detect_target)"
    asset="rtunnel-${target}.tar.gz"
    base="$(download_base)"

    log "Downloading $base/$asset"
    fetch "$base/$asset" "$TMP_DIR/$asset"

    if fetch_optional "$base/SHA256SUMS" "$TMP_DIR/SHA256SUMS"; then
        verify_asset "$TMP_DIR/$asset" "$asset" "$TMP_DIR/SHA256SUMS"
    else
        warn "SHA256SUMS not available; skipping checksum verification"
    fi

    tar -xzf "$TMP_DIR/$asset" -C "$TMP_DIR" "$name" ||
        die "failed to extract $name from $asset"
    printf '%s\n' "$TMP_DIR/$name"
}

resolve_binary() {
    local name="$1"

    if [[ -n "$RTUNNEL_BIN" ]]; then
        [[ -x "$RTUNNEL_BIN" ]] || die "RTUNNEL_BIN is not executable: $RTUNNEL_BIN"
        RTUNNEL_BIN="$(
            cd "$(dirname "$RTUNNEL_BIN")" &&
                printf '%s/%s\n' "$PWD" "$(basename "$RTUNNEL_BIN")"
        )"
        printf '%s\n' "$RTUNNEL_BIN"
        return
    fi

    local candidates=()
    if [[ -n "$SCRIPT_DIR" ]]; then
        candidates+=(
            "$SCRIPT_DIR/../target/release/$name"
            "$SCRIPT_DIR/$name"
        )
    fi

    local candidate
    for candidate in "${candidates[@]}"; do
        if [[ -x "$candidate" ]]; then
            printf '%s\n' "$candidate"
            return
        fi
    done

    download_binary "$name"
}

has_flag() {
    local flag="$1"
    shift
    local arg

    for arg in "$@"; do
        if [[ "$arg" == "$flag" || "$arg" == "$flag="* ]]; then
            return 0
        fi
    done

    return 1
}

run_root() {
    local arg
    for arg in "$@"; do
        if [[ "$arg" == "-h" || "$arg" == "--help" ]]; then
            "$@"
            return
        fi
    done

    if [[ "$EUID" -eq 0 ]]; then
        "$@"
    elif command -v sudo >/dev/null 2>&1; then
        sudo "$@"
    else
        die "root privileges are required; rerun with sudo"
    fi
}

if [[ $# -lt 1 ]]; then
    usage
    exit 64
fi

if [[ "$1" == "-h" || "$1" == "--help" ]]; then
    usage
    exit 0
fi

component="$1"
shift

case "$component" in
    relay)
        install_args=()
        has_flag --state-dir "$@" || install_args+=(--state-dir "$RTUNNEL_RELAY_STATE_DIR")
        has_flag --listen "$@" || install_args+=(--listen "$RTUNNEL_LISTEN_ADDR")
        if [[ -n "$RTUNNEL_BIN_DIR" ]] && ! has_flag --bin-dir "$@"; then
            install_args+=(--bin-dir "$RTUNNEL_BIN_DIR")
        fi

        bin="$(resolve_binary rtunneld)"
        run_root "$bin" install "${install_args[@]}" "$@"
        ;;
    agent)
        global_args=()
        install_args=()
        has_flag --state-dir "$@" || global_args+=(--state-dir "$RTUNNEL_AGENT_STATE_DIR")
        if [[ -n "$RTUNNEL_BIN_DIR" ]] && ! has_flag --bin-dir "$@"; then
            install_args+=(--bin-dir "$RTUNNEL_BIN_DIR")
        fi

        bin="$(resolve_binary rtunnel-agent)"
        run_root "$bin" "${global_args[@]}" install "${install_args[@]}" "$@"
        ;;
    client)
        install_args=()
        if [[ -n "$RTUNNEL_BIN_DIR" ]] && ! has_flag --bin-dir "$@"; then
            install_args+=(--bin-dir "$RTUNNEL_BIN_DIR")
        fi

        bin="$(resolve_binary rtunnel)"
        "$bin" install "${install_args[@]}" "$@"
        ;;
    *)
        usage
        exit 64
        ;;
esac
