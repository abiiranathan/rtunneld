#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

echo "=== Building rtunnel release binaries ==="
cargo build --release --workspace

RELAY_BIN="./target/release/rtunneld"
AGENT_BIN="./target/release/rtunnel-agent"
CLIENT_BIN="./target/release/rtunnel"

WORK_DIR=$(mktemp -d /tmp/rtunnel-e2e-XXXXXX)
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$WORK_DIR"' EXIT

RELAY_DIR="$WORK_DIR/relay"
AGENT_DIR="$WORK_DIR/agent"
CLIENT_DIR="$WORK_DIR/client"

echo "=== Initializing Relay ==="
"$RELAY_BIN" init --state-dir "$RELAY_DIR"

echo "=== Starting Relay Daemon ==="
"$RELAY_BIN" serve --state-dir "$RELAY_DIR" --listen 127.0.0.1:9443 &
RELAY_PID=$!
sleep 1

echo "=== Creating Enrollment Tokens ==="
AGENT_URI=$("$RELAY_BIN" token create --role agent --name lan-agent --ttl 5m --state-dir "$RELAY_DIR" --relay-host 127.0.0.1 --relay-port 9443 | grep "Enrollment URI:" | awk '{print $3}')
CLIENT_URI=$("$RELAY_BIN" token create --role client --name dev-laptop --ttl 5m --state-dir "$RELAY_DIR" --relay-host 127.0.0.1 --relay-port 9443 | grep "Enrollment URI:" | awk '{print $3}')

echo "=== Authorizing Access Grant ==="
"$RELAY_BIN" grant add dev-laptop lan-agent --state-dir "$RELAY_DIR"

echo "=== Starting Local TCP Echo Target ==="
ECHO_PORT=9022
python3 -c "
import socket, threading
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('127.0.0.1', $ECHO_PORT))
s.listen(5)
def handle(conn):
    while True:
        data = conn.recv(1024)
        if not data: break
        conn.sendall(data)
    conn.close()
while True:
    conn, _ = s.accept()
    threading.Thread(target=handle, args=(conn,), daemon=True).start()
" &
ECHO_PID=$!
sleep 1

echo "=== Enrolling Agent ==="
"$AGENT_BIN" --state-dir "$AGENT_DIR" enroll "$AGENT_URI" --allowed-target "127.0.0.1:$ECHO_PORT"

echo "=== Starting Agent Connector ==="
"$AGENT_BIN" --state-dir "$AGENT_DIR" run &
AGENT_PID=$!
sleep 1

echo "=== Enrolling Client ==="
"$CLIENT_BIN" --state-dir "$CLIENT_DIR" enroll "$CLIENT_URI"

echo "=== Testing Proxy Tunnel End-to-End ==="
TEST_PAYLOAD="Hello through encrypted rtunnel rendezvous!"
ECHO_RESULT=$(echo "$TEST_PAYLOAD" | "$CLIENT_BIN" --state-dir "$CLIENT_DIR" connect lan-agent "127.0.0.1:$ECHO_PORT")

if [ "$ECHO_RESULT" == "$TEST_PAYLOAD" ]; then
    echo "SUCCESS: Echo test matched expected payload through tunnel."
else
    echo "FAILURE: Output '$ECHO_RESULT' did not match expected '$TEST_PAYLOAD'"
    exit 1
fi

echo "=== Testing Revocation Response ==="
"$RELAY_BIN" revoke lan-agent --state-dir "$RELAY_DIR"
sleep 2

# Connection must fail after revocation
if echo "ping" | "$CLIENT_BIN" --state-dir "$CLIENT_DIR" connect lan-agent "127.0.0.1:$ECHO_PORT" 2>/dev/null; then
    echo "FAILURE: Connection succeeded despite revocation!"
    exit 1
else
    echo "SUCCESS: Revoked agent was blocked as expected."
fi

echo "=== All E2E Integration Checks Passed Successfully ==="
