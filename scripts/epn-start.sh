#!/bin/bash
# epn-start.sh — Launch the full EPN tunnel system
#
# Starts: discovery, 3 relays, tun-server, tun-client (SOCKS5 on :1080)
# Usage:
#   ./scripts/epn-start.sh               # SOCKS5 mode
#   ./scripts/epn-start.sh --transparent  # Transparent mode (requires sudo epn-setup.sh first)

set -euo pipefail

BUILD="${BUILD:-$(dirname "$0")/../build/apps}"
DISC_PORT="${DISC_PORT:-8000}"
SOCKS_PORT="${SOCKS_PORT:-1080}"
TPROXY_PORT="${TPROXY_PORT:-1081}"
LOG_DIR="${LOG_DIR:-/tmp/epn-logs}"
TRANSPARENT=0

for arg in "$@"; do
    [[ "$arg" == "--transparent" ]] && TRANSPARENT=1
done

mkdir -p "$LOG_DIR"

stop_all() {
    echo ""
    echo "Stopping EPN..."
    pkill -f "epn-discovery" 2>/dev/null || true
    pkill -f "epn-relay"     2>/dev/null || true
    pkill -f "epn-tun-server" 2>/dev/null || true
    pkill -f "epn-tun-client" 2>/dev/null || true
    sleep 0.5
    echo "EPN stopped."
}
trap stop_all EXIT INT TERM

echo "═══════════════════════════════════════════"
echo "  EPN — Ephemeral Private Network"
echo "═══════════════════════════════════════════"

echo ""
echo "Starting discovery server (port $DISC_PORT)..."
"$BUILD/epn-discovery/epn-discovery" --port "$DISC_PORT" \
    > "$LOG_DIR/discovery.log" 2>&1 &
sleep 0.4

echo "Starting relay nodes..."
for port in 9001 9002 9003; do
    "$BUILD/epn-relay/epn-relay" \
        --port "$port" --disc-port "$DISC_PORT" \
        > "$LOG_DIR/relay-$port.log" 2>&1 &
    sleep 0.2
done
sleep 0.3

echo "Starting tunnel server (port 9200)..."
"$BUILD/epn-tun-server/epn-tun-server" \
    --port 9200 --disc-port "$DISC_PORT" \
    > "$LOG_DIR/tun-server.log" 2>&1 &
sleep 0.7

echo "Starting tunnel client..."
if [[ $TRANSPARENT -eq 1 ]]; then
    echo "  Mode: Transparent proxy (port $TPROXY_PORT)"
    "$BUILD/epn-tun-client/epn-tun-client" \
        --disc-port "$DISC_PORT" \
        --transparent --tproxy-port "$TPROXY_PORT" \
        > "$LOG_DIR/tun-client.log" 2>&1 &
else
    echo "  Mode: SOCKS5 proxy (port $SOCKS_PORT)"
    "$BUILD/epn-tun-client/epn-tun-client" \
        --disc-port "$DISC_PORT" \
        --socks-port "$SOCKS_PORT" \
        > "$LOG_DIR/tun-client.log" 2>&1 &
fi
sleep 2.0

echo ""
echo "═══════════════════════════════════════════"
echo "  EPN System Running"
echo "═══════════════════════════════════════════"

if [[ $TRANSPARENT -eq 1 ]]; then
    echo ""
    echo "  Mode: Transparent (all TCP routed via EPN)"
    echo "  Requires: sudo ./scripts/epn-setup.sh first"
    echo ""
    echo "  Test:"
    echo "    curl http://example.com     # all traffic via EPN"
else
    echo ""
    echo "  Mode: SOCKS5 proxy"
    echo "  Proxy: 127.0.0.1:$SOCKS_PORT"
    echo ""
    echo "  Test:"
    echo "    curl --socks5 127.0.0.1:$SOCKS_PORT http://example.com"
    echo "    curl --socks5 127.0.0.1:$SOCKS_PORT https://api.example.com/v1/data"
    echo ""
    echo "  Browser: Set SOCKS5 proxy to 127.0.0.1:$SOCKS_PORT"
fi

echo ""
echo "  Logs: $LOG_DIR/"
echo "  Stop: Ctrl+C"
echo ""

# Wait indefinitely until SIGINT/SIGTERM
wait
