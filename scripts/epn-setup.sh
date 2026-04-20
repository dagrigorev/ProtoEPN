#!/bin/bash
# epn-setup.sh — Set up EPN transparent TCP tunnel
# Run as root. All outgoing TCP traffic will be routed through EPN.
#
# Usage:
#   sudo ./scripts/epn-setup.sh [relay_ip1] [relay_ip2] ...
#
# Example (relays on localhost for dev):
#   sudo ./scripts/epn-setup.sh 127.0.0.1
#
# After this, start:
#   ./build/apps/epn-tun-client/epn-tun-client \
#       --disc-port 8000 --transparent --tproxy-port 1081

set -euo pipefail

TPROXY_PORT="${TPROXY_PORT:-1081}"
CHAIN="EPN_REDIRECT"

# Colours
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}Error: must run as root (sudo $0)${NC}" >&2
    exit 1
fi

echo -e "${GREEN}EPN Transparent Tunnel Setup${NC}"
echo "  Proxy port:  $TPROXY_PORT"
echo "  iptables chain: $CHAIN"
echo ""

# ─── Create EPN chain ─────────────────────────────────────────────────────────
iptables -t nat -N "$CHAIN" 2>/dev/null || true
iptables -t nat -F "$CHAIN"

echo "Adding exclusion rules..."

# Loopback — never intercept
iptables -t nat -A "$CHAIN" -o lo -j RETURN

# Private / link-local / multicast ranges
for cidr in 127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 \
            169.254.0.0/16 224.0.0.0/4 240.0.0.0/4; do
    iptables -t nat -A "$CHAIN" -d "$cidr" -j RETURN
done

# User-specified exclusions (EPN relay/server IPs to avoid loops)
for ip in "$@"; do
    echo "  Excluding: $ip"
    iptables -t nat -A "$CHAIN" -d "$ip" -j RETURN
done

# Exclude packets marked by epn-tun-client itself (SO_MARK = 0xEAB5)
# This prevents the EPN tunnel's own TCP connections from being re-intercepted
iptables -t nat -A "$CHAIN" -m mark --mark 0xEAB5 -j RETURN

# ─── Redirect remaining TCP ────────────────────────────────────────────────────
echo "Adding REDIRECT rule → port $TPROXY_PORT..."
iptables -t nat -A "$CHAIN" -p tcp -j REDIRECT --to-ports "$TPROXY_PORT"

# ─── Hook into OUTPUT chain ────────────────────────────────────────────────────
iptables -t nat -D OUTPUT -p tcp -j "$CHAIN" 2>/dev/null || true
iptables -t nat -A OUTPUT  -p tcp -j "$CHAIN"

echo ""
echo -e "${GREEN}✓ iptables rules installed${NC}"
echo ""
echo "Current EPN chain:"
iptables -t nat -L "$CHAIN" -n --line-numbers
echo ""
echo "Next steps:"
echo "  1. Start EPN infrastructure (discovery, relays, tun-server)"
echo "  2. Run the tunnel client:"
echo "     ./build/apps/epn-tun-client/epn-tun-client \\"
echo "         --disc-port 8000 --transparent --tproxy-port $TPROXY_PORT"
echo "  3. All TCP traffic is now tunneled through EPN"
echo ""
echo "To undo: sudo ./scripts/epn-teardown.sh"
