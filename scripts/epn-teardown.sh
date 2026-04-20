#!/bin/bash
# epn-teardown.sh — Remove EPN transparent tunnel iptables rules

CHAIN="EPN_REDIRECT"
GREEN='\033[0;32m'; NC='\033[0m'

if [[ $EUID -ne 0 ]]; then
    echo "Error: must run as root" >&2; exit 1
fi

echo "Removing EPN iptables rules..."
iptables -t nat -D OUTPUT -p tcp -j "$CHAIN" 2>/dev/null || true
iptables -t nat -F "$CHAIN" 2>/dev/null || true
iptables -t nat -X "$CHAIN" 2>/dev/null || true

echo -e "${GREEN}✓ EPN tunnel rules removed. Traffic restored to normal routing.${NC}"
