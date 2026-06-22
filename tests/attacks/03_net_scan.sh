#!/bin/sh
# Attack 03: Network scanning (lateral movement / C2 discovery)
# Signature: net_connect spike to many destinations
# Simulates: attacker scanning internal network for reachable services
END=$(($(date +%s) + ${1:-20}))
# Scan localhost ports (always reachable, generates connect syscalls)
PORTS="21 22 23 25 53 80 110 143 443 993 995 1433 1521 3306 5432 6379 8080 8443 9090 27017"
while [ "$(date +%s)" -lt "$END" ]; do
  for p in $PORTS; do
    # -z = scan mode (just connect, no data). Short timeout.
    curl -s --connect-timeout 1 -o /dev/null "http://127.0.0.1:$p/" 2>/dev/null
  done
  # Also probe a few external targets
  curl -s --connect-timeout 1 -o /dev/null http://example.com 2>/dev/null
  curl -s --connect-timeout 1 -o /dev/null http://localhost:3000 2>/dev/null
  curl -s --connect-timeout 1 -o /dev/null http://localhost:6185 2>/dev/null
done
