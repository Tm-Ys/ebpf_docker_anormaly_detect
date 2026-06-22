#!/bin/sh
# Attack 05: Cryptocurrency mining
# Signature: sustained 100% CPU, high mem_layout (mmap), low file/net activity
# Simulates: crypto miner hashing in a tight loop
END=$(($(date +%s) + ${1:-20}))
# Spawn N parallel hashers to peg all CPUs
N=$(nproc 2>/dev/null || echo 2)
i=0
while [ "$i" -lt "$N" ]; do
  (
    # Tight SHA256 loop — this is what xmrig/stratum miners look like at the
    # syscall level: mmap for buffers, lots of CPU, almost no I/O.
    DATA=$(head -c 256 /dev/urandom | base64)
    while [ "$(date +%s)" -lt "$END" ]; do
      echo "$DATA" | sha256sum >/dev/null
      echo "$DATA" | md5sum >/dev/null
    done
  ) &
  i=$((i + 1))
done
wait
