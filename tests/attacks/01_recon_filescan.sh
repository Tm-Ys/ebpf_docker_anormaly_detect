#!/bin/sh
# Attack 01: Mass file enumeration (reconnaissance)
# Signature: file_open + file_read spike, high getdents
# Simulates: attacker mapping the filesystem for credentials, configs, secrets
END=$(($(date +%s) + ${1:-20}))
while [ "$(date +%s)" -lt "$END" ]; do
  # Bounded depth to keep each iteration fast on large filesystems.
  find / -maxdepth 4 -type f 2>/dev/null | wc -l >/dev/null
  find /etc /opt /var /root /home /app /usr/local -maxdepth 3 -name "*.conf" 2>/dev/null | wc -l >/dev/null
  find / -maxdepth 5 \( -name "*.pem" -o -name "*.key" -o -name "*.crt" \) 2>/dev/null | wc -l >/dev/null
  find / -maxdepth 4 \( -name ".env" -o -name ".git" -o -name ".ssh" \) 2>/dev/null | wc -l >/dev/null
done
