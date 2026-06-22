#!/bin/sh
# Attack 02: Sensitive file access (credential harvesting)
# Signature: file_open on specific sensitive paths, sequential not enumerated
# Simulates: attacker reading passwords, keys, env vars, proc info
END=$(($(date +%s) + ${1:-20}))
while [ "$(date +%s)" -lt "$END" ]; do
  cat /etc/passwd 2>/dev/null >/dev/null
  cat /etc/shadow 2>/dev/null >/dev/null
  cat /etc/group 2>/dev/null >/dev/null
  cat /etc/hosts 2>/dev/null >/dev/null
  cat /etc/resolv.conf 2>/dev/null >/dev/null
  cat /proc/1/environ 2>/dev/null >/dev/null
  cat /proc/1/cmdline 2>/dev/null >/dev/null
  cat /proc/self/status 2>/dev/null >/dev/null
  # SSH keys (won't exist but the opens fire)
  for k in id_rsa id_ed25519 identity authorized_keys; do
    cat "$HOME/.ssh/$k" 2>/dev/null >/dev/null
    cat "/root/.ssh/$k" 2>/dev/null >/dev/null
  done
  # App secrets
  cat /.env 2>/dev/null >/dev/null
  cat /app/.env 2>/dev/null >/dev/null
  cat /run/secrets/* 2>/dev/null >/dev/null
done
