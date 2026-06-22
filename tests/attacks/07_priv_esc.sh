#!/bin/sh
# Attack 07: Privilege escalation attempts
# Signature: priv_escalate syscall spike (setuid, setgid, setreuid, setregid, capset, ptrace)
# Simulates: attacker trying to escalate to root inside the container
#
# NOTE: uses python3 -c (inline) instead of nested heredoc, because nested
# heredocs break when piped through `docker run -i sh -s`.
END=$(($(date +%s) + ${1:-20}))
python3 -c "
import ctypes, ctypes.util, time, sys
try:
    libc = ctypes.CDLL(ctypes.util.find_library('c') or 'libc.so.6', use_errno=True)
except Exception:
    sys.exit(0)
end = $END
n = 0
while time.time() < end:
    libc.setuid(0)
    libc.setgid(0)
    libc.setreuid(0, 0)
    libc.setregid(0, 0)
    libc.ptrace(0, 0, 0, 0)
    n += 1
sys.stderr.write('priv_esc iterations: %d\n' % n)
" 2>&1
