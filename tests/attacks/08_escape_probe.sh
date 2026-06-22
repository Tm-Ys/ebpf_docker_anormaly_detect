#!/bin/sh
# Attack 08: Container escape probes
# Signature: escape_attempt spike (mount, umount, unshare, setns, bpf)
# Simulates: attacker probing container escape vectors (CVE-2019-5736-style,
#   cgroup release_agent, /proc/1/root, mount namespace tricks)
END=$(($(date +%s) + ${1:-20}))
while [ "$(date +%s)" -lt "$END" ]; do
  # Namespace escape via unshare + mount
  unshare --mount /bin/true 2>/dev/null
  unshare --user --mount /bin/true 2>/dev/null
  unshare --pid --fork /bin/true 2>/dev/null
  unshare --net /bin/true 2>/dev/null

  # Mount tricks (CVE-2019-5736 / standard container escape)
  mount -t tmpfs none /tmp 2>/dev/null
  mount -t proc none /proc 2>/dev/null
  mount --bind /etc /tmp 2>/dev/null
  umount /tmp 2>/dev/null

  # nsenter into PID 1's namespaces (host)
  nsenter --target 1 --mount --uts --ipc --net --pid /bin/true 2>/dev/null

  # cgroup release_agent escape (write to cgroup files)
  echo 1 > /sys/fs/cgroup/notify_on_release 2>/dev/null
  echo 1 > /sys/fs/cgroup/system.slice/notify_on_release 2>/dev/null

  # /proc/1/root access (host filesystem from container)
  ls /proc/1/root/ 2>/dev/null >/dev/null
  cat /proc/1/root/etc/shadow 2>/dev/null >/dev/null

  # Kernel module / device access
  cat /proc/modules 2>/dev/null >/dev/null
  ls /dev/sda* 2>/dev/null >/dev/null
done
