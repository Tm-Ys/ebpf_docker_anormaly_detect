//go:build ignore

// Syscall histogram with BPF-side container attribution.
//
// KEY CHANGE vs previous version: uses bpf_get_current_cgroup_id() to identify
// the container at syscall time, IN THE KERNEL. Userspace maintains a tiny
// cgid_map (cgroup_id → container_index). This eliminates the /proc-based
// userspace resolution that lost data for short-lived processes.
//
// Host processes are filtered in BPF (cgid_map lookup miss → return 0), so the
// data map only contains container entries — smaller, faster to poll.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// --- x86_64 syscall numbers ---
#define _NR_read        0
#define _NR_write       1
#define _NR_open        2
#define _NR_close       3
#define _NR_pread64    17
#define _NR_pwrite64   18
#define _NR_socket     41
#define _NR_connect    42
#define _NR_accept     43
#define _NR_sendto     44
#define _NR_recvfrom   45
#define _NR_sendmsg    46
#define _NR_recvmsg    47
#define _NR_bind       49
#define _NR_listen     50
#define _NR_accept4   288
#define _NR_clone      56
#define _NR_fork       57
#define _NR_vfork      58
#define _NR_execve     59
#define _NR_kill       62
#define _NR_ptrace    101
#define _NR_setuid    105
#define _NR_setgid    106
#define _NR_setreuid  113
#define _NR_setregid  114
#define _NR_capset    126
#define _NR_unlink     87
#define _NR_rename     82
#define _NR_chmod      90
#define _NR_fchmod     91
#define _NR_chown      92
#define _NR_fchown     93
#define _NR_lchown     94
#define _NR_mount     165
#define _NR_umount2   166
#define _NR_unshare   310
#define _NR_setns     308
#define _NR_openat    257
#define _NR_bpf       321
#define _NR_execveat  322
#define _NR_unlinkat  263
#define _NR_renameat  264
#define _NR_renameat2 316
#define _NR_fchmodat  268
#define _NR_fchownat  260
#define _NR_clone3    435
#define _NR_openat2   437
#define _NR_mmap       9
#define _NR_mprotect  10
#define _NR_brk       12

struct syscall_counts {
	__u64 total;
	__u64 file_open;
	__u64 file_close;
	__u64 file_read;
	__u64 file_write;
	__u64 file_unlink;
	__u64 file_rename;
	__u64 file_perm;
	__u64 net_socket;
	__u64 net_connect;
	__u64 net_bind;
	__u64 net_listen;
	__u64 net_accept;
	__u64 net_send;
	__u64 net_recv;
	__u64 proc_exec;
	__u64 proc_fork;
	__u64 proc_kill;
	__u64 priv_escalate;
	__u64 escape_attempt;
	__u64 mem_layout;
	__u64 other;
};

// Userspace-maintained: cgroup v2 id → container index.
// Updated when containers start/stop. Key insight: this lookup happens in BPF
// at syscall time, so attribution is instant and survives process exit.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u64);
	__type(value, __u32);
} cgid_map SEC(".maps");

// Per-container syscall histogram. Key = container index (from cgid_map).
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 256);
	__type(key, __u32);
	__type(value, struct syscall_counts);
} syscalls_by_cgid SEC(".maps");

// BTF anchor.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct syscall_counts);
} _syscalls_anchor SEC(".maps");

struct bpf_raw_tp_args {
	__u64 args[8];
};

SEC("raw_tracepoint/sys_enter")
int trace_sys_enter(struct bpf_raw_tp_args *ctx)
{
	// --- Container attribution in BPF (the core change) ---
	__u64 cgid = bpf_get_current_cgroup_id();
	__u32 *idx = bpf_map_lookup_elem(&cgid_map, &cgid);
	if (!idx)
		return 0; // host process — skip entirely, don't even count

	__u32 id = (__u32)ctx->args[1];

	struct syscall_counts *c = bpf_map_lookup_elem(&syscalls_by_cgid, idx);
	if (!c) {
		struct syscall_counts zero = {};
		bpf_map_update_elem(&syscalls_by_cgid, idx, &zero, BPF_NOEXIST);
		c = bpf_map_lookup_elem(&syscalls_by_cgid, idx);
		if (!c)
			return 0;
	}
	c->total++;

	switch (id) {
	case _NR_open: case _NR_openat: case _NR_openat2:        c->file_open++;     break;
	case _NR_close:                                            c->file_close++;    break;
	case _NR_read: case _NR_pread64:                          c->file_read++;     break;
	case _NR_write: case _NR_pwrite64:                        c->file_write++;    break;
	case _NR_unlink: case _NR_unlinkat:                       c->file_unlink++;   break;
	case _NR_rename: case _NR_renameat: case _NR_renameat2:   c->file_rename++;   break;
	case _NR_chmod: case _NR_fchmod: case _NR_fchmodat:
	case _NR_chown: case _NR_fchown: case _NR_lchown:
	case _NR_fchownat:                                         c->file_perm++;     break;
	case _NR_socket:                                           c->net_socket++;    break;
	case _NR_connect:                                          c->net_connect++;   break;
	case _NR_bind:                                             c->net_bind++;      break;
	case _NR_listen:                                           c->net_listen++;    break;
	case _NR_accept: case _NR_accept4:                        c->net_accept++;    break;
	case _NR_sendto: case _NR_sendmsg:                        c->net_send++;      break;
	case _NR_recvfrom: case _NR_recvmsg:                      c->net_recv++;      break;
	case _NR_execve: case _NR_execveat:                       c->proc_exec++;     break;
	case _NR_fork: case _NR_vfork:
	case _NR_clone: case _NR_clone3:                          c->proc_fork++;     break;
	case _NR_kill:                                             c->proc_kill++;     break;
	case _NR_ptrace:
	case _NR_setuid: case _NR_setgid:
	case _NR_setreuid: case _NR_setregid:
	case _NR_capset:                                           c->priv_escalate++; break;
	case _NR_mount: case _NR_umount2:
	case _NR_unshare: case _NR_setns:
	case _NR_bpf:                                              c->escape_attempt++;break;
	case _NR_mmap: case _NR_mprotect: case _NR_brk:           c->mem_layout++;    break;
	default:                                                   c->other++;         break;
	}
	return 0;
}
