//go:build ignore

// Adapted from Pixie's src/stirling/source_connectors/pid_runtime/bcc_bpf/pidruntime.c
//
// Pixie attaches a kprobe to finish_task_switch (kernel-internal, inlined on
// 6.6+). We instead use the stable sched:sched_switch tracepoint, which gives
// us prev_pid and next_pid directly. The accounting is the same idea: on each
// context switch, charge the outgoing task for the wall-time it ran since its
// last switch-in, and stamp the incoming task's switch-in time.
//
// Result: per-pid CPU runtime in nanoseconds, polled by userspace.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Per-pid accounting entry. PERCPU_HASH: no locks on the hot context-switch path.
struct cpu_acct {
	__u64 last_start_ns;  // ktime when this pid last switched IN
	__u64 runtime_ns;     // accumulated CPU runtime
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 65536);
	__type(key, __u32);              // pid (tgid)
	__type(value, struct cpu_acct);
} cpu_acct_by_pid SEC(".maps");

// BTF anchor so bpf2go -type can extract the struct.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct cpu_acct);
} _cpu_acct_anchor SEC(".maps");

// sched:sched_switch tracepoint field offsets, copied verbatim from
// /sys/kernel/tracing/events/sched/sched_switch/format (which includes the
// 8-byte common header that libbpf leaves in the ctx pointer). Reading via
// bpf_probe_read_kernel at these exact offsets removes any struct-layout doubt.
#define OFF_PREV_PID 24
#define OFF_NEXT_PID 56

SEC("tp/sched/sched_switch")
int trace_sched_switch(void *ctx)
{
	__u64 now = bpf_ktime_get_ns();

	__u32 prev_pid = 0, next_pid = 0;
	bpf_probe_read_kernel(&prev_pid, sizeof(prev_pid), ctx + OFF_PREV_PID);
	bpf_probe_read_kernel(&next_pid, sizeof(next_pid), ctx + OFF_NEXT_PID);

	if (prev_pid != 0) {
		struct cpu_acct *p = bpf_map_lookup_elem(&cpu_acct_by_pid, &prev_pid);
		if (p) {
			// Charge the outgoing task for time it ran since last switch-in.
			if (now >= p->last_start_ns)
				p->runtime_ns += now - p->last_start_ns;
			p->last_start_ns = 0; // not running
		}
	}

	if (next_pid != 0) {
		struct cpu_acct *n = bpf_map_lookup_elem(&cpu_acct_by_pid, &next_pid);
		if (n) {
			n->last_start_ns = now;
		} else {
			struct cpu_acct newv = {.last_start_ns = now, .runtime_ns = 0};
			bpf_map_update_elem(&cpu_acct_by_pid, &next_pid, &newv, BPF_NOEXIST);
		}
	}
	return 0;
}
