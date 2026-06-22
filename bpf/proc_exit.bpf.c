//go:build ignore

// Ported from Pixie's src/stirling/source_connectors/proc_exit/bcc_bpf/proc_exit_trace.c
// Changes vs BCC original:
//   - BCC macros (BPF_PERF_OUTPUT, TRACEPOINT_PROBE) -> libbpf SEC() + BTF maps
//   - task_struct offset detection (Pixie's task_struct_resolver.cc) -> direct
//     field access via CO-RE, since BTF provides the layout
//   - Only emit on thread-group-leader exit, matching original behavior
//
// Emits a proc_exit_event to a perf buffer for every process (not thread) exit.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Mirrors the kernel task_struct fields we need; layout must match the
// Go struct generated via bpf2go's -type proc_exit_event.
struct proc_exit_event {
	__u64 ts_ns;          // bpf_ktime_get_ns at exit
	__u64 start_time_ns;  // task->start_boottime, makes (tgid,start_time) a UPID
	__u32 tgid;           // process id (kernel tgid == userspace pid)
	__u32 exit_code;      // raw exit code; low 7 bits = signal, bits 8+ = exit status
	char   comm[16];      // task comm (executable name, truncated)
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} proc_exit_events SEC(".maps");

// Per-CPU scratch heap. Doubles as a BTF anchor: perf event arrays don't
// reference the event struct, so without this map the struct wouldn't be
// emitted to BTF and bpf2go's -type couldn't extract it. Also avoids putting
// a 40-byte struct on the BPF stack (verifier is friendlier to heap allocs).
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct proc_exit_event);
} proc_exit_heap SEC(".maps");

SEC("tp/sched/sched_process_exit")
int handle_proc_exit(void *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	__u32 tgid = id >> 32;
	__u32 tid  = id;

	// Only fire for thread-group leaders; threads share tgid but have their
	// own tid. This matches Pixie's is_thread_group_leader check.
	if (tgid != tid)
		return 0;

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();

	__u32 zero = 0;
	struct proc_exit_event *e = bpf_map_lookup_elem(&proc_exit_heap, &zero);
	if (!e)
		return 0; // should never happen for percpu array
	e->ts_ns = bpf_ktime_get_ns();
	e->tgid  = tgid;
	// bpf_get_current_task() returns a pointer the verifier treats as scalar,
	// so direct deref (task->field) is rejected. BPF_CORE_READ wraps
	// bpf_probe_read_kernel with CO-RE relocation, which the verifier accepts.
	// Equivalent to Pixie's bpf_probe_read-based access in BCC.
	e->start_time_ns = BPF_CORE_READ(task, start_boottime);
	e->exit_code     = BPF_CORE_READ(task, exit_code);
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	bpf_perf_event_output(ctx, &proc_exit_events, BPF_F_CURRENT_CPU, e, sizeof(*e));
	return 0;
}
