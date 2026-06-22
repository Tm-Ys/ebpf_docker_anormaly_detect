//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct exit_stat {
    __u64 ts_ns;
    __u32 tgid;
    __u32 pad;
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, u64);
    __uint(max_entries, 1);
} exit_count SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, struct exit_stat);
    __uint(max_entries, 1024);
} last_exit SEC(".maps");

SEC("tp/sched/sched_process_exit")
int count_sched_process_exit(void *ctx)
{
    u32 zero = 0;
    u64 *cnt = bpf_map_lookup_elem(&exit_count, &zero);
    if (cnt)
        __sync_fetch_and_add(cnt, 1);

    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;

    struct exit_stat st = {};
    st.ts_ns = bpf_ktime_get_ns();
    st.tgid = tgid;
    bpf_get_current_comm(&st.comm, sizeof(st.comm));
    bpf_map_update_elem(&last_exit, &tgid, &st, BPF_ANY);

    return 0;
}
