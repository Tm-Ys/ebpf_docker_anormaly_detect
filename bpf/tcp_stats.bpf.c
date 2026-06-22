//go:build ignore

// Ported from Pixie's src/stirling/source_connectors/tcp_stats/bcc_bpf/tcp_stats.c
//
// Probe attachment points are identical to Pixie (tcp_sendmsg ret, tcp_cleanup_rbuf,
// tcp_retransmit_skb) — that is the eBPF "technique" we reuse. The data path differs:
// Pixie emits a perf event per operation (needs addr info for tracing); we instead
// accumulate per-tgid counters in a percpu hash and poll from userspace. This drops
// ~99% of the overhead since anomaly detection only needs per-container aggregates.
//
// On kernel 6.6 tcp_sendpage is gone, so Pixie's sendpage probes are dropped here.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Per-tgid TCP counters. Userspace reads + clears periodically.
struct tcp_stats {
	__u64 bytes_tx;       // bytes sent (tcp_sendmsg return)
	__u64 bytes_rx;       // bytes recv (tcp_cleanup_rbuf copied)
	__u64 pkts_tx;        // sendmsg calls with >0 bytes
	__u64 pkts_rx;        // cleanup_rbuf calls with >0 bytes
	__u64 retransmits;    // tcp_retransmit_skb invocations
};

// PERCPU_HASH: no locking, fastest path. Userspace sums per-cpu values on read.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 10240);
	__type(key, __u32);             // tgid
	__type(value, struct tcp_stats);
} tcp_stats_by_tgid SEC(".maps");

// Anchor so bpf2go -type can extract the struct from BTF.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct tcp_stats);
} _tcp_stats_anchor SEC(".maps");

static __always_inline void bump(u32 tgid, __u64 tx_b, __u64 rx_b, __u64 retrans)
{
	struct tcp_stats *v = bpf_map_lookup_elem(&tcp_stats_by_tgid, &tgid);
	if (v) {
		if (tx_b)   { v->bytes_tx += tx_b;   v->pkts_tx += 1; }
		if (rx_b)   { v->bytes_rx += rx_b;   v->pkts_rx += 1; }
		if (retrans){ v->retransmits += 1; }
		return;
	}
	struct tcp_stats newv = {};
	if (tx_b)    { newv.bytes_tx = tx_b;  newv.pkts_tx = 1; }
	if (rx_b)    { newv.bytes_rx = rx_b;  newv.pkts_rx = 1; }
	if (retrans) { newv.retransmits = 1;  }
	bpf_map_update_elem(&tcp_stats_by_tgid, &tgid, &newv, BPF_NOEXIST);
}

// tcp_sendmsg return: bytes actually sent is the return value.
SEC("kretprobe/tcp_sendmsg")
int BPF_KRETPROBE(kretprobe_tcp_sendmsg, int sent)
{
	if (sent <= 0)
		return 0;
	u32 tgid = bpf_get_current_pid_tgid() >> 32;
	bump(tgid, (__u64)sent, 0, 0);
	return 0;
}

// tcp_cleanup_rbuf: copied is the bytes received.
SEC("kprobe/tcp_cleanup_rbuf")
int BPF_KPROBE(kprobe_tcp_cleanup_rbuf, struct sock *sk, int copied)
{
	if (copied <= 0)
		return 0;
	u32 tgid = bpf_get_current_pid_tgid() >> 32;
	bump(tgid, 0, (__u64)copied, 0);
	return 0;
}

// tcp_retransmit_skb: every call counts as one retransmission.
SEC("kprobe/tcp_retransmit_skb")
int BPF_KPROBE(kprobe_tcp_retransmit_skb, struct sock *sk, struct sk_buff *skb, int type)
{
	u32 tgid = bpf_get_current_pid_tgid() >> 32;
	bump(tgid, 0, 0, 1);
	return 0;
}
