package tcpstats

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -D__TARGET_ARCH_x86" -type tcp_stats tcpstats ../../../bpf/tcp_stats.bpf.c -- -I../../../bpf
