package syscalls

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -D__TARGET_ARCH_x86" -type syscall_counts syscalls ../../../bpf/syscall_trace.bpf.c -- -I../../../bpf
