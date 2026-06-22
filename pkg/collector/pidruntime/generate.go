package pidruntime

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -D__TARGET_ARCH_x86" -type cpu_acct pidruntime ../../../bpf/pid_runtime.bpf.c -- -I../../../bpf
