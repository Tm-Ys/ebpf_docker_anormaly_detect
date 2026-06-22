package procexit

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -type proc_exit_event procexit ../../../bpf/proc_exit.bpf.c -- -I../../../bpf
