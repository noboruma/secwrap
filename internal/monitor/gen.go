package monitor

// Regenerate vmlinux.h for your kernel with:
//   bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux -target bpfel,bpfeb -type event -type file_event secwrap secwrap.bpf.c -- -I. -O2 -g -Wall
