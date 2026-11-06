BIN := secwrap

.PHONY: all generate build vmlinux clean

all: build

# Regenerate vmlinux.h from the running kernel (needed when building on another arch/kernel).
vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > internal/monitor/vmlinux.h

# Compile the eBPF C program and generate Go bindings (needs clang + libbpf-dev).
generate:
	cd internal/monitor && go generate ./...

build: generate
	go build -trimpath -o $(BIN) ./cmd/secwrap

clean:
	rm -f $(BIN) internal/monitor/netmon_*_bpfel.*
