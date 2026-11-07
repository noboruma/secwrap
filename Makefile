BIN := secwrap

# Architectures built by `make dist`. Any Linux GOARCH works: the eBPF code is
# built once per byte order (bpfel, bpfeb), not per CPU.
ARCHES := amd64 386 arm64 arm mips mipsle mips64 mips64le riscv64 ppc64le s390x loong64

.PHONY: all generate build dist vmlinux clean

all: build

# vmlinux.h only provides kernel type definitions: field offsets are relocated
# at load time (CO-RE), so a vmlinux.h from any architecture works.
vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > internal/monitor/vmlinux.h

# Compile the eBPF C program and generate Go bindings (needs clang + libbpf-dev).
generate:
	cd internal/monitor && go generate ./...

build: generate
	go build -trimpath -o $(BIN) ./cmd/secwrap

# Static binaries for every architecture in dist/, each with its SHA-256
# checksum (mips: softfloat, for CPUs without an FPU).
dist: generate
	mkdir -p dist
	for a in $(ARCHES); do \
		CGO_ENABLED=0 GOOS=linux GOARCH=$$a GOMIPS=softfloat GOMIPS64=softfloat \
			go build -trimpath -ldflags "-s -w" -o dist/$(BIN)-linux-$$a ./cmd/secwrap || exit 1; \
		(cd dist && sha256sum $(BIN)-linux-$$a > $(BIN)-linux-$$a.sha256) || exit 1; \
	done

clean:
	rm -rf $(BIN) dist internal/monitor/secwrap_bpfe[lb].*
