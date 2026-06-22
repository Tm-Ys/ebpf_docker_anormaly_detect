.PHONY: all build bpf agent test clean generate vmlinux

BPF_SRC_DIR := bpf
AGENT_BIN   := bin/agent

CLANG       ?= clang
GOFLAGS     := -trimpath

all: $(AGENT_BIN)

# Generate vmlinux.h from the running kernel's BTF.
vmlinux:
	@bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(BPF_SRC_DIR)/vmlinux.h
	@echo "generated $(BPF_SRC_DIR)/vmlinux.h"

# Generate Go bindings from .bpf.c via bpf2go.
generate: vmlinux
	@go generate ./...

# Build the agent binary.
agent: generate
	@mkdir -p bin
	@go build $(GOFLAGS) -o $(AGENT_BIN) ./cmd/agent/
	@echo "built $(AGENT_BIN)"

build: agent

# Run the full test suite.
test:
	@bash tests/run_suite.sh napcat

# Run detection on collected data.
detect:
	@.venv/bin/python detect/detect.py data/features.csv \
		--train data/baseline.csv --contamination 0.12

# Generate visualization plots from scored data.
plots:
	@.venv/bin/python detect/visualize.py data/features_scored.csv data/labels.csv

clean:
	@rm -rf bin/ data/*.csv /tmp/test_suite_agent.log
	@find . -name '*_bpf*.go' -o -name '*_bpf*.o' | xargs rm -f 2>/dev/null || true
	@echo "cleaned"

# Verify the project has no pixie/stirling references.
verify-clean:
	@grep -rln "pixie\|stirling" --include="*.go" --include="*.c" --include="*.h" \
		--include="*.py" --include="*.sh" . 2>/dev/null | grep -v vmlinux.h \
		&& echo "ERROR: pixie/stirling references found" && exit 1 \
		|| echo "clean: no pixie references"
