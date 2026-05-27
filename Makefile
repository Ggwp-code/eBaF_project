CLANG ?= clang
CC ?= cc
BPFTOOL ?= bpftool
CFLAGS ?= -O2 -g -Wall -Wextra -Werror
BPF_CFLAGS ?= -O2 -g -target bpf -D__TARGET_ARCH_x86
BUILD_DIR := build
VMLINUX := $(BUILD_DIR)/vmlinux.h

USER_SRCS := src/user/main.c src/user/config.c src/user/bpf_loader.c
USER_OBJS := $(USER_SRCS:src/user/%.c=$(BUILD_DIR)/%.o)
BPF_SRCS := src/bpf/crypto_ctx.bpf.c src/bpf/xdp_crypto.bpf.c
BPF_OBJS := $(BPF_SRCS:src/bpf/%.c=$(BUILD_DIR)/%.o)
SKELS := $(BPF_OBJS:$(BUILD_DIR)/%.o=$(BUILD_DIR)/%.skel.h)

.PHONY: all check test integration-test correctness-test benchmark-smoke demo-smoke experiment clean

all: $(BUILD_DIR)/ebaf-crypto

check:
	./scripts/check_kernel_features.sh

test: $(BUILD_DIR)/test_config $(BUILD_DIR)/test_event_format $(BUILD_DIR)/test_stats_format
	./$(BUILD_DIR)/test_config
	./$(BUILD_DIR)/test_event_format
	./$(BUILD_DIR)/test_stats_format

integration-test: $(BUILD_DIR)/ebaf-crypto
	@tests/integration/test_xdp_smoke.sh; status=$$?; \
	if [ $$status -eq 77 ]; then exit 0; fi; \
	exit $$status

correctness-test: $(BUILD_DIR)/ebaf-crypto
	@tests/integration/test_crypto_correctness.sh; status=$$?; \
	if [ $$status -eq 77 ]; then exit 0; fi; \
	exit $$status

benchmark-smoke: $(BUILD_DIR)/ebaf-crypto
	@scripts/bench_smoke.sh; status=$$?; \
	if [ $$status -eq 77 ]; then exit 0; fi; \
	exit $$status

demo-smoke: $(BUILD_DIR)/ebaf-crypto
	@tests/integration/test_demo_runner.sh; status=$$?; \
	if [ $$status -eq 77 ]; then exit 0; fi; \
	exit $$status

experiment:
	python3 scripts/run_experiment.py --out experiments/latest.json --repeat 3
	python3 scripts/analyze_experiment.py experiments/latest.json

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(VMLINUX): | $(BUILD_DIR)
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(BUILD_DIR)/%.o: src/bpf/%.c $(VMLINUX) include/crypto_common.h | $(BUILD_DIR)
	$(CLANG) $(BPF_CFLAGS) -I$(BUILD_DIR) -Iinclude -c $< -o $@

$(BUILD_DIR)/%.skel.h: $(BUILD_DIR)/%.o
	$(BPFTOOL) gen skeleton $< > $@

$(BUILD_DIR)/%.o: src/user/%.c $(SKELS) include/crypto_common.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -Iinclude -I$(BUILD_DIR) -c $< -o $@

$(BUILD_DIR)/ebaf-crypto: $(USER_OBJS)
	$(CC) $(CFLAGS) $^ -lbpf -lelf -lz -o $@

$(BUILD_DIR)/test_config: tests/unit/test_config.c src/user/config.c src/user/config.h include/crypto_common.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -Iinclude -Isrc/user tests/unit/test_config.c src/user/config.c -o $@

$(BUILD_DIR)/test_event_format: tests/unit/test_event_format.c src/user/event_format.c src/user/event_format.h include/crypto_common.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -Iinclude -Isrc/user tests/unit/test_event_format.c src/user/event_format.c -o $@

$(BUILD_DIR)/test_stats_format: tests/unit/test_stats_format.c src/user/stats_format.c src/user/stats_format.h include/crypto_common.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -Iinclude -Isrc/user tests/unit/test_stats_format.c src/user/stats_format.c -o $@

clean:
	rm -rf $(BUILD_DIR)
