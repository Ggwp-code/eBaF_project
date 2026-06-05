CLANG ?= clang
CC ?= cc
BPFTOOL ?= bpftool
CFLAGS ?= -O2 -g -Wall -Wextra -Werror
BPF_ARCH ?= x86
BPF_CFLAGS ?= -O2 -g -target bpf -D__TARGET_ARCH_$(BPF_ARCH)
PORT ?= 7777
COUNT ?= 8
BUILD_DIR := build
VMLINUX := $(BUILD_DIR)/vmlinux.h

USER_SRCS := src/user/main.c src/user/config.c src/user/bpf_loader.c src/user/event_format.c src/user/stats_format.c
USER_OBJS := $(USER_SRCS:src/user/%.c=$(BUILD_DIR)/%.o)
BPF_SRCS := src/bpf/crypto_ctx.bpf.c src/bpf/xdp_crypto.bpf.c src/bpf/tc_crypto.bpf.c src/bpf/tc_transparent.bpf.c
BPF_OBJS := $(BPF_SRCS:src/bpf/%.c=$(BUILD_DIR)/%.o)
SKELS := $(BPF_OBJS:$(BUILD_DIR)/%.o=$(BUILD_DIR)/%.skel.h)
XDP_PROBE_OBJ := $(BUILD_DIR)/xdp_probe.bpf.o

.PHONY: all check test integration-test correctness-test protocol-validation-test benchmark-smoke demo-smoke experiment packet-proof physical-profile physical-tc-demo tc-chat-test tc-chat-benchmark tc-transparent-test backend-gate clean

all: $(BUILD_DIR)/ebaf-crypto $(BUILD_DIR)/udp-bench-sender

check:
	./scripts/check_kernel_features.sh

test: $(BUILD_DIR)/test_config $(BUILD_DIR)/test_event_format $(BUILD_DIR)/test_stats_format
	./$(BUILD_DIR)/test_config
	./$(BUILD_DIR)/test_event_format
	./$(BUILD_DIR)/test_stats_format
	python3 -m unittest tests.unit.test_experiment_tools
	python3 -m unittest tests.unit.test_packet_proof
	tests/unit/test_physical_profile.sh
	bash tests/unit/test_physical_tc_demo.sh

integration-test: $(BUILD_DIR)/ebaf-crypto
	@tests/integration/test_xdp_smoke.sh; status=$$?; \
	if [ $$status -eq 77 ]; then exit 0; fi; \
	exit $$status

correctness-test: $(BUILD_DIR)/ebaf-crypto
	@tests/integration/test_crypto_correctness.sh; status=$$?; \
	if [ $$status -eq 77 ]; then exit 0; fi; \
	exit $$status

protocol-validation-test: $(BUILD_DIR)/ebaf-crypto
	@tests/integration/test_protocol_validation.sh; status=$$?; \
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

tc-chat-test: $(BUILD_DIR)/ebaf-crypto
	@tests/integration/test_tc_udp_chat.sh; status=$$?; \
	if [ $$status -eq 77 ]; then exit 0; fi; \
	exit $$status

tc-chat-benchmark: $(BUILD_DIR)/ebaf-crypto
	@tests/integration/test_tc_udp_benchmark.sh; status=$$?; \
	if [ $$status -eq 77 ]; then exit 0; fi; \
	exit $$status

tc-transparent-test: $(BUILD_DIR)/ebaf-crypto
	@bash tests/integration/test_tc_transparent_udp.sh; status=$$?; \
	if [ $$status -eq 77 ]; then exit 0; fi; \
	exit $$status

experiment:
	python3 scripts/run_experiment.py --out experiments/latest.json --repeat 3
	python3 scripts/analyze_experiment.py experiments/latest.json experiments/latest.csv

packet-proof: $(BUILD_DIR)/ebaf-crypto
	@python3 scripts/packet_proof.py --out experiments/packet-proof.json; status=$$?; \
	if [ $$status -eq 77 ]; then exit 0; fi; \
	exit $$status

physical-profile: $(XDP_PROBE_OBJ)
	@if [ -z "$(IFACE)" ]; then echo "usage: make physical-profile IFACE=<interface>" >&2; exit 2; fi
	@scripts/physical_profile.sh "$(IFACE)"; status=$$?; \
	if [ $$status -eq 77 ]; then exit 0; fi; \
	exit $$status

physical-tc-demo: $(BUILD_DIR)/ebaf-crypto
	@if [ -z "$(IFACE)" ] || [ -z "$(PEER_IP)" ]; then echo "usage: make physical-tc-demo IFACE=<interface> PEER_IP=<ip> [PORT=7777] [COUNT=8]" >&2; exit 2; fi
	@IFACE="$(IFACE)" PEER_IP="$(PEER_IP)" PORT="$(PORT)" COUNT="$(COUNT)" bash scripts/physical_tc_demo.sh; status=$$?; \
	if [ $$status -eq 77 ]; then exit 0; fi; \
	exit $$status

backend-gate: all check test integration-test correctness-test protocol-validation-test tc-chat-test tc-transparent-test tc-chat-benchmark benchmark-smoke packet-proof experiment

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(VMLINUX): | $(BUILD_DIR)
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(BUILD_DIR)/%.o: src/bpf/%.c $(VMLINUX) include/crypto_common.h | $(BUILD_DIR)
	$(CLANG) $(BPF_CFLAGS) -I$(BUILD_DIR) -Iinclude -c $< -o $@

$(XDP_PROBE_OBJ): src/bpf/xdp_probe.bpf.c $(VMLINUX) | $(BUILD_DIR)
	$(CLANG) $(BPF_CFLAGS) -I$(BUILD_DIR) -c $< -o $@

$(BUILD_DIR)/%.skel.h: $(BUILD_DIR)/%.o
	$(BPFTOOL) gen skeleton $< > $@

$(BUILD_DIR)/%.o: src/user/%.c $(SKELS) include/crypto_common.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -Iinclude -I$(BUILD_DIR) -c $< -o $@

$(BUILD_DIR)/ebaf-crypto: $(USER_OBJS)
	$(CC) $(CFLAGS) $^ -lbpf -lelf -lz -o $@

$(BUILD_DIR)/udp-bench-sender: tools/udp_bench_sender.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $< -o $@

$(BUILD_DIR)/test_config: tests/unit/test_config.c src/user/config.c src/user/config.h include/crypto_common.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -Iinclude -Isrc/user tests/unit/test_config.c src/user/config.c -o $@

$(BUILD_DIR)/test_event_format: tests/unit/test_event_format.c src/user/event_format.c src/user/event_format.h include/crypto_common.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -Iinclude -Isrc/user tests/unit/test_event_format.c src/user/event_format.c -o $@

$(BUILD_DIR)/test_stats_format: tests/unit/test_stats_format.c src/user/stats_format.c src/user/stats_format.h include/crypto_common.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -Iinclude -Isrc/user tests/unit/test_stats_format.c src/user/stats_format.c -o $@

clean:
	rm -rf $(BUILD_DIR)
