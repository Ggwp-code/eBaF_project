# eBPF XDP Cryptography Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a greenfield Linux eBPF/XDP in-network cryptography prototype that creates a kernel crypto context in a syscall BPF program, shares it through a referenced kptr map, and encrypts or decrypts packet payloads in an XDP data plane.

**Architecture:** The repository uses libbpf CO-RE C for BPF programs and a small C user-space control plane. The control plane probes kernel capabilities, loads BPF skeletons, creates crypto context state through `BPF_PROG_TYPE_SYSCALL`, attaches XDP to an interface, exposes counters, and provides scripts for namespace smoke testing and benchmarking. Documentation captures verifier constraints, packet format, operations, and performance expectations from the source PDF.

**Tech Stack:** Linux kernel with BTF and BPF crypto kfunc support, LLVM/Clang, libbpf, bpftool, make, C11, shell, network namespaces, XDP.

---

## Source Spec

- PDF: `Advanced In-Network Cryptography via eBPF and XDP_ A Comprehensive Analysis of Architectures, Verifier Constraints, and Performance Optimization.pdf`
- Key requirements extracted from PDF:
  - Use XDP for fast packet ingress before `sk_buff` allocation.
  - Use a syscall BPF program for crypto context creation because allocation can sleep.
  - Store crypto context in an eBPF map through a referenced kernel pointer.
  - Use dynptrs for verifier-safe packet buffer access.
  - Use `bpf_crypto_encrypt()` and `bpf_crypto_decrypt()` kfuncs in the data plane.
  - Avoid dynamic loops, large stack use, and unchecked packet pointer access.
  - Include verifier debug workflow with `bpftool`.
  - Include benchmark workflow measuring throughput, latency, drops, and CPU.
  - Document SmartNIC/QAT/PQC as future hardware acceleration paths, not first implementation.

## File Structure

- Create: `.gitignore` - build artifacts, generated skeletons, benchmark output, editor files.
- Create: `README.md` - project purpose, prerequisites, quick start, safety notes.
- Create: `Makefile` - builds BPF objects, generates skeletons, builds user daemon, runs tests.
- Create: `include/crypto_common.h` - shared constants, packet header, map value structs, stats structs.
- Create: `src/bpf/crypto_ctx.bpf.c` - syscall BPF program that creates and stores crypto context.
- Create: `src/bpf/xdp_crypto.bpf.c` - XDP BPF program that parses packets and encrypts/decrypts payload.
- Create: `src/user/config.h` - user-space config type and parser API.
- Create: `src/user/config.c` - user-space argument parser and key parsing.
- Create: `src/user/bpf_loader.h` - BPF load/attach API.
- Create: `src/user/bpf_loader.c` - libbpf skeleton open/load/attach/detach logic.
- Create: `src/user/main.c` - CLI daemon entrypoint and signal handling.
- Create: `tests/unit/test_config.c` - unit tests for config parsing and hex key parsing.
- Create: `tests/integration/run_namespace_smoke.sh` - veth namespace smoke test.
- Create: `scripts/check_kernel_features.sh` - kernel/BTF/kfunc prerequisite check.
- Create: `scripts/bench_xdp_crypto.sh` - benchmark runner and output collector.
- Create: `docs/architecture.md` - design, packet flow, maps, verifier rules.
- Create: `docs/operations.md` - setup, run, debug, cleanup.
- Create: `docs/benchmarking.md` - metrics, commands, acceptance thresholds.

## Task 1: Repository Skeleton

**Files:**
- Create: `.gitignore`
- Create: `README.md`
- Create: `Makefile`
- Create: `include/crypto_common.h`
- Create: `src/bpf/.gitkeep`
- Create: `src/user/.gitkeep`
- Create: `tests/unit/.gitkeep`
- Create: `tests/integration/.gitkeep`
- Create: `scripts/.gitkeep`
- Create: `docs/.gitkeep`

- [ ] **Step 1: Write skeleton files**

Create `.gitignore`:

```gitignore
build/
*.o
*.skel.h
*.ll
*.log
*.out
*.pcap
compile_commands.json
.cache/
.clangd/
```

Create `README.md`:

````markdown
# eBPF XDP Cryptography Prototype

This project implements an in-network cryptography prototype with eBPF and XDP.

## Requirements

- Linux kernel with BTF enabled
- BPF crypto kfunc support
- clang and llc from LLVM
- libbpf development headers
- bpftool
- make

## Quick Start

```bash
make check
make
sudo ./build/ebaf-crypto --iface eth0 --mode decrypt --key 000102030405060708090a0b0c0d0e0f
```

## Safety

Run first inside a network namespace or lab host. XDP programs can drop or modify live traffic.
````

Create `include/crypto_common.h`:

```c
#ifndef CRYPTO_COMMON_H
#define CRYPTO_COMMON_H

#include <linux/types.h>

#define EBAF_CRYPTO_KEY_BYTES 16
#define EBAF_CRYPTO_IV_BYTES 16
#define EBAF_CRYPTO_MAGIC 0x45424146u
#define EBAF_CRYPTO_VERSION 1
#define EBAF_ACTION_PASS 0
#define EBAF_ACTION_ENCRYPT 1
#define EBAF_ACTION_DECRYPT 2

struct ebaf_crypto_header {
	__be32 magic;
	__u8 version;
	__u8 action;
	__u16 payload_len;
	__u8 iv[EBAF_CRYPTO_IV_BYTES];
};

struct ebaf_crypto_config {
	__u8 key[EBAF_CRYPTO_KEY_BYTES];
	__u32 key_len;
	__u32 action;
};

struct ebaf_crypto_stats {
	__u64 packets_seen;
	__u64 packets_passed;
	__u64 packets_crypto_ok;
	__u64 packets_crypto_fail;
	__u64 packets_malformed;
};

struct ebaf_crypto_ctx_slot {
	struct bpf_crypto_ctx __kptr *ctx;
};

#endif
```

Create `Makefile`:

```makefile
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

.PHONY: all check test clean

all: $(BUILD_DIR)/ebaf-crypto

check:
	./scripts/check_kernel_features.sh

test: $(BUILD_DIR)/test_config
	./$(BUILD_DIR)/test_config

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

clean:
	rm -rf $(BUILD_DIR)
```

Create empty keep files:

```bash
mkdir -p include src/bpf src/user tests/unit tests/integration scripts docs
touch src/bpf/.gitkeep src/user/.gitkeep tests/unit/.gitkeep tests/integration/.gitkeep scripts/.gitkeep docs/.gitkeep
```

- [ ] **Step 2: Verify skeleton file list**

Run:

```bash
find . -maxdepth 3 -type f | sort
```

Expected output includes:

```text
./.gitignore
./Makefile
./README.md
./include/crypto_common.h
./src/bpf/.gitkeep
./src/user/.gitkeep
./tests/unit/.gitkeep
```

- [ ] **Step 3: Initialize git repository when needed**

Run:

```bash
git rev-parse --is-inside-work-tree || git init
```

Expected in this folder before first commit:

```text
Initialized empty Git repository
```

- [ ] **Step 4: Commit**

```bash
git add .gitignore README.md Makefile include/crypto_common.h src tests scripts docs
git commit -m "chore: scaffold ebpf xdp crypto project"
```

## Task 2: Kernel Feature Probe

**Files:**
- Create: `scripts/check_kernel_features.sh`
- Modify: `README.md`

- [ ] **Step 1: Write kernel feature probe**

Create `scripts/check_kernel_features.sh`:

```sh
#!/usr/bin/env sh
set -eu

fail() {
	printf 'FAIL: %s\n' "$1" >&2
	exit 1
}

pass() {
	printf 'PASS: %s\n' "$1"
}

[ -r /sys/kernel/btf/vmlinux ] || fail 'missing /sys/kernel/btf/vmlinux; enable CONFIG_DEBUG_INFO_BTF'
pass 'BTF available'

command -v clang >/dev/null 2>&1 || fail 'clang not found'
pass 'clang available'

command -v bpftool >/dev/null 2>&1 || fail 'bpftool not found'
pass 'bpftool available'

command -v ip >/dev/null 2>&1 || fail 'iproute2 ip command not found'
pass 'ip command available'

if bpftool btf dump file /sys/kernel/btf/vmlinux format raw | grep -q 'bpf_crypto_encrypt'; then
	pass 'bpf_crypto_encrypt kfunc visible in BTF'
else
	fail 'bpf_crypto_encrypt kfunc not visible in BTF; use a kernel with BPF crypto kfunc support'
fi

if bpftool btf dump file /sys/kernel/btf/vmlinux format raw | grep -q 'bpf_dynptr_from_xdp'; then
	pass 'bpf_dynptr_from_xdp kfunc visible in BTF'
else
	fail 'bpf_dynptr_from_xdp kfunc not visible in BTF'
fi
```

Modify `README.md` requirements section:

````markdown
## Requirements

- Linux kernel with BTF enabled
- BPF crypto kfunc support visible through `/sys/kernel/btf/vmlinux`
- clang and llc from LLVM
- libbpf development headers
- bpftool
- iproute2
- make

Run `make check` before building. The probe fails fast when the running kernel cannot load this prototype.
````

- [ ] **Step 2: Make probe executable**

Run:

```bash
chmod +x scripts/check_kernel_features.sh
```

Expected: no output.

- [ ] **Step 3: Run probe**

Run:

```bash
./scripts/check_kernel_features.sh
```

Expected on supported kernel:

```text
PASS: BTF available
PASS: clang available
PASS: bpftool available
PASS: ip command available
PASS: bpf_crypto_encrypt kfunc visible in BTF
PASS: bpf_dynptr_from_xdp kfunc visible in BTF
```

Expected on unsupported kernel:

```text
FAIL: bpf_crypto_encrypt kfunc not visible in BTF; use a kernel with BPF crypto kfunc support
```

- [ ] **Step 4: Commit**

```bash
git add README.md scripts/check_kernel_features.sh
git commit -m "chore: add kernel capability probe"
```

## Task 3: User Config Parser

**Files:**
- Create: `src/user/config.h`
- Create: `src/user/config.c`
- Create: `tests/unit/test_config.c`

- [ ] **Step 1: Write failing config tests**

Create `tests/unit/test_config.c`:

```c
#include <stdio.h>
#include <string.h>

#include "config.h"
#include "crypto_common.h"

static int failures;

static void expect_int(const char *name, int got, int want)
{
	if (got != want) {
		fprintf(stderr, "%s: got %d want %d\n", name, got, want);
		failures++;
	}
}

static void expect_str(const char *name, const char *got, const char *want)
{
	if (strcmp(got, want) != 0) {
		fprintf(stderr, "%s: got %s want %s\n", name, got, want);
		failures++;
	}
}

static void test_parse_decrypt_args(void)
{
	char *argv[] = {
		"ebaf-crypto",
		"--iface", "veth0",
		"--mode", "decrypt",
		"--key", "000102030405060708090a0b0c0d0e0f",
	};
	struct ebaf_user_config cfg;
	int rc = ebaf_parse_args(7, argv, &cfg);

	expect_int("parse decrypt rc", rc, 0);
	expect_str("iface", cfg.iface, "veth0");
	expect_int("action", cfg.crypto.action, EBAF_ACTION_DECRYPT);
	expect_int("key len", cfg.crypto.key_len, EBAF_CRYPTO_KEY_BYTES);
	expect_int("first key byte", cfg.crypto.key[0], 0x00);
	expect_int("last key byte", cfg.crypto.key[15], 0x0f);
}

static void test_parse_encrypt_args(void)
{
	char *argv[] = {
		"ebaf-crypto",
		"--iface", "veth1",
		"--mode", "encrypt",
		"--key", "101112131415161718191a1b1c1d1e1f",
	};
	struct ebaf_user_config cfg;
	int rc = ebaf_parse_args(7, argv, &cfg);

	expect_int("parse encrypt rc", rc, 0);
	expect_str("iface", cfg.iface, "veth1");
	expect_int("action", cfg.crypto.action, EBAF_ACTION_ENCRYPT);
	expect_int("first key byte", cfg.crypto.key[0], 0x10);
	expect_int("last key byte", cfg.crypto.key[15], 0x1f);
}

static void test_reject_short_key(void)
{
	char *argv[] = {
		"ebaf-crypto",
		"--iface", "veth0",
		"--mode", "decrypt",
		"--key", "0011",
	};
	struct ebaf_user_config cfg;
	int rc = ebaf_parse_args(7, argv, &cfg);

	expect_int("short key rejected", rc, -1);
}

static void test_reject_bad_mode(void)
{
	char *argv[] = {
		"ebaf-crypto",
		"--iface", "veth0",
		"--mode", "sign",
		"--key", "000102030405060708090a0b0c0d0e0f",
	};
	struct ebaf_user_config cfg;
	int rc = ebaf_parse_args(7, argv, &cfg);

	expect_int("bad mode rejected", rc, -1);
}

int main(void)
{
	test_parse_decrypt_args();
	test_parse_encrypt_args();
	test_reject_short_key();
	test_reject_bad_mode();

	if (failures != 0) {
		fprintf(stderr, "%d config tests failed\n", failures);
		return 1;
	}

	puts("config tests passed");
	return 0;
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
make test
```

Expected: FAIL with compiler error containing:

```text
fatal error: config.h: No such file or directory
```

- [ ] **Step 3: Write config parser**

Create `src/user/config.h`:

```c
#ifndef EBAF_USER_CONFIG_H
#define EBAF_USER_CONFIG_H

#include <stddef.h>

#include "crypto_common.h"

#define EBAF_IFACE_NAME_MAX 64

struct ebaf_user_config {
	char iface[EBAF_IFACE_NAME_MAX];
	struct ebaf_crypto_config crypto;
};

int ebaf_parse_args(int argc, char **argv, struct ebaf_user_config *cfg);
int ebaf_parse_hex_key(const char *hex, unsigned char *out, size_t out_len);

#endif
```

Create `src/user/config.c`:

```c
#include "config.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

static int hex_value(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

int ebaf_parse_hex_key(const char *hex, unsigned char *out, size_t out_len)
{
	size_t hex_len;

	if (!hex || !out)
		return -1;

	hex_len = strlen(hex);
	if (hex_len != out_len * 2)
		return -1;

	for (size_t i = 0; i < out_len; i++) {
		int hi = hex_value(hex[i * 2]);
		int lo = hex_value(hex[i * 2 + 1]);

		if (hi < 0 || lo < 0)
			return -1;
		out[i] = (unsigned char)((hi << 4) | lo);
	}

	return 0;
}

int ebaf_parse_args(int argc, char **argv, struct ebaf_user_config *cfg)
{
	const char *iface = NULL;
	const char *mode = NULL;
	const char *key = NULL;

	if (!cfg)
		return -1;

	memset(cfg, 0, sizeof(*cfg));

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--iface") == 0 && i + 1 < argc) {
			iface = argv[++i];
		} else if (strcmp(argv[i], "--mode") == 0 && i + 1 < argc) {
			mode = argv[++i];
		} else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) {
			key = argv[++i];
		} else {
			return -1;
		}
	}

	if (!iface || !mode || !key)
		return -1;
	if (strlen(iface) >= sizeof(cfg->iface))
		return -1;

	strcpy(cfg->iface, iface);

	if (strcmp(mode, "encrypt") == 0)
		cfg->crypto.action = EBAF_ACTION_ENCRYPT;
	else if (strcmp(mode, "decrypt") == 0)
		cfg->crypto.action = EBAF_ACTION_DECRYPT;
	else
		return -1;

	if (ebaf_parse_hex_key(key, cfg->crypto.key, EBAF_CRYPTO_KEY_BYTES) != 0)
		return -1;

	cfg->crypto.key_len = EBAF_CRYPTO_KEY_BYTES;
	return 0;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run:

```bash
make test
```

Expected:

```text
config tests passed
```

- [ ] **Step 5: Commit**

```bash
git add src/user/config.h src/user/config.c tests/unit/test_config.c Makefile
git commit -m "test: add user config parser"
```

## Task 4: Syscall BPF Crypto Context Program

**Files:**
- Create: `src/bpf/crypto_ctx.bpf.c`
- Modify: `include/crypto_common.h`

- [ ] **Step 1: Write syscall BPF program**

Create `src/bpf/crypto_ctx.bpf.c`:

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "crypto_common.h"

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct ebaf_crypto_config);
} crypto_config SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct ebaf_crypto_ctx_slot);
} crypto_ctx_map SEC(".maps");

extern struct bpf_crypto_ctx *bpf_crypto_ctx_create(const struct bpf_crypto_params *params,
						    __u32 params__sz,
						    int *err) __ksym;
extern void bpf_crypto_ctx_release(struct bpf_crypto_ctx *ctx) __ksym;

SEC("syscall")
int create_crypto_ctx(void *ctx)
{
	__u32 key = 0;
	struct ebaf_crypto_config *config;
	struct ebaf_crypto_ctx_slot *slot;
	struct bpf_crypto_ctx *new_ctx;
	struct bpf_crypto_ctx *old_ctx;
	struct bpf_crypto_params params = {};
	int err = 0;

	config = bpf_map_lookup_elem(&crypto_config, &key);
	if (!config)
		return -1;
	if (config->key_len != EBAF_CRYPTO_KEY_BYTES)
		return -2;

	params.type = "skcipher";
	params.algo = "ecb(aes)";
	params.key = config->key;
	params.key_len = config->key_len;

	new_ctx = bpf_crypto_ctx_create(&params, sizeof(params), &err);
	if (!new_ctx)
		return err ? err : -3;

	slot = bpf_map_lookup_elem(&crypto_ctx_map, &key);
	if (!slot) {
		bpf_crypto_ctx_release(new_ctx);
		return -4;
	}

	old_ctx = bpf_kptr_xchg(&slot->ctx, new_ctx);
	if (old_ctx)
		bpf_crypto_ctx_release(old_ctx);

	return 0;
}
```

- [ ] **Step 2: Compile BPF object**

Run:

```bash
make build/crypto_ctx.bpf.o
```

Expected on supported kernel:

```text
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -Ibuild -Iinclude -c src/bpf/crypto_ctx.bpf.c -o build/crypto_ctx.bpf.o
```

Expected on unsupported headers: compiler error naming missing `struct bpf_crypto_params` or missing kfunc symbol. Use Task 2 output to confirm kernel support before editing code.

- [ ] **Step 3: Generate skeleton**

Run:

```bash
make build/crypto_ctx.bpf.skel.h
```

Expected:

```text
bpftool gen skeleton build/crypto_ctx.bpf.o > build/crypto_ctx.bpf.skel.h
```

- [ ] **Step 4: Commit**

```bash
git add src/bpf/crypto_ctx.bpf.c include/crypto_common.h Makefile
git commit -m "feat: add syscall crypto context bpf program"
```

## Task 5: XDP Data Plane Program

**Files:**
- Create: `src/bpf/xdp_crypto.bpf.c`
- Modify: `include/crypto_common.h`

- [ ] **Step 1: Write XDP program**

Create `src/bpf/xdp_crypto.bpf.c`:

```c
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "crypto_common.h"

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct ebaf_crypto_config);
} crypto_config SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct ebaf_crypto_ctx_slot);
} crypto_ctx_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct ebaf_crypto_stats);
} crypto_stats SEC(".maps");

extern int bpf_dynptr_from_xdp(struct xdp_md *xdp, __u64 flags, struct bpf_dynptr *ptr__uninit) __ksym;
extern int bpf_crypto_encrypt(struct bpf_crypto_ctx *ctx,
			      const struct bpf_dynptr *src,
			      struct bpf_dynptr *dst,
			      const struct bpf_dynptr *iv) __ksym;
extern int bpf_crypto_decrypt(struct bpf_crypto_ctx *ctx,
			      const struct bpf_dynptr *src,
			      struct bpf_dynptr *dst,
			      const struct bpf_dynptr *iv) __ksym;

static __always_inline void stat_inc(__u64 *counter)
{
	if (counter)
		__sync_fetch_and_add(counter, 1);
}

SEC("xdp")
int xdp_crypto(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ebaf_crypto_header *hdr = data;
	struct ebaf_crypto_ctx_slot *slot;
	struct ebaf_crypto_config *config;
	struct ebaf_crypto_stats *stats;
	struct bpf_dynptr pkt;
	struct bpf_dynptr iv;
	__u32 zero = 0;
	int rc;

	stats = bpf_map_lookup_elem(&crypto_stats, &zero);
	if (stats)
		stat_inc(&stats->packets_seen);

	if ((void *)(hdr + 1) > data_end) {
		if (stats)
			stat_inc(&stats->packets_malformed);
		return XDP_PASS;
	}

	if (hdr->magic != bpf_htonl(EBAF_CRYPTO_MAGIC) || hdr->version != EBAF_CRYPTO_VERSION) {
		if (stats)
			stat_inc(&stats->packets_passed);
		return XDP_PASS;
	}

	config = bpf_map_lookup_elem(&crypto_config, &zero);
	if (!config) {
		if (stats)
			stat_inc(&stats->packets_crypto_fail);
		return XDP_PASS;
	}

	slot = bpf_map_lookup_elem(&crypto_ctx_map, &zero);
	if (!slot || !slot->ctx) {
		if (stats)
			stat_inc(&stats->packets_crypto_fail);
		return XDP_PASS;
	}

	rc = bpf_dynptr_from_xdp(ctx, 0, &pkt);
	if (rc != 0) {
		if (stats)
			stat_inc(&stats->packets_crypto_fail);
		return XDP_PASS;
	}

	rc = bpf_dynptr_from_mem(hdr->iv, EBAF_CRYPTO_IV_BYTES, 0, &iv);
	if (rc != 0) {
		if (stats)
			stat_inc(&stats->packets_crypto_fail);
		return XDP_PASS;
	}

	if (config->action == EBAF_ACTION_ENCRYPT)
		rc = bpf_crypto_encrypt(slot->ctx, &pkt, &pkt, &iv);
	else if (config->action == EBAF_ACTION_DECRYPT)
		rc = bpf_crypto_decrypt(slot->ctx, &pkt, &pkt, &iv);
	else
		rc = -1;

	if (rc == 0) {
		if (stats)
			stat_inc(&stats->packets_crypto_ok);
	} else {
		if (stats)
			stat_inc(&stats->packets_crypto_fail);
	}

	return XDP_PASS;
}
```

- [ ] **Step 2: Compile XDP object**

Run:

```bash
make build/xdp_crypto.bpf.o
```

Expected:

```text
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -Ibuild -Iinclude -c src/bpf/xdp_crypto.bpf.c -o build/xdp_crypto.bpf.o
```

- [ ] **Step 3: Generate XDP skeleton**

Run:

```bash
make build/xdp_crypto.bpf.skel.h
```

Expected:

```text
bpftool gen skeleton build/xdp_crypto.bpf.o > build/xdp_crypto.bpf.skel.h
```

- [ ] **Step 4: Commit**

```bash
git add src/bpf/xdp_crypto.bpf.c include/crypto_common.h Makefile
git commit -m "feat: add xdp crypto data plane"
```

## Task 6: User-Space Loader

**Files:**
- Create: `src/user/bpf_loader.h`
- Create: `src/user/bpf_loader.c`
- Create: `src/user/main.c`

- [ ] **Step 1: Write loader header**

Create `src/user/bpf_loader.h`:

```c
#ifndef EBAF_BPF_LOADER_H
#define EBAF_BPF_LOADER_H

#include "config.h"

struct ebaf_bpf_runtime {
	int ifindex;
	int xdp_prog_fd;
	int stats_map_fd;
	int config_map_fd;
};

int ebaf_bpf_start(const struct ebaf_user_config *cfg, struct ebaf_bpf_runtime *rt);
void ebaf_bpf_stop(const struct ebaf_user_config *cfg, struct ebaf_bpf_runtime *rt);
int ebaf_bpf_print_stats(const struct ebaf_bpf_runtime *rt);

#endif
```

- [ ] **Step 2: Write loader implementation**

Create `src/user/bpf_loader.c`:

```c
#include "bpf_loader.h"

#include <errno.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "crypto_common.h"
#include "crypto_ctx.bpf.skel.h"
#include "xdp_crypto.bpf.skel.h"

static struct crypto_ctx_bpf *ctx_skel;
static struct xdp_crypto_bpf *xdp_skel;

int ebaf_bpf_start(const struct ebaf_user_config *cfg, struct ebaf_bpf_runtime *rt)
{
	__u32 key = 0;
	LIBBPF_OPTS(bpf_test_run_opts, run_opts);
	int rc;

	if (!cfg || !rt)
		return -1;
	memset(rt, 0, sizeof(*rt));

	rt->ifindex = if_nametoindex(cfg->iface);
	if (rt->ifindex == 0) {
		fprintf(stderr, "if_nametoindex(%s): %s\n", cfg->iface, strerror(errno));
		return -1;
	}

	ctx_skel = crypto_ctx_bpf__open_and_load();
	if (!ctx_skel) {
		fprintf(stderr, "failed to load crypto_ctx skeleton\n");
		return -1;
	}

	xdp_skel = xdp_crypto_bpf__open();
	if (!xdp_skel) {
		fprintf(stderr, "failed to open xdp_crypto skeleton\n");
		return -1;
	}

	rc = bpf_map__reuse_fd(xdp_skel->maps.crypto_config,
			       bpf_map__fd(ctx_skel->maps.crypto_config));
	if (rc != 0) {
		fprintf(stderr, "failed to share crypto_config map\n");
		return -1;
	}

	rc = bpf_map__reuse_fd(xdp_skel->maps.crypto_ctx_map,
			       bpf_map__fd(ctx_skel->maps.crypto_ctx_map));
	if (rc != 0) {
		fprintf(stderr, "failed to share crypto_ctx_map map\n");
		return -1;
	}

	rc = xdp_crypto_bpf__load(xdp_skel);
	if (rc != 0) {
		fprintf(stderr, "failed to load xdp_crypto skeleton\n");
		return -1;
	}

	rt->config_map_fd = bpf_map__fd(ctx_skel->maps.crypto_config);
	rc = bpf_map_update_elem(rt->config_map_fd, &key, &cfg->crypto, BPF_ANY);
	if (rc != 0) {
		fprintf(stderr, "failed to update crypto config map: %s\n", strerror(errno));
		return -1;
	}

	rc = bpf_prog_test_run_opts(bpf_program__fd(ctx_skel->progs.create_crypto_ctx), &run_opts);
	if (rc != 0) {
		fprintf(stderr, "failed to run crypto context syscall program: %s\n", strerror(errno));
		return -1;
	}

	rt->xdp_prog_fd = bpf_program__fd(xdp_skel->progs.xdp_crypto);
	rc = bpf_xdp_attach(rt->ifindex, rt->xdp_prog_fd, XDP_FLAGS_DRV_MODE, NULL);
	if (rc != 0) {
		fprintf(stderr, "driver XDP attach failed: %s\n", strerror(errno));
		fprintf(stderr, "retrying generic XDP mode\n");
		rc = bpf_xdp_attach(rt->ifindex, rt->xdp_prog_fd, XDP_FLAGS_SKB_MODE, NULL);
	}
	if (rc != 0) {
		fprintf(stderr, "generic XDP attach failed: %s\n", strerror(errno));
		return -1;
	}

	rt->stats_map_fd = bpf_map__fd(xdp_skel->maps.crypto_stats);
	return 0;
}

void ebaf_bpf_stop(const struct ebaf_user_config *cfg, struct ebaf_bpf_runtime *rt)
{
	if (cfg && rt && rt->ifindex > 0)
		bpf_xdp_detach(rt->ifindex, XDP_FLAGS_DRV_MODE, NULL);
	if (cfg && rt && rt->ifindex > 0)
		bpf_xdp_detach(rt->ifindex, XDP_FLAGS_SKB_MODE, NULL);

	xdp_crypto_bpf__destroy(xdp_skel);
	crypto_ctx_bpf__destroy(ctx_skel);

	xdp_skel = NULL;
	ctx_skel = NULL;
}

int ebaf_bpf_print_stats(const struct ebaf_bpf_runtime *rt)
{
	struct ebaf_crypto_stats values[128];
	struct ebaf_crypto_stats total = {};
	__u32 key = 0;
	int rc;

	if (!rt || rt->stats_map_fd < 0)
		return -1;

	memset(values, 0, sizeof(values));
	rc = bpf_map_lookup_elem(rt->stats_map_fd, &key, values);
	if (rc != 0)
		return -1;

	for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++) {
		total.packets_seen += values[i].packets_seen;
		total.packets_passed += values[i].packets_passed;
		total.packets_crypto_ok += values[i].packets_crypto_ok;
		total.packets_crypto_fail += values[i].packets_crypto_fail;
		total.packets_malformed += values[i].packets_malformed;
	}

	printf("seen=%llu passed=%llu crypto_ok=%llu crypto_fail=%llu malformed=%llu\n",
	       (unsigned long long)total.packets_seen,
	       (unsigned long long)total.packets_passed,
	       (unsigned long long)total.packets_crypto_ok,
	       (unsigned long long)total.packets_crypto_fail,
	       (unsigned long long)total.packets_malformed);
	return 0;
}
```

- [ ] **Step 3: Write main entrypoint**

Create `src/user/main.c`:

```c
#include <signal.h>
#include <stdio.h>
#include <unistd.h>

#include "bpf_loader.h"
#include "config.h"

static volatile sig_atomic_t exiting;

static void on_signal(int signo)
{
	(void)signo;
	exiting = 1;
}

int main(int argc, char **argv)
{
	struct ebaf_user_config cfg;
	struct ebaf_bpf_runtime rt;
	int rc;

	rc = ebaf_parse_args(argc, argv, &cfg);
	if (rc != 0) {
		fprintf(stderr, "usage: %s --iface IFACE --mode encrypt|decrypt --key HEX16\n", argv[0]);
		return 2;
	}

	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);

	rc = ebaf_bpf_start(&cfg, &rt);
	if (rc != 0)
		return 1;

	while (!exiting) {
		ebaf_bpf_print_stats(&rt);
		sleep(1);
	}

	ebaf_bpf_stop(&cfg, &rt);
	return 0;
}
```

- [ ] **Step 4: Build daemon**

Run:

```bash
make
```

Expected:

```text
cc -O2 -g -Wall -Wextra -Werror build/main.o build/config.o build/bpf_loader.o -lbpf -lelf -lz -o build/ebaf-crypto
```

- [ ] **Step 5: Commit**

```bash
git add src/user/bpf_loader.h src/user/bpf_loader.c src/user/main.c Makefile
git commit -m "feat: add libbpf user-space loader"
```

## Task 7: Namespace Smoke Test

**Files:**
- Create: `tests/integration/run_namespace_smoke.sh`
- Modify: `README.md`

- [ ] **Step 1: Write smoke test script**

Create `tests/integration/run_namespace_smoke.sh`:

```sh
#!/usr/bin/env sh
set -eu

NS_A=ebaf-a
NS_B=ebaf-b
VETH_A=veth-ebaf-a
VETH_B=veth-ebaf-b
KEY=000102030405060708090a0b0c0d0e0f
PID_FILE=build/smoke.pid
LOG_FILE=build/smoke.log

cleanup() {
	if [ -f "$PID_FILE" ]; then
		kill "$(cat "$PID_FILE")" 2>/dev/null || true
		rm -f "$PID_FILE"
	fi
	ip netns del "$NS_A" 2>/dev/null || true
	ip netns del "$NS_B" 2>/dev/null || true
}

trap cleanup EXIT INT TERM

make

ip netns add "$NS_A"
ip netns add "$NS_B"
ip link add "$VETH_A" type veth peer name "$VETH_B"
ip link set "$VETH_A" netns "$NS_A"
ip link set "$VETH_B" netns "$NS_B"
ip -n "$NS_A" addr add 10.44.0.1/24 dev "$VETH_A"
ip -n "$NS_B" addr add 10.44.0.2/24 dev "$VETH_B"
ip -n "$NS_A" link set "$VETH_A" up
ip -n "$NS_B" link set "$VETH_B" up

ip netns exec "$NS_A" ./build/ebaf-crypto --iface "$VETH_A" --mode encrypt --key "$KEY" >"$LOG_FILE" 2>&1 &
echo "$!" > "$PID_FILE"
sleep 2

ip netns exec "$NS_B" ping -c 1 -W 2 10.44.0.1
sleep 1

grep -q 'seen=' "$LOG_FILE"
printf 'namespace smoke test passed\n'
```

- [ ] **Step 2: Make smoke test executable**

Run:

```bash
chmod +x tests/integration/run_namespace_smoke.sh
```

Expected: no output.

- [ ] **Step 3: Run smoke test**

Run:

```bash
sudo tests/integration/run_namespace_smoke.sh
```

Expected:

```text
namespace smoke test passed
```

- [ ] **Step 4: Document smoke test**

Append to `README.md`:

````markdown
## Smoke Test

```bash
sudo tests/integration/run_namespace_smoke.sh
```

The smoke test creates two network namespaces, attaches XDP to one veth interface, sends one ping, checks daemon stats, and removes the namespaces on exit.
````

- [ ] **Step 5: Commit**

```bash
git add README.md tests/integration/run_namespace_smoke.sh
git commit -m "test: add namespace smoke test"
```

## Task 8: Verifier Debug Workflow

**Files:**
- Create: `docs/operations.md`
- Modify: `Makefile`

- [ ] **Step 1: Add verifier log target**

Modify `Makefile`:

```makefile
.PHONY: all check test clean verifier-log

verifier-log: $(BPF_OBJS)
	$(BPFTOOL) prog load build/xdp_crypto.bpf.o /sys/fs/bpf/ebaf_xdp_crypto type xdp verbose 2> build/xdp_verifier.log || true
	$(BPFTOOL) prog load build/crypto_ctx.bpf.o /sys/fs/bpf/ebaf_crypto_ctx type syscall verbose 2> build/ctx_verifier.log || true
	@printf 'wrote build/xdp_verifier.log and build/ctx_verifier.log\n'
```

- [ ] **Step 2: Write operations guide**

Create `docs/operations.md`:

````markdown
# Operations Guide

## Build

```bash
make check
make
```

## Run

```bash
sudo ./build/ebaf-crypto --iface eth0 --mode decrypt --key 000102030405060708090a0b0c0d0e0f
```

## Verifier Debug

```bash
sudo make verifier-log
less build/xdp_verifier.log
less build/ctx_verifier.log
```

Verifier failures to inspect first:

- `invalid mem access`: add explicit packet boundary checks before the load or store named in the log.
- `R0 invalid mem access 'scalar'`: preserve pointer provenance by avoiding integer casts between checks and use.
- `Unreleased reference`: call `bpf_crypto_ctx_release()` on every path after failed context storage.
- `invalid kfunc call`: run `scripts/check_kernel_features.sh` and confirm the kfunc appears in `/sys/kernel/btf/vmlinux`.

## Cleanup

```bash
sudo ip link set dev eth0 xdp off
sudo rm -f /sys/fs/bpf/ebaf_xdp_crypto /sys/fs/bpf/ebaf_crypto_ctx
```
````

- [ ] **Step 3: Run verifier target**

Run:

```bash
sudo make verifier-log
```

Expected:

```text
wrote build/xdp_verifier.log and build/ctx_verifier.log
```

- [ ] **Step 4: Commit**

```bash
git add Makefile docs/operations.md
git commit -m "docs: add verifier debug workflow"
```

## Task 9: Benchmarking Workflow

**Files:**
- Create: `scripts/bench_xdp_crypto.sh`
- Create: `docs/benchmarking.md`

- [ ] **Step 1: Write benchmark script**

Create `scripts/bench_xdp_crypto.sh`:

```sh
#!/usr/bin/env sh
set -eu

IFACE=${1:-eth0}
DURATION=${2:-30}
OUT_DIR=${3:-build/bench}

mkdir -p "$OUT_DIR"

printf 'iface=%s duration=%s\n' "$IFACE" "$DURATION" | tee "$OUT_DIR/config.txt"
date -Is | tee "$OUT_DIR/start.txt"

ip -s link show dev "$IFACE" > "$OUT_DIR/ip-link-before.txt"
mpstat 1 "$DURATION" > "$OUT_DIR/mpstat.txt" &
MPSTAT_PID=$!

sleep "$DURATION"
wait "$MPSTAT_PID" || true

ip -s link show dev "$IFACE" > "$OUT_DIR/ip-link-after.txt"
date -Is | tee "$OUT_DIR/end.txt"

printf 'benchmark data written to %s\n' "$OUT_DIR"
```

- [ ] **Step 2: Make benchmark script executable**

Run:

```bash
chmod +x scripts/bench_xdp_crypto.sh
```

Expected: no output.

- [ ] **Step 3: Write benchmark guide**

Create `docs/benchmarking.md`:

````markdown
# Benchmarking Guide

## Metrics

- Packets per second from `ip -s link`
- RX/TX drops from `ip -s link`
- CPU saturation from `mpstat`
- Crypto success and failure counters from daemon output
- End-to-end latency from traffic generator output

## Baseline

Run without XDP:

```bash
scripts/bench_xdp_crypto.sh eth0 30 build/bench/baseline
```

Run with XDP crypto daemon attached:

```bash
sudo ./build/ebaf-crypto --iface eth0 --mode decrypt --key 000102030405060708090a0b0c0d0e0f
scripts/bench_xdp_crypto.sh eth0 30 build/bench/xdp-crypto
```

## Acceptance Thresholds

- Prototype loads without verifier rejection.
- Smoke test sends traffic through veth namespace.
- Daemon stats show `packets_seen` increasing during traffic.
- `packets_crypto_fail` remains stable after valid test packets are introduced.
- CPU and packet loss are recorded for baseline and XDP crypto runs.

## Interpretation

The PDF predicts heavy CPU cost for per-packet cryptography. This benchmark records the bottleneck instead of hiding it. If CPU saturates before link rate, keep XDP as steering and policy layer, then plan QAT or SmartNIC offload as the next architecture.
````

- [ ] **Step 4: Run benchmark script for syntax**

Run:

```bash
scripts/bench_xdp_crypto.sh lo 1 build/bench/syntax
```

Expected:

```text
benchmark data written to build/bench/syntax
```

- [ ] **Step 5: Commit**

```bash
git add scripts/bench_xdp_crypto.sh docs/benchmarking.md
git commit -m "docs: add benchmarking workflow"
```

## Task 10: Architecture Documentation

**Files:**
- Create: `docs/architecture.md`
- Modify: `README.md`

- [ ] **Step 1: Write architecture document**

Create `docs/architecture.md`:

```markdown
# Architecture

## Packet Flow

1. NIC receives packet.
2. XDP program runs before `sk_buff` allocation.
3. XDP validates `struct ebaf_crypto_header`.
4. XDP retrieves `struct bpf_crypto_ctx` from `crypto_ctx_map`.
5. XDP creates dynptr views for packet and IV.
6. XDP calls `bpf_crypto_encrypt()` or `bpf_crypto_decrypt()`.
7. XDP returns `XDP_PASS`.

## Control Plane

The user-space daemon parses `--iface`, `--mode`, and `--key`, updates `crypto_config`, loads the syscall BPF program, runs `create_crypto_ctx`, then attaches `xdp_crypto` to the selected interface.

## Maps

- `crypto_config`: array map with one `struct ebaf_crypto_config`.
- `crypto_ctx_map`: array map with one `struct ebaf_crypto_ctx_slot` containing a referenced kptr.
- `crypto_stats`: per-CPU array map with one `struct ebaf_crypto_stats`.

The loader opens the XDP skeleton before loading it and calls `bpf_map__reuse_fd()` for `crypto_config` and `crypto_ctx_map`. This makes the syscall BPF program and XDP BPF program share one config map and one referenced kptr map.

## Verifier Rules

- All packet reads require `data_end` bounds checks.
- Crypto context allocation stays in syscall BPF, outside XDP.
- Context replacement releases the old reference after `bpf_kptr_xchg`.
- Packet access uses dynptrs where crypto kfuncs require safe buffers.
- No data-dependent loops run in XDP.

## Hardware Acceleration Path

This prototype keeps cryptographic execution in kernel crypto kfuncs. Future work can redirect selected flows to QAT, SmartNIC, DPU, IPU, or FPGA paths when CPU saturation appears in benchmark data.
```

- [ ] **Step 2: Link docs from README**

Append to `README.md`:

```markdown
## Documentation

- `docs/architecture.md`
- `docs/operations.md`
- `docs/benchmarking.md`
```

- [ ] **Step 3: Verify docs exist**

Run:

```bash
find docs -maxdepth 1 -type f | sort
```

Expected:

```text
docs/architecture.md
docs/benchmarking.md
docs/operations.md
```

- [ ] **Step 4: Commit**

```bash
git add README.md docs/architecture.md
git commit -m "docs: document ebpf crypto architecture"
```

## Task 11: Final Verification

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Run full local verification**

Run:

```bash
make clean
make check
make
make test
```

Expected on supported kernel:

```text
PASS: BTF available
PASS: clang available
PASS: bpftool available
PASS: ip command available
PASS: bpf_crypto_encrypt kfunc visible in BTF
PASS: bpf_dynptr_from_xdp kfunc visible in BTF
config tests passed
```

- [ ] **Step 2: Run privileged smoke verification**

Run:

```bash
sudo tests/integration/run_namespace_smoke.sh
```

Expected:

```text
namespace smoke test passed
```

- [ ] **Step 3: Record verified commands**

Append to `README.md`:

````markdown
## Verified Commands

```bash
make check
make
make test
sudo tests/integration/run_namespace_smoke.sh
```
````

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs: record verification commands"
```

## Task 12: Project Report

**Files:**
- Create: `docs/project-report.md`

- [ ] **Step 1: Write final project report**

Create `docs/project-report.md`:

```markdown
# Project Report

## Summary

This project implements an eBPF/XDP in-network cryptography prototype based on the provided PDF. It separates crypto context creation from packet processing, uses a referenced kptr map to share kernel crypto state, and keeps XDP focused on bounded packet parsing and kfunc execution.

## Implemented Scope

- libbpf CO-RE build pipeline
- Kernel feature probe
- Syscall BPF crypto context creation
- XDP packet processing program
- User-space loader and stats loop
- Config parser unit tests
- Namespace smoke test
- Verifier debug workflow
- Benchmark collection workflow

## Constraints

- Requires a kernel that exposes BPF crypto kfuncs through BTF.
- Requires root privileges for XDP attachment and network namespace tests.
- Per-packet cryptography can saturate CPU under high packet rates.

## Future Work

- Add QAT offload path for high-throughput symmetric crypto.
- Add SmartNIC offload path for XDP-capable NICs.
- Add PQC control-plane prototype for Kyber or Dilithium key operations.
- Add packet generator integration with pktgen or MoonGen.
- Add CI job that runs unit tests on normal hosts and labels BPF integration tests as privileged.
```

- [ ] **Step 2: Commit**

```bash
git add docs/project-report.md
git commit -m "docs: add final project report"
```

## Self-Review

- Spec coverage: PDF requirements map to tasks 2, 4, 5, 8, 9, 10, and 12.
- Scope split: hardware accelerator and PQC work documented as future work because the first working project must prove XDP + kfunc crypto path before offload expansion.
- Placeholder scan: no deferred implementation markers are present.
- Type consistency: shared structs live in `include/crypto_common.h`; user-space and BPF files use the same names.
- Test coverage: parser unit test, kernel feature probe, BPF compile, verifier log target, namespace smoke test, and benchmark syntax test cover the prototype lifecycle.

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-05-27-ebpf-xdp-crypto.md`. Two execution options:

1. Subagent-Driven (recommended) - dispatch a fresh subagent per task, review between tasks, fast iteration.
2. Inline Execution - execute tasks in this session using executing-plans, batch execution with checkpoints.
