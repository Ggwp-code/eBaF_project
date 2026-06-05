# Transparent UDP Crypto Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a research-grade transparent UDP crypto path where normal UDP apps can send plaintext while BPF encrypts/decrypts packets at network hooks.

**Architecture:** Keep existing XDP `EBAF` decrypt path. Add a TC egress program for outbound standard UDP encryption because local application egress is not visible to XDP. Use `bpf_dynptr_from_skb` for TC payload crypto and require an `EBAF` transport header/IV for decryptability. Start with a constrained verified prototype: fixed UDP port, IPv4 only, no fragmentation, AES-CBC 16-byte aligned payloads, and integration tests over veth namespaces.

**Tech Stack:** eBPF TC classifier, eBPF XDP, libbpf skeletons, BPF crypto kfuncs, BPF dynptr, iproute2 `tc`, Bash/Python integration tests.

---

## Important Constraint

Transparent arbitrary UDP encryption requires carrying metadata for decrypt:

- magic/version
- action
- payload length
- IV

XDP cannot easily insert this header between UDP header and payload. TC egress can modify skb room, but verifier-safe arbitrary payload shifting is non-trivial. Therefore this plan implements **research prototype transparent mode** in two steps:

1. **TC egress crypto for UDP packets that already reserve an `EBAF` shim header.** Apps send normal UDP via a tiny socket shim/helper that prefixes reserved header bytes but sends plaintext body.
2. Later phase can explore full arbitrary UDP header insertion.

This gives real app endpoints and real network packets without fake replay, while staying verifier-safe.

---

## File Structure

- Create `src/bpf/tc_crypto.bpf.c`: TC egress/ingress program for skb-based crypto using `bpf_dynptr_from_skb`.
- Modify `include/crypto_common.h`: add hook direction constants and transparent mode config flags.
- Modify `src/user/config.{h,c}`: parse `--hook xdp|tc|both`, `--direction encrypt|decrypt`.
- Modify `src/user/bpf_loader.{h,c}`: load TC skeleton, attach/detach TC clsact programs, reuse crypto maps/stats/events.
- Modify `src/user/main.c`: usage text and runtime lifecycle.
- Modify `Makefile`: build TC BPF object/skeleton.
- Modify `scripts/check_kernel_features.sh`: check `bpf_dynptr_from_skb`.
- Create `scripts/udp_chat_client.py`: real UDP app client, sends EBAF-shim plaintext messages.
- Create `scripts/udp_chat_server.py`: real UDP app server, receives decrypted plaintext messages.
- Create `tests/integration/test_tc_udp_crypto.sh`: veth namespace integration test.
- Modify `README.md` and `docs/project-report.md`: document transparent-mode limits and demo.

---

### Task 1: Kernel And Build Plumbing

**Files:**
- Modify: `scripts/check_kernel_features.sh`
- Modify: `Makefile`
- Create: `src/bpf/tc_crypto.bpf.c`

- [ ] **Step 1: Extend feature check**

Add this block to `scripts/check_kernel_features.sh` after the XDP dynptr check:

```sh
if bpftool btf dump file /sys/kernel/btf/vmlinux format raw | grep -q 'bpf_dynptr_from_skb'; then
	pass 'bpf_dynptr_from_skb kfunc visible in BTF'
else
	fail 'bpf_dynptr_from_skb kfunc not visible in BTF'
fi
```

- [ ] **Step 2: Add minimal TC program**

Create `src/bpf/tc_crypto.bpf.c`:

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

SEC("tc")
int tc_crypto(struct __sk_buff *skb)
{
	(void)skb;
	return 0;
}
```

- [ ] **Step 3: Wire Makefile**

Change:

```make
BPF_SRCS := src/bpf/crypto_ctx.bpf.c src/bpf/xdp_crypto.bpf.c
```

to:

```make
BPF_SRCS := src/bpf/crypto_ctx.bpf.c src/bpf/xdp_crypto.bpf.c src/bpf/tc_crypto.bpf.c
```

- [ ] **Step 4: Verify**

Run:

```bash
make check
make -B build/tc_crypto.bpf.o
make -B all
```

Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add scripts/check_kernel_features.sh Makefile src/bpf/tc_crypto.bpf.c
git commit -m "feat: add tc crypto program skeleton"
```

---

### Task 2: CLI Hook Selection

**Files:**
- Modify: `src/user/config.h`
- Modify: `src/user/config.c`
- Modify: `src/user/main.c`
- Modify: `tests/unit/test_config.c`

- [ ] **Step 1: Add config fields**

Add:

```c
#define EBAF_HOOK_XDP 1
#define EBAF_HOOK_TC 2
#define EBAF_HOOK_BOTH 3
```

to `src/user/config.h`, and add to `struct ebaf_user_config`:

```c
unsigned int hook;
```

- [ ] **Step 2: Parse `--hook`**

Default `hook = EBAF_HOOK_XDP`.

Add parser branch:

```c
} else if (strcmp(argv[i], "--hook") == 0 && i + 1 < argc) {
	const char *hook = argv[++i];
	if (strcmp(hook, "xdp") == 0)
		cfg->hook = EBAF_HOOK_XDP;
	else if (strcmp(hook, "tc") == 0)
		cfg->hook = EBAF_HOOK_TC;
	else if (strcmp(hook, "both") == 0)
		cfg->hook = EBAF_HOOK_BOTH;
	else
		return -1;
```

- [ ] **Step 3: Unit test**

Add to `tests/unit/test_config.c`:

```c
static void test_parse_hook_option(void)
{
	char *argv[] = {
		"ebaf-crypto", "--iface", "veth0", "--mode", "encrypt",
		"--key", "000102030405060708090a0b0c0d0e0f",
		"--hook", "both",
	};
	struct ebaf_user_config cfg;
	int rc = ebaf_parse_args(9, argv, &cfg);

	expect_int("parse hook rc", rc, 0);
	expect_int("hook both", cfg.hook, EBAF_HOOK_BOTH);
}
```

- [ ] **Step 4: Verify**

Run:

```bash
make test
```

Expected: config tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/user/config.* src/user/main.c tests/unit/test_config.c
git commit -m "feat: add hook selection option"
```

---

### Task 3: TC Attach/Detach Loader

**Files:**
- Modify: `src/user/bpf_loader.h`
- Modify: `src/user/bpf_loader.c`
- Modify: `Makefile`

- [ ] **Step 1: Include TC skeleton**

Add:

```c
#include "tc_crypto.bpf.skel.h"
```

and a static skeleton pointer:

```c
static struct tc_crypto_bpf *tc_skel;
```

- [ ] **Step 2: Add runtime fields**

Add to `struct ebaf_bpf_runtime`:

```c
struct bpf_tc_hook tc_hook;
struct bpf_tc_opts tc_opts;
int tc_attached;
```

- [ ] **Step 3: Attach TC egress**

Implement helper:

```c
static int attach_tc_egress(int ifindex, int prog_fd, struct ebaf_bpf_runtime *rt)
{
	LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = ifindex, .attach_point = BPF_TC_EGRESS);
	LIBBPF_OPTS(bpf_tc_opts, opts, .prog_fd = prog_fd);
	int err;

	bpf_tc_hook_create(&hook);
	err = bpf_tc_attach(&hook, &opts);
	if (err)
		return err;
	rt->tc_hook = hook;
	rt->tc_opts = opts;
	rt->tc_attached = 1;
	return 0;
}
```

- [ ] **Step 4: Stop TC**

In `ebaf_bpf_stop`:

```c
if (rt && rt->tc_attached) {
	bpf_tc_detach(&rt->tc_hook, &rt->tc_opts);
	bpf_tc_hook_destroy(&rt->tc_hook);
}
tc_crypto_bpf__destroy(tc_skel);
```

- [ ] **Step 5: Verify build**

Run:

```bash
make -B all
```

Expected: build passes.

- [ ] **Step 6: Commit**

```bash
git add src/user/bpf_loader.* Makefile
git commit -m "feat: attach tc crypto program"
```

---

### Task 4: TC Egress Encrypt EBAF-Shim UDP

**Files:**
- Modify: `src/bpf/tc_crypto.bpf.c`
- Modify: `include/crypto_common.h`

- [ ] **Step 1: Implement parser**

In `src/bpf/tc_crypto.bpf.c`, parse Ethernet, IPv4, UDP like `xdp_crypto.bpf.c`, using `skb->data` / `skb->data_end` and bounds checks.

- [ ] **Step 2: Require EBAF header**

Only process UDP payloads where:

```c
hdr->magic == bpf_htonl(EBAF_CRYPTO_MAGIC)
hdr->version == EBAF_CRYPTO_VERSION
hdr->action == EBAF_ACTION_ENCRYPT
```

- [ ] **Step 3: Use skb dynptr**

Use:

```c
extern int bpf_dynptr_from_skb(struct __sk_buff *skb, __u64 flags, struct bpf_dynptr *ptr__uninit) __ksym;
```

Create dynptr over payload body and IV, then call `bpf_crypto_encrypt`.

- [ ] **Step 4: Emit event**

Reuse `struct ebaf_crypto_event` and ring buffer map. Set action `encrypt`, source/destination/ports, lengths, and ciphertext sample.

- [ ] **Step 5: Verify**

Run:

```bash
make -B build/tc_crypto.bpf.o
make -B all
```

Expected: verifier/build pass.

- [ ] **Step 6: Commit**

```bash
git add src/bpf/tc_crypto.bpf.c include/crypto_common.h
git commit -m "feat: encrypt ebaf udp at tc egress"
```

---

### Task 5: Real UDP Chat App

**Files:**
- Create: `scripts/udp_chat_client.py`
- Create: `scripts/udp_chat_server.py`

- [ ] **Step 1: Client**

Create `scripts/udp_chat_client.py` that sends UDP payload:

```text
EBAF header + IV + 16-byte-aligned plaintext chat body
```

Command:

```bash
python3 scripts/udp_chat_client.py --host 10.77.0.2 --port 7777 --message "hello real app"
```

- [ ] **Step 2: Server**

Create `scripts/udp_chat_server.py` that receives UDP payload, strips `EBAF` header, unpads spaces, and prints plaintext body.

Command:

```bash
python3 scripts/udp_chat_server.py --host 0.0.0.0 --port 7777
```

- [ ] **Step 3: Verify scripts**

Run:

```bash
python3 -m py_compile scripts/udp_chat_client.py scripts/udp_chat_server.py
```

Expected: no output.

- [ ] **Step 4: Commit**

```bash
git add scripts/udp_chat_client.py scripts/udp_chat_server.py
git commit -m "feat: add real udp chat app"
```

---

### Task 6: Integration Test Real App Path

**Files:**
- Create: `tests/integration/test_tc_udp_chat.sh`
- Modify: `Makefile`

- [ ] **Step 1: Add test target**

Add to `.PHONY`:

```make
tc-chat-test
```

Add target:

```make
tc-chat-test: $(BUILD_DIR)/ebaf-crypto
	@tests/integration/test_tc_udp_chat.sh; status=$$?; \
	if [ $$status -eq 77 ]; then exit 0; fi; \
	exit $$status
```

- [ ] **Step 2: Create integration test**

Test creates veth namespace pair and uses this real packet path:

- host client sends plaintext `EBAF`-shim UDP
- host TC egress encrypts payload on the wire
- peer namespace TC ingress decrypts payload for veth-local integration
- peer namespace server receives original plaintext message

Start host encrypt:

```bash
build/ebaf-crypto --iface HOST_IF --mode encrypt --hook tc --key KEY --port 7777 --jsonl
```

Start namespace decrypt:

```bash
ip netns exec NS build/ebaf-crypto --iface NS_IF --mode decrypt --hook tc --key KEY --port 7777 --jsonl
```

Then runs `udp_chat_server.py` in the namespace and `udp_chat_client.py` on host.

Expected:

```text
tc udp chat crypto passed
```

- [ ] **Step 3: Verify**

Run:

```bash
sudo make tc-chat-test
```

Expected: pass.

- [ ] **Step 4: Commit**

```bash
git add Makefile tests/integration/test_tc_udp_chat.sh
git commit -m "test: add tc udp chat integration"
```

---

## Final Verification

Run:

```bash
make check
make test
make -B all
sudo make tc-chat-test
sudo make demo-smoke
```

Expected: all pass.

## Later Phase

Full transparent arbitrary UDP header insertion/removal is deferred. It needs separate verifier-focused design using `bpf_skb_adjust_room`, checksum repair, and bounded payload shifting.
