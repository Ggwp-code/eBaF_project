# Research Grade Backend Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the backend from a demo-oriented XDP encryptor into a reproducible research artifact with a clear protocol, structured observability, correctness evidence, benchmark harness, and failure analysis.

**Architecture:** Keep XDP data-path small and verifier-friendly. Move orchestration, event decoding, benchmark collection, and experiment reporting into user-space modules and scripts. Add protocol metadata and measurement hooks without pretending to provide production security beyond the kernel crypto kfunc limits.

**Tech Stack:** eBPF/XDP C, libbpf skeletons, BPF ring buffer, Bash integration tests, Python experiment harnesses, Markdown report artifacts.

---

## File Structure

- Modify `include/crypto_common.h`: protocol constants, event schema, stats schema.
- Modify `src/bpf/xdp_crypto.bpf.c`: packet validation, crypto transform, event emission, error reason counters.
- Modify `src/bpf/crypto_ctx.bpf.c`: crypto context validation and algorithm selection.
- Modify `src/user/config.{h,c}`: CLI flags for algorithm, direction, event output, run metadata, benchmark mode.
- Modify `src/user/bpf_loader.{h,c}`: ring buffer event handling, stats snapshots, attach/detach lifecycle.
- Modify `src/user/main.c`: runtime loop, event polling, machine-readable output.
- Create `src/user/event_format.{h,c}`: JSONL/text formatting for packet events and stats.
- Create `src/user/stats_format.{h,c}`: stable machine-readable stats snapshot formatting.
- Create `tests/unit/test_event_format.c`: event formatting unit tests.
- Create `tests/unit/test_stats_format.c`: stats formatting unit tests.
- Modify `tests/integration/test_crypto_correctness.sh`: verify encrypt/decrypt, event emission, error counters.
- Create `tests/integration/test_protocol_validation.sh`: malformed packet matrix.
- Create `scripts/run_experiment.py`: reproducible benchmark runner.
- Create `scripts/analyze_experiment.py`: summarize benchmark outputs into tables.
- Create `docs/research-methodology.md`: threat model, limitations, experiment design.
- Modify `docs/project-report.md`: replace showcase claims with measured backend claims.

---

### Task 1: Lock Protocol Scope And Research Claims

**Files:**
- Create: `docs/research-methodology.md`
- Modify: `README.md`

- [ ] **Step 1: Write methodology document**

Create `docs/research-methodology.md`:

```markdown
# Research Methodology

## Scope

This project studies in-kernel UDP payload transformation using eBPF/XDP and Linux BPF crypto kfuncs.

## Research Questions

1. Can XDP invoke kernel crypto kfuncs to transform UDP payloads at line-rate-ish lab traffic rates?
2. What verifier and protocol constraints shape this design?
3. What is the performance cost of XDP crypto versus pass-through XDP?
4. What observability is possible from a verifier-safe packet data path?

## Non-Goals

- No production confidentiality guarantee.
- No authenticated encryption in the current kfunc path.
- No TCP stream reassembly.
- No key exchange.
- No persistent key management.

## Threat Model

Packets already carry an `EBAF` protocol header and IV. The XDP program transforms only matching IPv4/UDP packets on the configured destination port. Attackers can inject malformed packets; the program must pass or count them without crashing, verifier rejection, or out-of-bounds access.

## Evidence Required

- Correctness: encrypt changes body; decrypt restores body.
- Validation: malformed protocol packets increment reason counters.
- Observability: ring-buffer events show transformed packet metadata.
- Performance: reproducible packets-per-second and CPU observations across pass-through, encrypt, and decrypt modes.
```

- [ ] **Step 2: Update README positioning**

Change README first paragraph to:

```markdown
This project is a research artifact for studying in-kernel UDP payload cryptography with eBPF, XDP, libbpf, and Linux BPF crypto kfuncs.
```

- [ ] **Step 3: Commit**

```bash
git add README.md docs/research-methodology.md
git commit -m "docs: define backend research scope"
```

---

### Task 2: Add Stable Event And Stats Formatting Modules

**Files:**
- Create: `src/user/event_format.h`
- Create: `src/user/event_format.c`
- Create: `src/user/stats_format.h`
- Create: `src/user/stats_format.c`
- Create: `tests/unit/test_event_format.c`
- Create: `tests/unit/test_stats_format.c`
- Modify: `Makefile`

- [ ] **Step 1: Write event formatter test**

Create `tests/unit/test_event_format.c`:

```c
#include <stdio.h>
#include <string.h>

#include "event_format.h"

int main(void)
{
	struct ebaf_crypto_event event = {
		.timestamp_ns = 123,
		.src_ip = 0x0200630a,
		.dst_ip = 0x0100630a,
		.src_port = 4242,
		.dst_port = 7777,
		.payload_len = 56,
		.data_len = 32,
		.action = EBAF_ACTION_ENCRYPT,
		.algo = EBAF_ALGO_CBC_AES,
		.sample_len = 4,
		.sample = {0xde, 0xad, 0xbe, 0xef},
	};
	char out[512];

	if (ebaf_format_event_json(&event, out, sizeof(out)) <= 0)
		return 1;
	if (strstr(out, "\"action\":\"encrypt\"") == NULL)
		return 2;
	if (strstr(out, "\"algo\":\"cbc-aes\"") == NULL)
		return 3;
	if (strstr(out, "\"sample\":\"deadbeef\"") == NULL)
		return 4;

	puts("event format tests passed");
	return 0;
}
```

- [ ] **Step 2: Write event formatter implementation**

Create `src/user/event_format.h`:

```c
#ifndef EBAF_EVENT_FORMAT_H
#define EBAF_EVENT_FORMAT_H

#include <stddef.h>

#include "crypto_common.h"

int ebaf_format_event_json(const struct ebaf_crypto_event *event, char *out, size_t out_len);

#endif
```

Create `src/user/event_format.c`:

```c
#include "event_format.h"

#include <arpa/inet.h>
#include <stdio.h>

static const char *action_name(__u8 action)
{
	if (action == EBAF_ACTION_ENCRYPT)
		return "encrypt";
	if (action == EBAF_ACTION_DECRYPT)
		return "decrypt";
	return "pass";
}

static const char *algo_name(__u8 algo)
{
	if (algo == EBAF_ALGO_CBC_AES)
		return "cbc-aes";
	if (algo == EBAF_ALGO_CHACHA20)
		return "chacha20";
	return "unknown";
}

int ebaf_format_event_json(const struct ebaf_crypto_event *event, char *out, size_t out_len)
{
	char src_ip[INET_ADDRSTRLEN] = "?";
	char dst_ip[INET_ADDRSTRLEN] = "?";
	char sample[EBAF_EVENT_SAMPLE_BYTES * 2 + 1] = {};
	struct in_addr src;
	struct in_addr dst;
	size_t sample_len;

	if (!event || !out || out_len == 0)
		return -1;

	src.s_addr = event->src_ip;
	dst.s_addr = event->dst_ip;
	inet_ntop(AF_INET, &src, src_ip, sizeof(src_ip));
	inet_ntop(AF_INET, &dst, dst_ip, sizeof(dst_ip));

	sample_len = event->sample_len;
	if (sample_len > EBAF_EVENT_SAMPLE_BYTES)
		sample_len = EBAF_EVENT_SAMPLE_BYTES;
	for (size_t i = 0; i < sample_len; i++)
		snprintf(sample + i * 2, sizeof(sample) - i * 2, "%02x", event->sample[i]);

	return snprintf(out, out_len,
			"{\"type\":\"packet\",\"ts_ns\":%llu,\"action\":\"%s\",\"algo\":\"%s\","
			"\"src\":\"%s\",\"src_port\":%u,\"dst\":\"%s\",\"dst_port\":%u,"
			"\"payload_len\":%u,\"data_len\":%u,\"sample\":\"%s\"}",
			(unsigned long long)event->timestamp_ns,
			action_name(event->action),
			algo_name(event->algo),
			src_ip,
			event->src_port,
			dst_ip,
			event->dst_port,
			event->payload_len,
			event->data_len,
			sample);
}
```

- [ ] **Step 3: Wire Makefile unit target**

Add:

```make
$(BUILD_DIR)/test_event_format: tests/unit/test_event_format.c src/user/event_format.c src/user/event_format.h include/crypto_common.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -Iinclude -Isrc/user tests/unit/test_event_format.c src/user/event_format.c -o $@
```

Update `test` target:

```make
test: $(BUILD_DIR)/test_config $(BUILD_DIR)/test_event_format
	./$(BUILD_DIR)/test_config
	./$(BUILD_DIR)/test_event_format
```

- [ ] **Step 4: Verify**

Run:

```bash
make test
```

Expected:

```text
config tests passed
event format tests passed
```

- [ ] **Step 5: Commit**

```bash
git add Makefile src/user/event_format.* tests/unit/test_event_format.c
git commit -m "test: add stable packet event formatting"
```

---

### Task 3: Expand Error Reason Counters

**Files:**
- Modify: `include/crypto_common.h`
- Modify: `src/bpf/xdp_crypto.bpf.c`
- Modify: `src/user/bpf_loader.c`
- Create: `tests/integration/test_protocol_validation.sh`
- Modify: `Makefile`

- [ ] **Step 1: Add reason fields**

Extend `struct ebaf_crypto_stats`:

```c
__u64 packets_bad_eth;
__u64 packets_bad_ip;
__u64 packets_bad_udp;
__u64 packets_bad_magic;
__u64 packets_bad_length;
__u64 packets_bad_alignment;
__u64 packets_no_crypto_ctx;
```

- [ ] **Step 2: Replace generic malformed increments**

In `src/bpf/xdp_crypto.bpf.c`, add helper:

```c
static __always_inline void stat_reason(struct ebaf_crypto_stats *stats, __u64 *counter)
{
	if (!stats || !counter)
		return;
	stat_inc(&stats->packets_malformed);
	stat_inc(counter);
}
```

Use exact mapping:

```c
stat_reason(stats, &stats->packets_bad_eth);
stat_reason(stats, &stats->packets_bad_ip);
stat_reason(stats, &stats->packets_bad_udp);
stat_reason(stats, &stats->packets_bad_magic);
stat_reason(stats, &stats->packets_bad_length);
stat_reason(stats, &stats->packets_bad_alignment);
stat_reason(stats, &stats->packets_no_crypto_ctx);
```

- [ ] **Step 3: Print reason counters**

Update stats line in `src/user/bpf_loader.c`:

```c
printf("seen=%llu passed=%llu crypto_ok=%llu crypto_fail=%llu malformed=%llu bad_eth=%llu bad_ip=%llu bad_udp=%llu bad_magic=%llu bad_length=%llu bad_alignment=%llu no_crypto_ctx=%llu\n", ...);
```

- [ ] **Step 4: Add malformed protocol integration test**

Create `tests/integration/test_protocol_validation.sh` by reusing namespace setup from `tests/integration/test_crypto_correctness.sh`. Send these malformed UDP payloads:

```text
BADMAGIC + valid header length
EBAF + version 1 + payload_len smaller than actual body
EBAF + version 1 + AES body length 15 bytes
```

Expected log fragments:

```text
bad_magic=
bad_length=
bad_alignment=
```

- [ ] **Step 5: Wire Makefile**

Add:

```make
protocol-validation-test: $(BUILD_DIR)/ebaf-crypto
	@tests/integration/test_protocol_validation.sh; status=$$?; \
	if [ $$status -eq 77 ]; then exit 0; fi; \
	exit $$status
```

- [ ] **Step 6: Verify**

Run:

```bash
make test
sudo make protocol-validation-test
```

Expected:

```text
config tests passed
protocol validation passed
```

- [ ] **Step 7: Commit**

```bash
git add include/crypto_common.h src/bpf/xdp_crypto.bpf.c src/user/bpf_loader.c Makefile tests/integration/test_protocol_validation.sh
git commit -m "feat: add protocol validation counters"
```

---

### Task 4: Add Real Experiment Harness

**Files:**
- Create: `scripts/run_experiment.py`
- Create: `scripts/analyze_experiment.py`
- Modify: `Makefile`
- Create: `experiments/.gitkeep`

- [ ] **Step 1: Create experiment runner**

Create `scripts/run_experiment.py`:

```python
#!/usr/bin/env python3
import argparse
import json
import pathlib
import subprocess
import time

def run(cmd):
    started = time.time()
    proc = subprocess.run(cmd, text=True, capture_output=True)
    return {
        "cmd": cmd,
        "returncode": proc.returncode,
        "duration_sec": round(time.time() - started, 3),
        "stdout": proc.stdout,
        "stderr": proc.stderr,
    }

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="experiments/latest.json")
    parser.add_argument("--repeat", type=int, default=3)
    args = parser.parse_args()

    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    results = []

    for name, target in [
        ("check", ["make", "check"]),
        ("correctness", ["sudo", "make", "correctness-test"]),
        ("benchmark", ["sudo", "make", "benchmark-smoke"]),
    ]:
        for i in range(args.repeat if name == "benchmark" else 1):
            item = run(target)
            item["name"] = name
            item["iteration"] = i
            results.append(item)

    out.write_text(json.dumps({"created_at": time.time(), "results": results}, indent=2), encoding="utf-8")
    print(out)

if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Create analyzer**

Create `scripts/analyze_experiment.py`:

```python
#!/usr/bin/env python3
import json
import re
import statistics
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
pps = []
for result in data["results"]:
    match = re.search(r"pps=(\d+)", result["stdout"])
    if match:
        pps.append(int(match.group(1)))

if not pps:
    raise SystemExit("no pps samples found")

print(f"samples={len(pps)}")
print(f"pps_min={min(pps)}")
print(f"pps_median={int(statistics.median(pps))}")
print(f"pps_max={max(pps)}")
```

- [ ] **Step 3: Wire Makefile**

Add:

```make
experiment:
	python3 scripts/run_experiment.py --out experiments/latest.json --repeat 3
	python3 scripts/analyze_experiment.py experiments/latest.json
```

- [ ] **Step 4: Verify**

Run:

```bash
sudo make experiment
```

Expected output includes:

```text
samples=3
pps_median=
```

- [ ] **Step 5: Commit**

```bash
git add Makefile scripts/run_experiment.py scripts/analyze_experiment.py experiments/.gitkeep
git commit -m "feat: add reproducible experiment harness"
```

---

### Task 5: Add Backend JSONL Runtime Mode

**Files:**
- Modify: `src/user/config.{h,c}`
- Modify: `src/user/main.c`
- Modify: `src/user/bpf_loader.{h,c}`
- Modify: `src/user/event_format.{h,c}`
- Modify: `tests/unit/test_config.c`

- [ ] **Step 1: Add CLI flag test**

Extend `tests/unit/test_config.c`:

```c
static void test_parse_jsonl_option(void)
{
	char *argv[] = {
		"ebaf-crypto",
		"--iface", "veth0",
		"--mode", "encrypt",
		"--key", "000102030405060708090a0b0c0d0e0f",
		"--jsonl",
	};
	struct ebaf_user_config cfg;
	int rc = ebaf_parse_args(8, argv, &cfg);

	expect_int("parse jsonl rc", rc, 0);
	expect_int("jsonl enabled", cfg.output_jsonl, 1);
}
```

- [ ] **Step 2: Implement config field**

Add to `struct ebaf_user_config`:

```c
int output_jsonl;
```

Add parser branch:

```c
} else if (strcmp(argv[i], "--jsonl") == 0) {
	cfg->output_jsonl = 1;
	cfg->print_events = 1;
```

- [ ] **Step 3: Use JSONL formatter for events**

Change ring-buffer callback context to carry output mode:

```c
struct ebaf_event_printer {
	int jsonl;
};
```

Print JSONL when enabled:

```c
char line[512];
ebaf_format_event_json(event, line, sizeof(line));
puts(line);
```

- [ ] **Step 4: Verify**

Run:

```bash
make test
make -B all
```

Expected: both pass.

- [ ] **Step 5: Commit**

```bash
git add src/user tests/unit
git commit -m "feat: add jsonl runtime event output"
```

---

### Task 6: Publish Backend Evidence In Report

**Files:**
- Modify: `docs/project-report.md`
- Modify: `README.md`

- [ ] **Step 1: Add report backend section**

Add to `docs/project-report.md`:

```markdown
## Backend Research Artifact

The backend now exposes three evidence layers:

1. Kernel counters for pass, crypto success, crypto failure, and validation failures.
2. BPF ring-buffer packet events emitted from the XDP data path after successful transformation.
3. Reproducible experiment JSON files under `experiments/`.

This separates the research backend from the dashboard. The UI may visualize events, but the backend evidence is available without browser code.
```

- [ ] **Step 2: Add README command block**

Add:

```bash
make check
make test
sudo make correctness-test
sudo make benchmark-smoke
sudo make experiment
sudo ./build/ebaf-crypto --iface <iface> --mode encrypt --key <hex> --port 7777 --events --jsonl
```

- [ ] **Step 3: Commit**

```bash
git add README.md docs/project-report.md
git commit -m "docs: document backend evidence pipeline"
```

---

## Execution Order

1. Task 1: define claims first.
2. Task 2: stabilize event formatting.
3. Task 3: add protocol validation counters.
4. Task 4: add experiment harness.
5. Task 5: add JSONL runtime output.
6. Task 6: document backend evidence.

## Verification Gate

Before calling this backend research-ready:

```bash
make check
make test
make -B all
sudo make integration-test
sudo make correctness-test
sudo make benchmark-smoke
sudo make protocol-validation-test
sudo make experiment
```

Expected: all non-root commands pass; all root commands pass on kernel with BPF crypto kfunc support.

## Current Dirty Worktree Note

The worktree currently has uncommitted backend event-stream changes. Before executing this plan, either commit them as:

```bash
git add README.md include/crypto_common.h src/bpf/xdp_crypto.bpf.c src/user/bpf_loader.c src/user/bpf_loader.h src/user/config.c src/user/config.h src/user/main.c tests/unit/test_config.c
git commit -m "feat: add xdp packet event stream"
```

or fold them into Task 2.

