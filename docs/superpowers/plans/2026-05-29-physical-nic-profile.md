# Physical NIC Profile Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a safe, optional physical NIC profile command that reports native XDP support, generic fallback, driver details, MTU, IRQ/NAPI clues, and offload state without sending traffic.

**Architecture:** Build a minimal `xdp_probe.bpf.o` program that returns `XDP_PASS`. A Bash script requires root and explicit `IFACE`, refuses existing XDP attachments, probes native and generic attach modes with immediate cleanup, reads sysfs/ethtool/bpftool data, and writes JSON to `experiments/physical-profile-IFACE.json`.

**Tech Stack:** Bash, bpftool, iproute2, ethtool, sysfs, minimal eBPF XDP probe object, Makefile.

---

### Task 1: Build Minimal XDP Probe Object

**Files:**
- Create: `src/bpf/xdp_probe.bpf.c`
- Modify: `Makefile`

- [ ] Add `src/bpf/xdp_probe.bpf.c` with `SEC("xdp") int xdp_probe(struct xdp_md *ctx) { return XDP_PASS; }`.
- [ ] Add `$(BUILD_DIR)/xdp_probe.bpf.o` target to `Makefile`.
- [ ] Verify `make -B build/xdp_probe.bpf.o`.

### Task 2: Add Physical Profile Script

**Files:**
- Create: `scripts/physical_profile.sh`

- [ ] Write Bash script requiring root and one `IFACE`.
- [ ] Refuse missing interface and missing `build/xdp_probe.bpf.o`.
- [ ] Use `bpftool net` for current XDP state and refuse if `IFACE` already has XDP attached.
- [ ] Probe native with `ip link set dev "$IFACE" xdp obj build/xdp_probe.bpf.o sec xdp`, detach immediately, record success/error.
- [ ] Probe generic with `ip link set dev "$IFACE" xdpgeneric obj build/xdp_probe.bpf.o sec xdp`, detach immediately, record success/error.
- [ ] Record driver/bus via `ethtool -i`, offloads via `ethtool -k`, MTU/link state via `ip -j link show`, IRQ clues via `/proc/interrupts`, queue count via `/sys/class/net/$IFACE/queues`.
- [ ] Write JSON to `experiments/physical-profile-$IFACE.json`.

### Task 3: Wire Make Targets And Tests

**Files:**
- Modify: `Makefile`
- Create: `tests/unit/test_physical_profile.sh`

- [ ] Add `physical-profile: $(BUILD_DIR)/xdp_probe.bpf.o` target requiring `IFACE`.
- [ ] Add shell syntax test for `scripts/physical_profile.sh`.
- [ ] Add non-root skip check test for `scripts/physical_profile.sh lo`.
- [ ] Include shell unit in `make test`.

### Final Verification

Run:

```bash
make test
make -B build/xdp_probe.bpf.o
sudo make physical-profile IFACE=<your-interface>
```

Expected: JSON profile written, no traffic sent, XDP detached after probe.
