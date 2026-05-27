# Live Cipher Dashboard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a browser dashboard that shows local server-to-client UDP packets being transformed by the XDP crypto program in real time.

**Architecture:** A privileged Python runner creates a veth namespace demo, starts `build/ebaf-crypto`, sends readable `EBAF` UDP packets, captures transformed packets, and serves JSON over HTTP. Static browser files render a Wireshark-like packet table, hex/ASCII panes, counters, and charts.

**Tech Stack:** Python 3 stdlib, Linux network namespaces, existing C eBPF binary, HTML/CSS/JS Canvas.

---

## Task 1: Demo Runner

**Files:**
- Create: `scripts/demo_live_cipher.py`

- [ ] Write a Python runner with:
  - root check
  - `make` build check
  - temp namespace/veth setup
  - cleanup on SIGINT/SIGTERM
  - `ebaf-crypto` subprocess on host veth
  - sender thread that emits `EBAF` UDP frames with readable ASCII body
  - capture thread that records transformed packets from host veth
  - HTTP server with `/`, `/api/snapshot`, `/api/events`, `/api/stop`
  - JSON snapshot containing stats, recent packets, plaintext ASCII/hex, cipher hex, pps, crypto_ok/sec

- [ ] Run: `python3 -m py_compile scripts/demo_live_cipher.py`

- [ ] Commit:
```bash
git add scripts/demo_live_cipher.py
git commit -m "feat: add live cipher demo runner"
```

## Task 2: Browser Dashboard

**Files:**
- Create: `web/demo/index.html`
- Create: `web/demo/styles.css`
- Create: `web/demo/app.js`

- [ ] Build dashboard UI with:
  - dense Wireshark-like layout
  - top status bar
  - counters
  - packet timeline
  - plaintext ASCII pane
  - plaintext/cipher hex panes
  - Canvas chart for pps and crypto_ok/sec
  - Stop and reset controls

- [ ] Run: `python3 -m py_compile scripts/demo_live_cipher.py`

- [ ] Commit:
```bash
git add web/demo/index.html web/demo/styles.css web/demo/app.js
git commit -m "feat: add live cipher dashboard ui"
```

## Task 3: Demo Smoke Test And Docs

**Files:**
- Create: `tests/integration/test_demo_runner.sh`
- Modify: `Makefile`
- Modify: `README.md`

- [ ] Add Makefile target:
```makefile
demo-smoke: $(BUILD_DIR)/ebaf-crypto
	@tests/integration/test_demo_runner.sh; status=$$?; \
	if [ $$status -eq 77 ]; then exit 0; fi; \
	exit $$status
```

- [ ] Add smoke test that runs the demo for a short duration, fetches `/api/snapshot`, and asserts `crypto_ok > 0`, recent packets exist, ASCII plaintext exists, and cipher hex exists.

- [ ] Add README demo commands:
```bash
sudo scripts/demo_live_cipher.py --duration 30
xdg-open http://127.0.0.1:8088
sudo make demo-smoke
```

- [ ] Run:
```bash
make check
make test
sudo make demo-smoke
```

- [ ] Commit:
```bash
git add Makefile README.md tests/integration/test_demo_runner.sh
git commit -m "test: add live dashboard smoke test"
```

## Self-Review

- Spec coverage: local server/client, real XDP path, ASCII/hex, graphs, stop/cleanup, smoke test.
- No placeholders.
- Existing tests remain required.
