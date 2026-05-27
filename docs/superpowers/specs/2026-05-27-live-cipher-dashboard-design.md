# Live Cipher Dashboard Design

## Goal

Build a presentation-ready live packet analysis dashboard for the eBPF/XDP crypto project. The demo must show packets moving from a local server to a local client while the XDP program encrypts or decrypts packet bodies in real time.

## Demo Shape

Use a local server/client demo by default, not live internet traffic. This keeps the presentation repeatable and safe while still showing real packets through a real XDP attach path.

The demo creates a temporary namespace/veth pair:

- server side sends UDP packets containing readable text payloads in the `EBAF` packet format.
- client side receives transformed packets.
- XDP attaches to the host-side veth interface.
- the dashboard watches stats and sample packets while traffic flows.

The real interface path remains available later, but the first dashboard target is local server-to-client because it produces reliable visible ciphering on every run.

## User Experience

The dashboard should feel like a small Wireshark-style packet analyzer:

- packet timeline with newest packets at top
- before/after packet body view
- ASCII text view for readable payloads
- hex view for plaintext and ciphertext
- live counters for `seen`, `passed`, `crypto_ok`, `crypto_fail`, and `malformed`
- packets-per-second graph
- crypto-ok-per-second graph
- start, stop, and reset controls
- clear status line showing interface, mode, algorithm, port, and running state

## Architecture

Add a demo runner and a browser UI.

The runner owns the privileged networking work:

- creates veth namespace topology
- starts `build/ebaf-crypto`
- starts a local UDP sender with readable payloads
- captures sample plaintext before XDP and transformed payload after XDP
- streams JSON events to the browser
- stops XDP and deletes namespaces on exit

The browser UI stays unprivileged:

- renders server-sent events or polled JSON snapshots
- draws charts using plain browser APIs
- displays packet rows, hex, and ASCII
- provides controls that call local runner HTTP endpoints

## Components

- `scripts/demo_live_cipher.py`: privileged local demo runner and HTTP server.
- `web/demo/index.html`: dashboard shell.
- `web/demo/app.js`: event handling, chart drawing, packet table updates.
- `web/demo/styles.css`: Wireshark-like dense dashboard styling.
- `tests/integration/test_demo_runner.sh`: smoke test that starts the demo briefly and verifies JSON stats.
- `README.md`: demo instructions and presentation workflow.

## Data Flow

1. User runs `sudo scripts/demo_live_cipher.py --iface demo --mode encrypt --algo cbc-aes`.
2. Runner builds or verifies `build/ebaf-crypto`.
3. Runner creates server/client namespace topology.
4. Runner starts `ebaf-crypto` on the XDP interface.
5. Runner sends UDP `EBAF` packets with readable messages.
6. Runner captures representative packet bodies before and after transform.
7. Runner emits JSON snapshots to dashboard.
8. Browser updates table, hex/ASCII panes, and charts.
9. User stops demo; runner detaches XDP and cleans namespace.

## Safety

- Default demo uses temporary veth interfaces only.
- Real interface mode requires an explicit `--real-iface wlan0` style flag.
- XDP attach uses no-replace semantics.
- Runner uses auto-timeout by default.
- Cleanup runs on SIGINT, SIGTERM, and normal exit.

## Testing

- Existing `make check`, `make test`, `sudo make integration-test`, `sudo make correctness-test`, and `sudo make benchmark-smoke` must keep passing.
- New demo smoke test starts the runner for a short duration, fetches `/api/snapshot`, and confirms:
  - packet count increases
  - `crypto_ok` increases
  - snapshot includes ASCII plaintext
  - snapshot includes transformed hex payload

## Out Of Scope

- Full Wireshark dissector plugin.
- TLS or TCP stream reconstruction.
- Authenticated encryption proof.
- Remote multi-host demo.
