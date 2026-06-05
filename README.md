# eBaF: eBPF In-Kernel UDP Crypto

eBaF is a Linux research prototype for encrypting UDP payloads inside the kernel with eBPF, XDP, TC, libbpf, and BPF crypto kfuncs.

It proves a real packet path:

- Normal UDP apps can send plaintext.
- TC transparent mode can pad, encrypt, and append crypto metadata.
- A peer TC hook can decrypt before the receiving app sees the packet.
- XDP and TC paths expose counters, packet events, proof artifacts, and repeatable benchmarks.

This is lab software, not production security software.

## What It Shows

- `xdp`: packet crypto for `EBAF`-framed IPv4/UDP payloads.
- `tc`: encrypt/decrypt path over veth and physical NIC egress.
- `tc --transparent`: normal UDP payloads transformed without changing the app.
- Live dashboard: Wireshark-like view of TC transparent UDP media traffic.
- Physical NIC probe: native/generic XDP support, queues, IRQ hints, driver/offload metadata where available.
- Benchmarks: local veth PPS, correctness proof, malformed packet counters.

## Requirements

- Linux kernel with BTF enabled
- BPF crypto kfuncs visible through `/sys/kernel/btf/vmlinux`
- `clang`, `bpftool`, `iproute2`, `make`
- libbpf development headers
- `ffmpeg` for the live media dashboard

Check the host first:

```bash
make check
```

## Quick Start

Build:

```bash
make
```

Run the full backend gate:

```bash
sudo make backend-gate
```

Run a live TC transparent media dashboard:

```bash
sudo python3 scripts/demo_live_cipher.py --port 8000
```

Open:

```text
http://127.0.0.1:8000
```

Use your own video as UDP source:

```bash
sudo python3 scripts/demo_live_cipher.py --port 8000 --media-file /path/to/video.mp4
```

## Runtime Examples

XDP or TC framed packet mode:

```bash
sudo ./build/ebaf-crypto --iface eth0 --mode encrypt --hook xdp --key <32-hex-char-aes128-key> --port 7777 --events --jsonl
```

TC transparent mode:

```bash
sudo ./build/ebaf-crypto --iface eth0 --mode encrypt --hook tc --transparent --key <32-hex-char-aes128-key> --port 7777 --events --jsonl
```

Decrypt transparent traffic on the peer:

```bash
sudo ./build/ebaf-crypto --iface eth0 --mode decrypt --hook tc --transparent --key <32-hex-char-aes128-key> --port 7777 --events --jsonl
```

Generate a fresh AES key before running traffic outside the integration scripts.

## Useful Commands

```bash
make test
sudo make integration-test
sudo make correctness-test
sudo make protocol-validation-test
sudo make tc-transparent-test
sudo make benchmark-smoke
sudo make experiment
sudo make packet-proof
```

Physical NIC profile:

```bash
sudo make physical-profile IFACE=wlan0
cat experiments/physical-profile-wlan0.json
```

Physical TC send-only demo:

```bash
sudo make physical-tc-demo IFACE=wlan0 PEER_IP=$(ip route | awk '/default/ {print $3; exit}')
cat experiments/physical-tc-demo-wlan0.json
```

## Dashboard

The dashboard starts a temporary veth pair and network namespace.

Default mode:

- TC encrypt on host egress
- TC decrypt on namespace ingress
- `ffmpeg` generates MPEG-TS UDP media
- namespace UDP receiver counts decrypted packets
- browser reads `/api/snapshot`, `/api/artifacts`, and `/api/capabilities`

Smoke test:

```bash
sudo make demo-smoke
```

## Packet Formats

### Framed XDP/TC Mode

UDP payload begins with:

- marker: `EBAF`
- version: `1`
- action: `1` encrypt or `2` decrypt
- payload length: big-endian 16-bit value
- IV: 16 bytes
- body: plaintext or ciphertext

AES-CBC bodies must be 16-byte aligned.

### TC Transparent Mode

Application sends normal UDP payload.

Encrypt path:

1. pad payload to AES-CBC block size
2. encrypt payload in place
3. append eBaF tail metadata with IV and body length
4. repair packet length fields

Decrypt path:

1. read tail metadata
2. decrypt body in place
3. remove padding and metadata
4. deliver plaintext UDP payload to the receiver

## Crypto Modes

- `cbc-aes`: kernel `cbc(aes)`, AES-128-CBC
- `chacha20`: kernel `chacha20`, 256-bit stream cipher, framed path only

`chacha20poly1305` is not exposed through this tested BPF crypto path. Authenticated encryption remains future work.

## Evidence Artifacts

Generated files:

- `experiments/latest.json`
- `experiments/latest.csv`
- `experiments/packet-proof.json`
- `experiments/physical-profile-<iface>.json`
- `experiments/physical-tc-demo-<iface>.json`

Typical green signals:

```text
tc transparent udp crypto passed
ciphertext_differs=True
decrypt_matches=True
```

## Safety

Run this first inside a network namespace or lab host. XDP and TC programs can modify live traffic. Physical NIC results depend on driver support, offloads, DMA path, IRQ behavior, and whether native XDP is available.
