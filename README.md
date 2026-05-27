# eBPF XDP Cryptography Prototype

This project implements an in-network cryptography prototype with eBPF and XDP.

## Requirements

- Linux kernel with BTF enabled
- BPF crypto kfunc support visible through `/sys/kernel/btf/vmlinux`
- clang and llc from LLVM
- libbpf development headers
- bpftool
- iproute2
- make

Run `make check` before building. The probe fails fast when the running kernel cannot load this prototype.

## Quick Start

```bash
make check
make
sudo ./build/ebaf-crypto --iface eth0 --mode decrypt --key <32-hex-char-aes128-key> --port 7777
```

For lab-only testing, `000102030405060708090a0b0c0d0e0f` is the fixed AES-128 sample key used by the integration scripts. Use a generated secret key for real traffic.

Optional runtime flags:

- `--algo cbc-aes|chacha20`: cipher to use, default `cbc-aes`
- `--port PORT`: UDP destination port to process, default `7777`
- `--stats-interval SEC`: stats print interval, default `1`
- `--duration SEC`: exit automatically after this many seconds

`cbc-aes` uses a 16-byte key encoded as 32 hex characters. `chacha20` uses a 32-byte key encoded as 64 hex characters. `chacha20poly1305` is not exposed through this BPF crypto path on the tested kernel, so authenticated encryption remains future work outside this XDP kfunc path.

## Tests

```bash
make test
sudo make integration-test
sudo make correctness-test
sudo make benchmark-smoke
```

The integration test creates a temporary network namespace and veth pair, attaches the XDP program, sends ping traffic plus a crafted Ethernet/IPv4/UDP packet carrying an `EBAF` payload, and expects:

```text
integration crypto smoke passed
```

The benchmark smoke test sends `EBAF` UDP packets for a short fixed duration and prints a packets-per-second sample.

The correctness test encrypts a known plaintext body, feeds the captured ciphertext through decrypt mode, and expects the original plaintext.

## Live Cipher Dashboard

Run a local server-to-client demo with real packets crossing a temporary veth pair:

```bash
sudo scripts/demo_live_cipher.py --duration 30
```

Open:

```text
http://127.0.0.1:8088
```

The dashboard shows a Wireshark-style packet timeline, plaintext ASCII, plaintext hex, ciphertext hex, live counters, and throughput graphs. It cleans up the namespace and detaches XDP when stopped.

Smoke test:

```bash
sudo make demo-smoke
```

## Packet Format

The XDP program processes IPv4/UDP packets whose destination port matches `--port`. UDP payload starts with:

- magic: `EBAF`
- version: `1`
- action: `1` encrypt or `2` decrypt
- payload length: big-endian 16-bit value
- IV: 16 bytes
- body: cipher text/plaintext bytes; AES-CBC bodies must be 16-byte aligned

Supported crypto modes:

- `cbc-aes`: kernel `cbc(aes)`, AES-128-CBC
- `chacha20`: kernel `chacha20`, 256-bit key stream cipher without Poly1305 authentication

## Safety

Run first inside a network namespace or lab host. XDP programs can drop or modify live traffic.
