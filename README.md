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
sudo ./build/ebaf-crypto --iface eth0 --mode decrypt --key 000102030405060708090a0b0c0d0e0f
```

## Tests

```bash
make test
sudo make integration-test
```

The integration test creates a temporary network namespace and veth pair, attaches the XDP program, sends ping traffic plus a crafted `EBAF` frame, and expects:

```text
integration crypto smoke passed
```

## Safety

Run first inside a network namespace or lab host. XDP programs can drop or modify live traffic.
