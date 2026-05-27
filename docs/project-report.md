# Project Report

## Summary

This project implements an eBPF/XDP in-network cryptography prototype. It separates crypto context creation from packet processing, shares kernel crypto state through a referenced kptr map, and keeps the XDP program focused on bounded packet parsing, kfunc execution, and per-CPU stats.

## Implemented Scope

- libbpf CO-RE build pipeline
- Kernel feature probe
- Syscall BPF crypto context creation
- XDP packet processing program
- User-space loader and stats loop
- Ethernet/IPv4/UDP parser with configurable destination port
- Config parser unit tests
- Namespace and veth integration smoke test
- Crafted UDP `EBAF` packet crypto-path assertion
- Root-only benchmark smoke workflow
- README verification workflow

## Verification

```bash
make check
make
make test
sudo make integration-test
sudo make correctness-test
sudo make benchmark-smoke
```

Expected integration result:

```text
integration crypto smoke passed
```

## Constraints

- Requires a kernel that exposes BPF crypto kfuncs through BTF.
- Requires root privileges for XDP attachment and network namespace tests.
- Supports `cbc(aes)` with packet-carried IV and AES block-aligned payloads.
- Supports `chacha20` as an unauthenticated stream cipher fallback; `chacha20poly1305` is not exposed through the tested BPF crypto kfunc path.
- Per-packet cryptography can saturate CPU under high packet rates.
- IPv4/UDP parsing is intentionally narrow; VLAN, IPv6, and fragmented traffic pass through.

## Future Work

- Add safer cipher mode support when kernel crypto kfunc constraints allow it.
- Add VLAN and IPv6 parser coverage.
- Add QAT offload path for high-throughput symmetric crypto.
- Add SmartNIC offload path for XDP-capable NICs.
- Add PQC control-plane prototype for Kyber or Dilithium key operations.
- Add packet generator integration with pktgen or MoonGen.
- Add CI job that runs unit tests on normal hosts and labels BPF integration tests as privileged.
