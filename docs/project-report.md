# Project Report

## Summary

This project implements an eBPF/XDP in-network cryptography prototype. It separates crypto context creation from packet processing, shares kernel crypto state through a referenced kptr map, and keeps the XDP program focused on bounded packet parsing, kfunc execution, and per-CPU stats.

## Implemented Scope

- libbpf CO-RE build pipeline
- Kernel feature probe
- Syscall BPF crypto context creation
- XDP packet processing program
- User-space loader and stats loop
- Config parser unit tests
- Namespace and veth integration smoke test
- Crafted `EBAF` packet crypto-path assertion
- README verification workflow

## Verification

```bash
make check
make
make test
sudo make integration-test
```

Expected integration result:

```text
integration crypto smoke passed
```

## Constraints

- Requires a kernel that exposes BPF crypto kfuncs through BTF.
- Requires root privileges for XDP attachment and network namespace tests.
- Uses `ecb(aes)` for prototype compatibility; do not treat this as production cryptography.
- Per-packet cryptography can saturate CPU under high packet rates.

## Future Work

- Add safer cipher mode support when kernel crypto kfunc constraints allow it.
- Add QAT offload path for high-throughput symmetric crypto.
- Add SmartNIC offload path for XDP-capable NICs.
- Add PQC control-plane prototype for Kyber or Dilithium key operations.
- Add packet generator integration with pktgen or MoonGen.
- Add CI job that runs unit tests on normal hosts and labels BPF integration tests as privileged.
