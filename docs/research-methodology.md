# Research Methodology

## Scope

Studies in-kernel UDP payload transformation using eBPF/XDP and Linux BPF crypto kfuncs.

## Research Questions

- Can eBPF/XDP transform UDP payloads in-kernel using Linux BPF crypto kfuncs?
- What verifier and protocol constraints shape a safe packet data path?
- What observability is required to validate packet transformation behavior?
- What performance cost does in-kernel UDP payload transformation add versus pass-through XDP?

## Non-Goals

- Production confidentiality
- Authenticated encryption
- TCP reassembly
- Key exchange
- Persistent key management

## Threat Model

Packets already carry an `EBAF` protocol header and IV. The XDP program transforms only matching IPv4/UDP packets on the configured destination port. Attackers can inject malformed packets; the program must pass or count them without crashing, verifier rejection, or out-of-bounds access.

## Evidence Required

- Correctness: encrypt changes body; decrypt restores body.
- Validation: malformed protocol packets increment reason counters.
- Observability: ring-buffer events show transformed packet metadata.
- Performance: reproducible packets-per-second and CPU observations across pass-through, encrypt, and decrypt modes.
