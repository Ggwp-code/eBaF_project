#!/usr/bin/env python3
import argparse
import json
import os
import pathlib
import subprocess
import time


PLAINTEXT = "hello real app"
PLAINTEXT_PADDED_HEX = (PLAINTEXT.encode("utf-8") + b"\x02\x02").hex()


def packet_events(stdout):
    events = []
    for line in stdout.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(event, dict) and event.get("type") == "packet":
            events.append(event)
    return events


def build_proof(stdout):
    encrypted = ""
    decrypted = ""
    for event in packet_events(stdout):
        if event.get("action") == "encrypt" and not encrypted:
            encrypted = event.get("sample", "")
        if event.get("action") == "decrypt" and not decrypted:
            decrypted = event.get("sample", "")

    if not encrypted or not decrypted:
        raise ValueError("missing encrypt/decrypt packet samples")

    return {
        "created_at": time.time(),
        "plaintext": PLAINTEXT,
        "plaintext_padded_hex": PLAINTEXT_PADDED_HEX,
        "encrypted_sample_hex": encrypted,
        "decrypted_sample_hex": decrypted,
        "ciphertext_differs": encrypted != PLAINTEXT_PADDED_HEX,
        "decrypt_matches": decrypted == PLAINTEXT_PADDED_HEX,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="experiments/packet-proof.json")
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("SKIP: packet proof needs root")
        return 77

    proc = subprocess.run(["make", "tc-chat-test"], text=True, capture_output=True)
    if proc.returncode != 0:
        print(proc.stdout, end="")
        print(proc.stderr, end="")
        return proc.returncode

    proof = build_proof(proc.stdout)
    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(proof, indent=2), encoding="utf-8")
    print(out)
    print(f"ciphertext_differs={proof['ciphertext_differs']}")
    print(f"decrypt_matches={proof['decrypt_matches']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
