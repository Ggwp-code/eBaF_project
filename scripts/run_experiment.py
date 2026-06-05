#!/usr/bin/env python3
import argparse
import json
import os
import pathlib
import platform
import subprocess
import sys
import time


PAYLOAD_SIZES = [64, 512, 1200, 1408]


def build_matrix():
    cases = [
        {
            "name": "check",
            "hook": "none",
            "mode": "feature-gate",
            "payload_bytes": "",
            "cmd": ["make", "check"],
            "repeat": 1,
        },
        {
            "name": "correctness",
            "hook": "xdp",
            "mode": "encrypt-decrypt",
            "payload_bytes": "",
            "cmd": ["sudo", "make", "correctness-test"],
            "repeat": 1,
        },
        {
            "name": "local_veth_tc_encrypt_decrypt",
            "hook": "tc",
            "mode": "encrypt-decrypt",
            "payload_bytes": 16,
            "cmd": ["sudo", "make", "tc-chat-test"],
            "repeat": 1,
        },
    ]
    for payload_bytes in PAYLOAD_SIZES:
        cases.append(
            {
                "name": f"local_veth_xdp_encrypt_{payload_bytes}",
                "hook": "xdp",
                "mode": "encrypt",
                "payload_bytes": payload_bytes,
                "cmd": ["sudo", "make", "benchmark-smoke"],
                "env": {
                    "EBAF_BENCH_HOOK": "xdp",
                    "EBAF_BENCH_PAYLOAD_BYTES": str(payload_bytes),
                },
                "repeat": None,
            }
        )
        cases.append(
            {
                "name": f"local_veth_tc_encrypt_{payload_bytes}",
                "hook": "tc",
                "mode": "encrypt",
                "payload_bytes": payload_bytes,
                "cmd": ["sudo", "make", "benchmark-smoke"],
                "env": {
                    "EBAF_BENCH_HOOK": "tc",
                    "EBAF_BENCH_PAYLOAD_BYTES": str(payload_bytes),
                },
                "repeat": None,
            }
        )
        cases.append(
            {
                "name": f"local_veth_tc_encrypt_decrypt_{payload_bytes}",
                "hook": "tc",
                "mode": "encrypt-decrypt",
                "payload_bytes": payload_bytes,
                "cmd": ["sudo", "make", "tc-chat-benchmark"],
                "env": {"EBAF_BENCH_PAYLOAD_BYTES": str(payload_bytes)},
                "repeat": None,
            }
        )
    return cases


def collect_metadata():
    return {
        "kernel": platform.release(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "cpu_count": os.cpu_count() or 0,
    }


def run(cmd, env=None):
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    started = time.time()
    proc = subprocess.run(cmd, text=True, capture_output=True, env=merged_env)
    return {
        "cmd": cmd,
        "returncode": proc.returncode,
        "duration_sec": round(time.time() - started, 3),
        "stdout": proc.stdout,
        "stderr": proc.stderr,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="experiments/latest.json")
    parser.add_argument("--repeat", type=int, default=3)
    parser.add_argument("--fast", action="store_true")
    args = parser.parse_args()

    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    results = []

    matrix = build_matrix()
    total = sum(args.repeat if case["repeat"] is None else case["repeat"] for case in matrix)
    index = 0
    for case in matrix:
        repeats = 1 if args.fast else args.repeat if case["repeat"] is None else case["repeat"]
        for iteration in range(repeats):
            index += 1
            print(
                f"[{index}/{total}] {case['name']} iter={iteration + 1}/{repeats}",
                flush=True,
                file=sys.stderr,
            )
            item = run(case["cmd"], case.get("env"))
            item["name"] = case["name"]
            item["hook"] = case["hook"]
            item["mode"] = case["mode"]
            item["payload_bytes"] = case["payload_bytes"]
            item["iteration"] = iteration
            item["metadata"] = collect_metadata()
            results.append(item)

    out.write_text(
        json.dumps({"created_at": time.time(), "results": results}, indent=2),
        encoding="utf-8",
    )
    print(out)


if __name__ == "__main__":
    main()
