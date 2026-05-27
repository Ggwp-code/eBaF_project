#!/usr/bin/env python3
import argparse
import json
import pathlib
import subprocess
import time


def run(cmd):
    started = time.time()
    proc = subprocess.run(cmd, text=True, capture_output=True)
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
    args = parser.parse_args()

    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    results = []

    for name, target in [
        ("check", ["make", "check"]),
        ("correctness", ["sudo", "make", "correctness-test"]),
        ("benchmark", ["sudo", "make", "benchmark-smoke"]),
    ]:
        for i in range(args.repeat if name == "benchmark" else 1):
            item = run(target)
            item["name"] = name
            item["iteration"] = i
            results.append(item)

    out.write_text(json.dumps({"created_at": time.time(), "results": results}, indent=2),
                   encoding="utf-8")
    print(out)


if __name__ == "__main__":
    main()
