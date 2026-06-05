#!/usr/bin/env python3
import csv
import json
import re
import statistics
import sys


CSV_FIELDS = [
    "name",
    "hook",
    "mode",
    "payload_bytes",
    "samples",
    "passed",
    "pps_min",
    "pps_median",
    "pps_max",
    "crypto_ok",
    "malformed",
    "duration_sec",
    "cpu_count",
    "kernel",
]


def parse_last_counter(stdout, key):
    matches = re.findall(rf"{key}=(\d+)", stdout)
    if not matches:
        return 0
    return int(matches[-1])


def count_packet_events(stdout):
    count = 0
    for line in stdout.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(event, dict) and event.get("type") == "packet":
            count += 1
    return count


def summarize(data):
    grouped = {}
    for result in data["results"]:
        grouped.setdefault(result["name"], []).append(result)

    rows = []
    for name, results in grouped.items():
        pps = []
        crypto_ok = 0
        malformed = 0
        duration_sec = 0.0
        passed = True
        for result in results:
            match = re.search(r"pps=(\d+)", result["stdout"])
            if match:
                pps.append(int(match.group(1)))
            crypto_ok += parse_last_counter(result["stdout"], "crypto_ok")
            crypto_ok += count_packet_events(result["stdout"])
            malformed += parse_last_counter(result["stdout"], "malformed")
            duration_sec += float(result.get("duration_sec", 0.0))
            passed = passed and result["returncode"] == 0

        first = results[0]
        metadata = first.get("metadata", {})
        rows.append(
            {
                "name": name,
                "hook": first.get("hook", ""),
                "mode": first.get("mode", ""),
                "payload_bytes": first.get("payload_bytes", ""),
                "samples": len(results),
                "passed": passed,
                "pps_min": min(pps) if pps else "",
                "pps_median": int(statistics.median(pps)) if pps else "",
                "pps_max": max(pps) if pps else "",
                "crypto_ok": crypto_ok,
                "malformed": malformed,
                "duration_sec": round(duration_sec, 3),
                "cpu_count": metadata.get("cpu_count", ""),
                "kernel": metadata.get("kernel", ""),
            }
        )
    return rows


def write_csv(rows, out):
    writer = csv.DictWriter(out, fieldnames=CSV_FIELDS)
    writer.writeheader()
    writer.writerows(rows)


def print_summary(rows):
    for row in rows:
        pps = row["pps_median"] if row["pps_median"] != "" else "n/a"
        print(
            f"{row['name']} hook={row['hook']} mode={row['mode']} "
            f"samples={row['samples']} passed={row['passed']} "
            f"pps_median={pps} crypto_ok={row['crypto_ok']} "
            f"malformed={row['malformed']}"
        )


def main():
    if len(sys.argv) < 2:
        raise SystemExit("usage: analyze_experiment.py INPUT.json [OUTPUT.csv]")

    with open(sys.argv[1], encoding="utf-8") as f:
        data = json.load(f)
    rows = summarize(data)
    print_summary(rows)

    if len(sys.argv) >= 3:
        with open(sys.argv[2], "w", newline="", encoding="utf-8") as f:
            write_csv(rows, f)
        print(sys.argv[2])


if __name__ == "__main__":
    main()
