#!/usr/bin/env python3
import json
import re
import statistics
import sys


data = json.load(open(sys.argv[1], encoding="utf-8"))
pps = []
for result in data["results"]:
    match = re.search(r"pps=(\d+)", result["stdout"])
    if match:
        pps.append(int(match.group(1)))

if not pps:
    raise SystemExit("no pps samples found")

print(f"samples={len(pps)}")
print(f"pps_min={min(pps)}")
print(f"pps_median={int(statistics.median(pps))}")
print(f"pps_max={max(pps)}")
