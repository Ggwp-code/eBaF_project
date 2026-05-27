#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
	echo "SKIP: live dashboard smoke needs root"
	exit 77
fi

for cmd in ip python3 timeout; do
	if ! command -v "${cmd}" >/dev/null 2>&1; then
		echo "SKIP: ${cmd} missing"
		exit 77
	fi
done

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LOG="$(mktemp)"
PORT="18088"
PID=""

cleanup()
{
	if [[ -n "${PID}" ]] && kill -0 "${PID}" >/dev/null 2>&1; then
		kill -TERM "${PID}" >/dev/null 2>&1 || true
		wait "${PID}" >/dev/null 2>&1 || true
	fi
	rm -f "${LOG}"
}
trap cleanup EXIT

cd "${ROOT_DIR}"
timeout --preserve-status 45s scripts/demo_live_cipher.py --host 127.0.0.1 --port "${PORT}" --duration 30 >"${LOG}" 2>&1 &
PID=$!

for _ in $(seq 1 20); do
	if grep -q "dashboard http://127.0.0.1:${PORT}" "${LOG}"; then
		break
	fi
	if ! kill -0 "${PID}" >/dev/null 2>&1; then
		cat "${LOG}"
		echo "FAIL: demo runner exited early"
		exit 1
	fi
	sleep 0.5
done

if ! python3 - "http://127.0.0.1:${PORT}/api/snapshot" <<'PY'
import json
import sys
import time
import urllib.request
import urllib.error

url = sys.argv[1]
last = {}
for _ in range(20):
    try:
        with urllib.request.urlopen(url, timeout=2) as resp:
            last = json.load(resp)
    except urllib.error.URLError:
        time.sleep(0.5)
        continue
    stats = last.get("stats", {})
    packets = last.get("packets", [])
    has_ascii = any(p.get("plain_ascii") for p in packets)
    has_cipher = any(p.get("cipher_hex") for p in packets)
    if stats.get("crypto_ok", 0) > 0 and packets and has_ascii and has_cipher:
        print("live dashboard smoke passed")
        raise SystemExit(0)
    time.sleep(1)

print(json.dumps(last, indent=2))
raise SystemExit(
    "snapshot did not show live ciphering "
    f"(sender_count={last.get('sender_count')} capture_count={last.get('capture_count')} "
    f"stats={last.get('stats')} app_lines={last.get('app_lines')})"
)
PY
then
	cat "${LOG}"
	exit 1
fi
