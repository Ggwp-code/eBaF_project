#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${ROOT_DIR}/build/ebaf-crypto"
OUT_DIR="${ROOT_DIR}/experiments"
IFACE="${IFACE:-${1:-}}"
PEER_IP="${PEER_IP:-}"
PORT="${PORT:-7777}"
COUNT="${COUNT:-8}"
KEY="${KEY:-000102030405060708090a0b0c0d0e0f}"
LOG_FILE="$(mktemp)"
CLIENT_LOG="$(mktemp)"
APP_PID=""

usage()
{
	echo "usage: sudo make physical-tc-demo IFACE=<iface> PEER_IP=<ip> [PORT=7777] [COUNT=8]" >&2
}

cleanup()
{
	if [[ -n "${APP_PID}" ]] && kill -0 "${APP_PID}" >/dev/null 2>&1; then
		kill -TERM "${APP_PID}" >/dev/null 2>&1 || true
		wait "${APP_PID}" >/dev/null 2>&1 || true
	fi
	rm -f "${LOG_FILE}" "${CLIENT_LOG}"
}
trap cleanup EXIT

if [[ -z "${IFACE}" || -z "${PEER_IP}" ]]; then
	usage
	exit 2
fi
if [[ "${EUID}" -ne 0 ]]; then
	echo "SKIP: physical TC demo needs root"
	exit 77
fi
for cmd in ip python3 timeout grep; do
	if ! command -v "${cmd}" >/dev/null 2>&1; then
		echo "missing command: ${cmd}" >&2
		exit 2
	fi
done
if [[ ! -d "/sys/class/net/${IFACE}" ]]; then
	echo "interface not found: ${IFACE}" >&2
	exit 2
fi
if [[ ! -x "${BIN}" ]]; then
	echo "missing binary: ${BIN}" >&2
	exit 2
fi

mkdir -p "${OUT_DIR}"
OUT="${OUT_DIR}/physical-tc-demo-${IFACE}.json"

timeout --preserve-status 10s "${BIN}" --iface "${IFACE}" --mode encrypt \
	--hook tc --transparent --key "${KEY}" --port "${PORT}" --stats-interval 1 \
	--duration 6 --jsonl >"${LOG_FILE}" 2>&1 &
APP_PID=$!

sleep 2
if ! kill -0 "${APP_PID}" >/dev/null 2>&1; then
	cat "${LOG_FILE}"
	echo "FAIL: ebaf-crypto exited before physical TC traffic" >&2
	exit 1
fi

python3 - "${PEER_IP}" "${PORT}" "${COUNT}" >"${CLIENT_LOG}" 2>&1 <<'PY'
import socket
import sys
import time

peer, port, count = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for seq in range(1, count + 1):
    msg = f"physical tc normal udp seq={seq:04d}".encode("ascii")
    sent = sock.sendto(msg, (peer, port))
    print(f"sent {peer}:{port} seq={seq} bytes={sent}")
    time.sleep(0.05)
PY

wait "${APP_PID}" >/dev/null 2>&1 || true
APP_PID=""

python3 - "${OUT}" "${IFACE}" "${PEER_IP}" "${PORT}" "${COUNT}" "${LOG_FILE}" "${CLIENT_LOG}" <<'PY'
import json
import re
import sys
import time

out, iface, peer_ip, port, count, log_path, client_path = sys.argv[1:]
stats = {}
events = []
stats_re = re.compile(r"([a-z_]+)=([0-9]+)")

with open(log_path, "r", encoding="utf-8", errors="replace") as f:
    for line in f:
        line = line.strip()
        if line.startswith("{"):
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("type") == "packet":
                events.append(event)
            continue
        for key, value in stats_re.findall(line):
            stats[key] = int(value)

with open(client_path, "r", encoding="utf-8", errors="replace") as f:
    client_lines = [line.rstrip() for line in f][-20:]

profile = {
    "created_at": time.time(),
    "interface": iface,
    "peer_ip": peer_ip,
    "port": int(port),
    "sent": int(count),
    "hook": "tc",
    "mode": "encrypt",
    "scope": "physical interface transparent UDP send-only",
    "stats": stats,
    "events": events[-20:],
    "client_lines": client_lines,
    "notes": [
        "This sends normal UDP packets through the selected physical interface.",
        "Only encryption is proven here. Decryption needs a second endpoint running the matching TC decrypt program.",
        "The program filters by UDP destination port, so unrelated traffic is passed."
    ],
}
with open(out, "w", encoding="utf-8") as f:
    json.dump(profile, f, indent=2)
print(out)
print(f"crypto_ok={stats.get('crypto_ok', 0)} malformed={stats.get('malformed', 0)} events={len(events)}")
PY

if ! grep -Eq 'crypto_ok=[1-9][0-9]*' "${LOG_FILE}"; then
	cat "${LOG_FILE}"
	echo "FAIL: physical TC demo did not encrypt packets" >&2
	exit 1
fi
