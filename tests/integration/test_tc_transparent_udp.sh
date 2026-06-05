#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
	echo "SKIP: tc transparent udp test needs root"
	exit 77
fi

for cmd in ip python3 timeout grep; do
	if ! command -v "${cmd}" >/dev/null 2>&1; then
		echo "SKIP: ${cmd} missing"
		exit 77
	fi
done

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${ROOT_DIR}/build/ebaf-crypto"
KEY="000102030405060708090a0b0c0d0e0f"
UDP_PORT="7777"
NS="ebaftr$$"
HOST_IF="ebaftrh$$"
NS_IF="ebaftrp$$"
SERVER_LOG="$(mktemp)"
ENC_LOG="$(mktemp)"
DEC_LOG="$(mktemp)"
READY_FILE="$(mktemp)"
SERVER_PID=""
ENC_PID=""
DEC_PID=""

cleanup()
{
	for pid in "${ENC_PID}" "${DEC_PID}" "${SERVER_PID}"; do
		if [[ -n "${pid}" ]] && kill -0 "${pid}" >/dev/null 2>&1; then
			kill -TERM "${pid}" >/dev/null 2>&1 || true
			wait "${pid}" >/dev/null 2>&1 || true
		fi
	done
	ip netns del "${NS}" >/dev/null 2>&1 || true
	ip link del "${HOST_IF}" >/dev/null 2>&1 || true
	rm -f "${SERVER_LOG}" "${ENC_LOG}" "${DEC_LOG}" "${READY_FILE}"
}
trap cleanup EXIT

ip netns add "${NS}"
ip link add "${HOST_IF}" type veth peer name "${NS_IF}"
ip link set "${NS_IF}" netns "${NS}"
ip addr add 10.81.0.1/24 dev "${HOST_IF}"
ip link set "${HOST_IF}" up
ip netns exec "${NS}" ip addr add 10.81.0.2/24 dev "${NS_IF}"
ip netns exec "${NS}" ip link set lo up
ip netns exec "${NS}" ip link set "${NS_IF}" up

timeout --preserve-status 12s "${BIN}" --iface "${HOST_IF}" --mode encrypt \
	--hook tc --transparent --key "${KEY}" --port "${UDP_PORT}" \
	--stats-interval 1 --jsonl >"${ENC_LOG}" 2>&1 &
ENC_PID=$!

timeout --preserve-status 12s ip netns exec "${NS}" "${BIN}" --iface "${NS_IF}" \
	--mode decrypt --hook tc --transparent --key "${KEY}" --port "${UDP_PORT}" \
	--stats-interval 1 --jsonl >"${DEC_LOG}" 2>&1 &
DEC_PID=$!

sleep 2

ip netns exec "${NS}" python3 - "${UDP_PORT}" "${READY_FILE}" >"${SERVER_LOG}" 2>&1 <<'PY' &
import socket
import sys

port = int(sys.argv[1])
ready_file = sys.argv[2]
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("10.81.0.2", port))
with open(ready_file, "w", encoding="ascii") as ready:
	ready.write("ready\n")
sock.settimeout(8)
data, _ = sock.recvfrom(65535)
print(data.decode("ascii", errors="replace"))
PY
SERVER_PID=$!

for _ in {1..50}; do
	if [[ -s "${READY_FILE}" ]]; then
		break
	fi
	sleep 0.1
done
if [[ ! -s "${READY_FILE}" ]]; then
	cat "${SERVER_LOG}" || true
	echo "FAIL: transparent UDP server not ready"
	exit 1
fi

python3 - "${UDP_PORT}" <<'PY'
import socket
import sys

port = int(sys.argv[1])
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(b"hello transparent udp", ("10.81.0.2", port))
PY

wait "${SERVER_PID}" || {
	cat "${ENC_LOG}" || true
	cat "${DEC_LOG}" || true
	cat "${SERVER_LOG}" || true
	echo "FAIL: transparent UDP server did not receive plaintext"
	exit 1
}
SERVER_PID=""

sleep 2
kill -TERM "${ENC_PID}" "${DEC_PID}" >/dev/null 2>&1 || true
wait "${ENC_PID}" >/dev/null 2>&1 || true
wait "${DEC_PID}" >/dev/null 2>&1 || true
ENC_PID=""
DEC_PID=""

grep -q "hello transparent udp" "${SERVER_LOG}" || {
	cat "${SERVER_LOG}"
	cat "${ENC_LOG}" || true
	cat "${DEC_LOG}" || true
	echo "FAIL: transparent plaintext missing"
	exit 1
}
grep -Eq 'crypto_ok=[1-9][0-9]*' "${ENC_LOG}" || {
	cat "${ENC_LOG}"
	echo "FAIL: transparent encrypt crypto_ok missing"
	exit 1
}
grep -Eq 'crypto_ok=[1-9][0-9]*' "${DEC_LOG}" || {
	cat "${DEC_LOG}"
	echo "FAIL: transparent decrypt crypto_ok missing"
	exit 1
}

echo "tc transparent udp crypto passed"
