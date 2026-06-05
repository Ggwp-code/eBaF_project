#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
	echo "SKIP: tc udp benchmark needs root"
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
SENDER_BIN="${ROOT_DIR}/build/udp-bench-sender"
KEY="000102030405060708090a0b0c0d0e0f"
UDP_PORT="7777"
DURATION="${EBAF_BENCH_DURATION:-5}"
PAYLOAD_BYTES="${EBAF_BENCH_PAYLOAD_BYTES:-64}"
NS="ebaftcb$$"
HOST_IF="ebaftcbh$$"
NS_IF="ebaftcbp$$"
ENC_LOG="$(mktemp)"
DEC_LOG="$(mktemp)"
COUNT_FILE="$(mktemp)"
ENC_PID=""
DEC_PID=""

cleanup()
{
	for pid in "${ENC_PID}" "${DEC_PID}"; do
		if [[ -n "${pid}" ]] && kill -0 "${pid}" >/dev/null 2>&1; then
			kill -TERM "${pid}" >/dev/null 2>&1 || true
			wait "${pid}" >/dev/null 2>&1 || true
		fi
	done
	ip netns del "${NS}" >/dev/null 2>&1 || true
	ip link del "${HOST_IF}" >/dev/null 2>&1 || true
	rm -f "${ENC_LOG}" "${DEC_LOG}" "${COUNT_FILE}"
}
trap cleanup EXIT

ip netns add "${NS}"
ip link add "${HOST_IF}" type veth peer name "${NS_IF}"
ip link set "${NS_IF}" netns "${NS}"
ip addr add 10.79.0.1/24 dev "${HOST_IF}"
ip link set "${HOST_IF}" up
ip netns exec "${NS}" ip addr add 10.79.0.2/24 dev "${NS_IF}"
ip netns exec "${NS}" ip link set lo up
ip netns exec "${NS}" ip link set "${NS_IF}" up

timeout --preserve-status "$((DURATION + 6))s" "${BIN}" --iface "${HOST_IF}" \
	--mode encrypt --hook tc --key "${KEY}" --port "${UDP_PORT}" \
	--stats-interval 1 --duration "$((DURATION + 2))" >"${ENC_LOG}" 2>&1 &
ENC_PID=$!

timeout --preserve-status "$((DURATION + 6))s" ip netns exec "${NS}" "${BIN}" \
	--iface "${NS_IF}" --mode decrypt --hook tc --key "${KEY}" \
	--port "${UDP_PORT}" --stats-interval 1 --duration "$((DURATION + 2))" \
	>"${DEC_LOG}" 2>&1 &
DEC_PID=$!

sleep 2
for entry in "encrypt:${ENC_PID}:${ENC_LOG}" "decrypt:${DEC_PID}:${DEC_LOG}"; do
	IFS=: read -r name pid log <<<"${entry}"
	if ! kill -0 "${pid}" >/dev/null 2>&1; then
		cat "${log}"
		echo "FAIL: ${name} ebaf-crypto exited before benchmark"
		exit 1
	fi
done

ip netns exec "${NS}" python3 - "${UDP_PORT}" "${DURATION}" "${COUNT_FILE}" "${PAYLOAD_BYTES}" <<'PY' &
import socket
import struct
import sys
import time

port, duration, count_path, payload_bytes = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3], int(sys.argv[4])
header = struct.Struct("!IBBH16s")
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("10.79.0.2", port))
sock.settimeout(0.2)
deadline = time.monotonic() + duration + 2
count = 0
while time.monotonic() < deadline:
    try:
        data, _ = sock.recvfrom(65535)
    except socket.timeout:
        continue
    if len(data) < header.size:
        continue
    magic, version, action, payload_len, _ = header.unpack_from(data)
    body = data[header.size:]
    if magic == 0x45424146 and version == 1 and action == 1 and payload_len == len(body):
        if body == b"A" * (payload_bytes - 1) + b"\x01":
            count += 1
sock.close()
with open(count_path, "w", encoding="ascii") as f:
    f.write(str(count))
PY
RECV_PID=$!

"${SENDER_BIN}" 10.79.0.2 "${UDP_PORT}" "${DURATION}" "${PAYLOAD_BYTES}"

wait "${RECV_PID}" || true
received="$(cat "${COUNT_FILE}")"

kill -TERM "${ENC_PID}" "${DEC_PID}" >/dev/null 2>&1 || true
wait "${ENC_PID}" >/dev/null 2>&1 || true
wait "${DEC_PID}" >/dev/null 2>&1 || true
ENC_PID=""
DEC_PID=""

enc_ok="$(grep -Eo 'crypto_ok=[0-9]+' "${ENC_LOG}" | tail -n 1 | cut -d= -f2)"
dec_ok="$(grep -Eo 'crypto_ok=[0-9]+' "${DEC_LOG}" | tail -n 1 | cut -d= -f2)"
enc_bad="$(grep -Eo 'malformed=[0-9]+' "${ENC_LOG}" | tail -n 1 | cut -d= -f2)"
dec_bad="$(grep -Eo 'malformed=[0-9]+' "${DEC_LOG}" | tail -n 1 | cut -d= -f2)"
enc_ok="${enc_ok:-0}"
dec_ok="${dec_ok:-0}"
enc_bad="${enc_bad:-0}"
dec_bad="${dec_bad:-0}"
crypto_ok=$((enc_ok + dec_ok))
malformed=$((enc_bad + dec_bad))
pps=$((received / DURATION))

if [[ "${received}" -eq 0 || "${crypto_ok}" -eq 0 ]]; then
	cat "${ENC_LOG}"
	cat "${DEC_LOG}"
	echo "FAIL: tc udp benchmark saw no decrypted packets"
	exit 1
fi

echo "tc udp benchmark received=${received} duration=${DURATION}s pps=${pps} crypto_ok=${crypto_ok} malformed=${malformed}"
