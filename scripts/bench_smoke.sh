#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
	echo "SKIP: benchmark smoke needs root"
	exit 77
fi

for cmd in ip python3 timeout; do
	if ! command -v "${cmd}" >/dev/null 2>&1; then
		echo "SKIP: ${cmd} missing"
		exit 77
	fi
done

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${ROOT_DIR}/build/ebaf-crypto"
KEY="000102030405060708090a0b0c0d0e0f"
UDP_PORT="7777"
DURATION="${EBAF_BENCH_DURATION:-5}"
HOOK="${EBAF_BENCH_HOOK:-xdp}"
PAYLOAD_BYTES="${EBAF_BENCH_PAYLOAD_BYTES:-64}"
NS="ebafbench$$"
HOST_IF="ebafbh$$"
NS_IF="ebafbp$$"
LOG="$(mktemp)"
COUNT_FILE="$(mktemp)"
APP_PID=""

cleanup()
{
	if [[ -n "${APP_PID}" ]] && kill -0 "${APP_PID}" >/dev/null 2>&1; then
		kill -TERM "${APP_PID}" >/dev/null 2>&1 || true
		wait "${APP_PID}" >/dev/null 2>&1 || true
	fi
	ip netns del "${NS}" >/dev/null 2>&1 || true
	ip link del "${HOST_IF}" >/dev/null 2>&1 || true
	rm -f "${LOG}" "${COUNT_FILE}"
}
trap cleanup EXIT

ip netns add "${NS}"
ip link add "${HOST_IF}" type veth peer name "${NS_IF}"
ip link set "${NS_IF}" netns "${NS}"
ip addr add 10.88.0.1/24 dev "${HOST_IF}"
ip link set "${HOST_IF}" up
ip netns exec "${NS}" ip addr add 10.88.0.2/24 dev "${NS_IF}"
ip netns exec "${NS}" ip link set lo up
ip netns exec "${NS}" ip link set "${NS_IF}" up
HOST_MAC="$(cat "/sys/class/net/${HOST_IF}/address")"
NS_MAC="$(ip netns exec "${NS}" cat "/sys/class/net/${NS_IF}/address")"

if [[ "${HOOK}" = "tc" ]]; then
	timeout --preserve-status "$((DURATION + 5))s" "${BIN}" --iface "${HOST_IF}" --mode encrypt --hook tc --key "${KEY}" --port "${UDP_PORT}" --stats-interval 1 --duration "$((DURATION + 1))" >"${LOG}" 2>&1 &
else
	timeout --preserve-status "$((DURATION + 5))s" "${BIN}" --iface "${HOST_IF}" --mode encrypt --hook xdp --key "${KEY}" --port "${UDP_PORT}" --stats-interval 1 --duration "$((DURATION + 1))" >"${LOG}" 2>&1 &
fi
APP_PID=$!
sleep 2

if ! kill -0 "${APP_PID}" >/dev/null 2>&1; then
	cat "${LOG}"
	echo "FAIL: ebaf-crypto exited before benchmark"
	exit 1
fi

SENDER=(ip netns exec "${NS}" python3 - "${NS_IF}" "${NS_MAC}" "${HOST_MAC}" "${UDP_PORT}" "${DURATION}" "${COUNT_FILE}" "xdp" "${PAYLOAD_BYTES}")
if [[ "${HOOK}" = "tc" ]]; then
	SENDER=(python3 - "${HOST_IF}" "${HOST_MAC}" "${NS_MAC}" "${UDP_PORT}" "${DURATION}" "${COUNT_FILE}" "tc" "${PAYLOAD_BYTES}")
fi

"${SENDER[@]}" <<'PY'
import socket
import struct
import sys
import time

iface, src_mac_text, dst_mac_text, dst_port_text, duration_text, count_path, hook, payload_bytes_text = sys.argv[1:]
src_mac = bytes.fromhex(src_mac_text.replace(":", ""))
dst_mac = bytes.fromhex(dst_mac_text.replace(":", ""))
dst_port = int(dst_port_text)
duration = int(duration_text)
payload_bytes = int(payload_bytes_text)
if payload_bytes % 16 != 0:
    raise SystemExit("payload bytes must be 16-byte aligned")
payload = b"A" * payload_bytes
udp_payload = b"EBAF" + bytes([1, 1]) + len(payload).to_bytes(2, "big") + bytes(range(16)) + payload
if hook == "tc":
    src_ip = socket.inet_aton("10.88.0.1")
    dst_ip = socket.inet_aton("10.88.0.2")
else:
    src_ip = socket.inet_aton("10.88.0.2")
    dst_ip = socket.inet_aton("10.88.0.1")
udp = struct.pack("!HHHH", 4242, dst_port, 8 + len(udp_payload), 0)
total_len = 20 + len(udp) + len(udp_payload)
ip_without_sum = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_len, 0, 0, 64, socket.IPPROTO_UDP, 0, src_ip, dst_ip)

def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF

ip = ip_without_sum[:10] + struct.pack("!H", checksum(ip_without_sum)) + ip_without_sum[12:]
frame = dst_mac + src_mac + struct.pack("!H", 0x0800) + ip + udp + udp_payload
sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
sock.bind((iface, 0))
end = time.monotonic() + duration
count = 0
while time.monotonic() < end:
    sock.send(frame)
    count += 1
sock.close()
with open(count_path, "w", encoding="ascii") as f:
    f.write(str(count))
PY

wait "${APP_PID}" || true
APP_PID=""

sent="$(cat "${COUNT_FILE}")"
pps=$((sent / DURATION))
tail -n 1 "${LOG}"
echo "benchmark smoke sent=${sent} duration=${DURATION}s pps=${pps}"
