#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
	echo "SKIP: integration test needs root"
	exit 77
fi

for cmd in ip ping python3 timeout; do
	if ! command -v "${cmd}" >/dev/null 2>&1; then
		echo "SKIP: ${cmd} missing"
		exit 77
	fi
done

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${ROOT_DIR}/build/ebaf-crypto"
KEY="000102030405060708090a0b0c0d0e0f"
UDP_PORT="7777"
NS="ebafns$$"
HOST_IF="ebafh$$"
NS_IF="ebafp$$"
LOG="$(mktemp)"
APP_PID=""

cleanup()
{
	if [[ -n "${APP_PID}" ]] && kill -0 "${APP_PID}" >/dev/null 2>&1; then
		kill -TERM "${APP_PID}" >/dev/null 2>&1 || true
		wait "${APP_PID}" >/dev/null 2>&1 || true
	fi
	ip netns del "${NS}" >/dev/null 2>&1 || true
	ip link del "${HOST_IF}" >/dev/null 2>&1 || true
	rm -f "${LOG}"
}
trap cleanup EXIT

ip netns add "${NS}"
ip link add "${HOST_IF}" type veth peer name "${NS_IF}"
ip link set "${NS_IF}" netns "${NS}"
ip addr add 10.77.0.1/24 dev "${HOST_IF}"
ip link set "${HOST_IF}" up
ip netns exec "${NS}" ip addr add 10.77.0.2/24 dev "${NS_IF}"
ip netns exec "${NS}" ip link set lo up
ip netns exec "${NS}" ip link set "${NS_IF}" up
HOST_MAC="$(cat "/sys/class/net/${HOST_IF}/address")"
NS_MAC="$(ip netns exec "${NS}" cat "/sys/class/net/${NS_IF}/address")"

timeout --preserve-status 10s "${BIN}" --iface "${HOST_IF}" --mode encrypt --key "${KEY}" --port "${UDP_PORT}" >"${LOG}" 2>&1 &
APP_PID=$!
sleep 2

if ! kill -0 "${APP_PID}" >/dev/null 2>&1; then
	cat "${LOG}"
	echo "FAIL: ebaf-crypto exited before traffic"
	exit 1
fi

ip netns exec "${NS}" ping -c 2 -W 1 10.77.0.1 >/dev/null
ip netns exec "${NS}" python3 - "${NS_IF}" "${NS_MAC}" "${HOST_MAC}" "${UDP_PORT}" <<'PY'
import socket
import struct
import sys

iface = sys.argv[1]
src_mac = bytes.fromhex(sys.argv[2].replace(":", ""))
dst_mac = bytes.fromhex(sys.argv[3].replace(":", ""))
dst_port = int(sys.argv[4])
payload = b"A" * 40
udp_payload = (
    b"EBAF"
    + bytes([1, 1])
    + len(payload).to_bytes(2, "big")
    + bytes(range(16))
    + payload
)
src_ip = socket.inet_aton("10.77.0.2")
dst_ip = socket.inet_aton("10.77.0.1")
udp = struct.pack("!HHHH", 4242, dst_port, 8 + len(udp_payload), 0)
total_len = 20 + len(udp) + len(udp_payload)
ip_without_sum = struct.pack(
    "!BBHHHBBH4s4s",
    0x45,
    0,
    total_len,
    0,
    0,
    64,
    socket.IPPROTO_UDP,
    0,
    src_ip,
    dst_ip,
)

def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF

ip = ip_without_sum[:10] + struct.pack("!H", checksum(ip_without_sum)) + ip_without_sum[12:]
eth = dst_mac + src_mac + struct.pack("!H", 0x0800)
frame = eth + ip + udp + udp_payload

sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
sock.bind((iface, 0))
sock.send(frame)
sock.close()
PY
sleep 2

kill -TERM "${APP_PID}"
wait "${APP_PID}" || true
APP_PID=""

if ! grep -Eq 'seen=[1-9][0-9]*' "${LOG}"; then
	cat "${LOG}"
	echo "FAIL: no XDP packets observed"
	exit 1
fi

if ! grep -Eq 'crypto_ok=[1-9][0-9]*' "${LOG}"; then
	cat "${LOG}"
	echo "FAIL: no EBAF crypto packet processed"
	exit 1
fi

echo "integration crypto smoke passed"
