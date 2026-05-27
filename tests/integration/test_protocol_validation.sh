#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
	echo "SKIP: protocol validation test needs root"
	exit 77
fi

for cmd in ip python3 timeout; do
	if ! command -v "${cmd}" >/dev/null 2>&1; then
		echo "SKIP: ${cmd} missing"
		exit 77
	fi
done

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${ROOT_DIR}/build/ebaf-crypto"
KEY="000102030405060708090a0b0c0d0e0f"
UDP_PORT="7777"
NS="ebafproto$$"
HOST_IF="ebafvh$$"
NS_IF="ebafvp$$"
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
ip addr add 10.99.0.1/24 dev "${HOST_IF}"
ip link set "${HOST_IF}" up
ip netns exec "${NS}" ip addr add 10.99.0.2/24 dev "${NS_IF}"
ip netns exec "${NS}" ip link set lo up
ip netns exec "${NS}" ip link set "${NS_IF}" up
HOST_MAC="$(cat "/sys/class/net/${HOST_IF}/address")"
NS_MAC="$(ip netns exec "${NS}" cat "/sys/class/net/${NS_IF}/address")"

timeout --preserve-status 10s "${BIN}" --iface "${HOST_IF}" --mode encrypt --key "${KEY}" \
	--port "${UDP_PORT}" --stats-interval 1 >"${LOG}" 2>&1 &
APP_PID=$!
sleep 2
if ! kill -0 "${APP_PID}" >/dev/null 2>&1; then
	cat "${LOG}"
	echo "FAIL: ebaf-crypto exited before validation sends"
	exit 1
fi

python3 - "${NS}" "${NS_IF}" "${NS_MAC}" "${HOST_MAC}" "${UDP_PORT}" <<'PY'
import socket
import struct
import subprocess
import sys

ns, ns_if, src_mac_text, dst_mac_text, dst_port_text = sys.argv[1:]
src_mac = bytes.fromhex(src_mac_text.replace(":", ""))
dst_mac = bytes.fromhex(dst_mac_text.replace(":", ""))
dst_port = int(dst_port_text)
src_ip = socket.inet_aton("10.99.0.2")
dst_ip = socket.inet_aton("10.99.0.1")
iv = bytes(range(16))

def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF

def frame(payload):
    udp = struct.pack("!HHHH", 4242, dst_port, 8 + len(payload), 0)
    total_len = 20 + len(udp) + len(payload)
    ip0 = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_len, 0, 0, 64,
                      socket.IPPROTO_UDP, 0, src_ip, dst_ip)
    ip = ip0[:10] + struct.pack("!H", checksum(ip0)) + ip0[12:]
    return dst_mac + src_mac + struct.pack("!H", 0x0800) + ip + udp + payload

def ebaf_payload(magic, declared_len, body):
    return magic + bytes([1, 1]) + declared_len.to_bytes(2, "big") + iv + body

payloads = [
    ebaf_payload(b"BAD!", 16, bytes(range(16))),
    ebaf_payload(b"EBAF", 8, bytes(range(16))),
    ebaf_payload(b"EBAF", 15, bytes(range(15))),
]
sender = (
    "import socket,sys;"
    "frame=bytes.fromhex(sys.argv[2]);"
    "s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW);"
    "s.bind((sys.argv[1],0));"
    "s.send(frame);"
    "s.close()"
)
for payload in payloads:
    subprocess.run(["ip", "netns", "exec", ns, "python3", "-c", sender,
                    ns_if, frame(payload).hex()], check=True)
PY

sleep 2
kill -TERM "${APP_PID}" >/dev/null 2>&1 || true
wait "${APP_PID}" >/dev/null 2>&1 || true
APP_PID=""

for counter in bad_magic bad_length bad_alignment; do
	if ! grep -Eq "${counter}=[1-9][0-9]*" "${LOG}"; then
		cat "${LOG}"
		echo "FAIL: ${counter} did not increment"
		exit 1
	fi
done

echo "protocol validation passed"
