#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
	echo "SKIP: correctness test needs root"
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
NS="ebafcorrect$$"
HOST_IF="ebafch$$"
NS_IF="ebafcp$$"
LOG="$(mktemp)"
BODY_FILE="$(mktemp)"
APP_PID=""

cleanup()
{
	if [[ -n "${APP_PID}" ]] && kill -0 "${APP_PID}" >/dev/null 2>&1; then
		kill -TERM "${APP_PID}" >/dev/null 2>&1 || true
		wait "${APP_PID}" >/dev/null 2>&1 || true
	fi
	ip netns del "${NS}" >/dev/null 2>&1 || true
	ip link del "${HOST_IF}" >/dev/null 2>&1 || true
	rm -f "${LOG}" "${BODY_FILE}"
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

run_app()
{
	local mode="$1"

	: >"${LOG}"
	timeout --preserve-status 10s "${BIN}" --iface "${HOST_IF}" --mode "${mode}" --key "${KEY}" --port "${UDP_PORT}" --stats-interval 1 >"${LOG}" 2>&1 &
	APP_PID=$!
	sleep 2
	if ! kill -0 "${APP_PID}" >/dev/null 2>&1; then
		cat "${LOG}"
		echo "FAIL: ebaf-crypto exited in ${mode} mode"
		exit 1
	fi
}

stop_app()
{
	if [[ -n "${APP_PID}" ]] && kill -0 "${APP_PID}" >/dev/null 2>&1; then
		kill -TERM "${APP_PID}"
		wait "${APP_PID}" || true
	fi
	APP_PID=""
}

send_and_capture_body()
{
	local body_hex="$1"
	local out_file="$2"

	python3 - "${HOST_IF}" "${NS}" "${NS_IF}" "${NS_MAC}" "${HOST_MAC}" "${UDP_PORT}" "${body_hex}" "${out_file}" <<'PY'
import socket
import struct
import subprocess
import sys
import time

host_if, ns, ns_if, src_mac_text, dst_mac_text, dst_port_text, body_hex, out_file = sys.argv[1:]
src_mac = bytes.fromhex(src_mac_text.replace(":", ""))
dst_mac = bytes.fromhex(dst_mac_text.replace(":", ""))
dst_port = int(dst_port_text)
body = bytes.fromhex(body_hex)
iv = bytes(range(16))
udp_payload = b"EBAF" + bytes([1, 1]) + len(body).to_bytes(2, "big") + iv + body
src_ip = socket.inet_aton("10.99.0.2")
dst_ip = socket.inet_aton("10.99.0.1")
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
rx = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
rx.bind((host_if, 0))
rx.settimeout(3.0)
sender = (
    "import socket,sys;"
    "frame=bytes.fromhex(sys.argv[2]);"
    "s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW);"
    "s.bind((sys.argv[1],0));"
    "s.send(frame);"
    "s.close()"
)
subprocess.run(["ip", "netns", "exec", ns, "python3", "-c", sender, ns_if, frame.hex()], check=True)
end = time.monotonic() + 3.0
while time.monotonic() < end:
    packet = rx.recv(65535)
    if len(packet) < 14 + 20 + 8 + 24:
        continue
    if packet[12:14] != b"\x08\x00":
        continue
    if packet[23] != socket.IPPROTO_UDP:
        continue
    ihl = (packet[14] & 0x0F) * 4
    udp_off = 14 + ihl
    payload_off = udp_off + 8
    if len(packet) < payload_off + 24:
        continue
    if struct.unpack("!H", packet[udp_off + 2:udp_off + 4])[0] != dst_port:
        continue
    payload = packet[payload_off:]
    if payload[:4] != b"EBAF" or payload[4] != 1:
        continue
    body_len = struct.unpack("!H", payload[6:8])[0]
    body = payload[24:24 + body_len]
    with open(out_file, "w", encoding="ascii") as f:
        f.write(body.hex())
    sys.exit(0)
raise SystemExit("no transformed EBAF packet captured")
PY
}

PLAINTEXT_HEX="3031323334353637383941424344454630313233343536373839414243444546"

run_app encrypt
send_and_capture_body "${PLAINTEXT_HEX}" "${BODY_FILE}"
stop_app
CIPHERTEXT_HEX="$(cat "${BODY_FILE}")"

if [[ "${CIPHERTEXT_HEX}" == "${PLAINTEXT_HEX}" ]]; then
	cat "${LOG}"
	echo "FAIL: encryption did not change plaintext body"
	exit 1
fi

run_app decrypt
send_and_capture_body "${CIPHERTEXT_HEX}" "${BODY_FILE}"
stop_app
DECRYPTED_HEX="$(cat "${BODY_FILE}")"

if [[ "${DECRYPTED_HEX}" != "${PLAINTEXT_HEX}" ]]; then
	echo "FAIL: decrypt output mismatch"
	echo "want=${PLAINTEXT_HEX}"
	echo "got=${DECRYPTED_HEX}"
	exit 1
fi

echo "integration crypto correctness passed"
