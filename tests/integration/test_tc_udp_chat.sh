#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
	echo "SKIP: tc udp chat test needs root"
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
NS="ebaftc$$"
HOST_IF="ebaftch$$"
NS_IF="ebaftcp$$"
SERVER_LOG="$(mktemp)"
ENC_LOG="$(mktemp)"
DEC_LOG="$(mktemp)"
CLIENT_LOG="$(mktemp)"
SERVER_PID=""
ENC_PID=""
DEC_PID=""
KEEP_LOGS="${EBAF_KEEP_TEST_LOGS:-0}"

dump_logs()
{
	echo "=== client log ==="
	cat "${CLIENT_LOG}" || true
	echo "=== server log ==="
	cat "${SERVER_LOG}" || true
	echo "=== encrypt log ==="
	cat "${ENC_LOG}" || true
	echo "=== decrypt log ==="
	cat "${DEC_LOG}" || true
}

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
	if [[ "${KEEP_LOGS}" = "1" ]]; then
		echo "logs: client=${CLIENT_LOG} server=${SERVER_LOG} encrypt=${ENC_LOG} decrypt=${DEC_LOG}"
	else
		rm -f "${SERVER_LOG}" "${ENC_LOG}" "${DEC_LOG}" "${CLIENT_LOG}"
	fi
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

timeout --preserve-status 12s "${BIN}" --iface "${HOST_IF}" --mode encrypt \
	--hook tc --key "${KEY}" --port "${UDP_PORT}" --stats-interval 1 \
	--jsonl >"${ENC_LOG}" 2>&1 &
ENC_PID=$!

timeout --preserve-status 12s ip netns exec "${NS}" "${BIN}" --iface "${NS_IF}" \
	--mode decrypt --hook tc --key "${KEY}" --port "${UDP_PORT}" \
	--stats-interval 1 --jsonl >"${DEC_LOG}" 2>&1 &
DEC_PID=$!

sleep 2
for entry in "encrypt:${ENC_PID}:${ENC_LOG}" "decrypt:${DEC_PID}:${DEC_LOG}"; do
	IFS=: read -r name pid log <<<"${entry}"
	if ! kill -0 "${pid}" >/dev/null 2>&1; then
		cat "${log}"
		echo "FAIL: ${name} ebaf-crypto exited before traffic"
		exit 1
	fi
done

ip netns exec "${NS}" python3 "${ROOT_DIR}/scripts/udp_chat_server.py" \
	--host 10.77.0.2 --port "${UDP_PORT}" --count 1 --timeout 8 \
	>"${SERVER_LOG}" 2>&1 &
SERVER_PID=$!

sleep 1
python3 "${ROOT_DIR}/scripts/udp_chat_client.py" --host 10.77.0.2 \
	--port "${UDP_PORT}" --message "hello real app" --count 1 \
	>"${CLIENT_LOG}" 2>&1

wait "${SERVER_PID}" || {
	dump_logs
	echo "FAIL: udp chat server did not receive plaintext"
	exit 1
}
SERVER_PID=""

sleep 2
kill -TERM "${ENC_PID}" "${DEC_PID}" >/dev/null 2>&1 || true
wait "${ENC_PID}" >/dev/null 2>&1 || true
wait "${DEC_PID}" >/dev/null 2>&1 || true
ENC_PID=""
DEC_PID=""

if ! grep -q "hello real app" "${SERVER_LOG}"; then
	dump_logs
	echo "FAIL: decrypted plaintext missing at server"
	exit 1
fi

if ! grep -Eq 'crypto_ok=[1-9][0-9]*' "${ENC_LOG}"; then
	dump_logs
	echo "FAIL: host TC encrypt crypto_ok did not increment"
	exit 1
fi

if ! grep -Eq 'crypto_ok=[1-9][0-9]*' "${DEC_LOG}"; then
	dump_logs
	echo "FAIL: namespace XDP decrypt crypto_ok did not increment"
	exit 1
fi

grep '"type":"packet"' "${ENC_LOG}" || true
grep '"type":"packet"' "${DEC_LOG}" || true
echo "tc udp chat crypto passed"
