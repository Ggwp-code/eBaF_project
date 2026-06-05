#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IFACE="${1:-}"
PROBE_OBJ="${ROOT_DIR}/build/xdp_probe.bpf.o"
OUT_DIR="${ROOT_DIR}/experiments"
PROBE_ACTIVE_MODE=""
PROBE_ACTIVE_ID=""

json_escape()
{
	python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))'
}

json_string()
{
	printf '%s' "$1" | json_escape
}

need_cmd()
{
	if ! command -v "$1" >/dev/null 2>&1; then
		echo "missing command: $1" >&2
		exit 2
	fi
}

detach_mode()
{
	local mode="$1"

	ip link set dev "${IFACE}" "${mode}" off
}

cleanup_probe()
{
	local cleanup_output
	local current_id

	if [[ -n "${PROBE_ACTIVE_MODE}" ]]; then
		current_id="$(current_xdp_id)"
		if [[ -n "${PROBE_ACTIVE_ID}" && "${current_id}" != "${PROBE_ACTIVE_ID}" ]]; then
			echo "refusing cleanup on ${IFACE}: current XDP id ${current_id:-none} differs from probe id ${PROBE_ACTIVE_ID}" >&2
			exit 2
		fi
		if ! cleanup_output="$(detach_mode "${PROBE_ACTIVE_MODE}" 2>&1)"; then
			echo "failed to detach temporary ${PROBE_ACTIVE_MODE} probe from ${IFACE}: ${cleanup_output}" >&2
			if current_xdp_attached; then
				exit 2
			fi
		fi
		PROBE_ACTIVE_MODE=""
		PROBE_ACTIVE_ID=""
	fi
}

probe_mode()
{
	local mode="$1"
	local output
	local detach_error
	local probe_id
	local current_id

	if output="$(ip link set dev "${IFACE}" "${mode}" obj "${PROBE_OBJ}" sec xdp 2>&1)"; then
		PROBE_ACTIVE_MODE="${mode}"
		trap cleanup_probe EXIT INT TERM
		probe_id="$(current_xdp_id)"
		if [[ -z "${probe_id}" ]]; then
			echo "failed to read temporary ${mode} probe id on ${IFACE}" >&2
			exit 2
		fi
		PROBE_ACTIVE_ID="${probe_id}"
		current_id="$(current_xdp_id)"
		if [[ "${current_id}" != "${probe_id}" ]]; then
			echo "refusing to detach ${IFACE}: current XDP id ${current_id:-none} differs from probe id ${probe_id}" >&2
			exit 2
		fi
		if output="$(detach_mode "${mode}" 2>&1)" && ! current_xdp_attached; then
			PROBE_ACTIVE_MODE=""
			PROBE_ACTIVE_ID=""
			trap - EXIT INT TERM
			printf '{"supported":true,"error":""}'
		else
			detach_error="${output}"
			cleanup_probe
			if current_xdp_attached; then
				echo "failed to detach temporary ${mode} probe from ${IFACE}: ${detach_error}" >&2
				exit 2
			fi
			PROBE_ACTIVE_MODE=""
			PROBE_ACTIVE_ID=""
			trap - EXIT INT TERM
			printf '{"supported":false,"error":%s}' "$(json_string "detach retry succeeded after: ${detach_error}")"
		fi
	else
		printf '{"supported":false,"error":%s}' "$(json_string "${output}")"
	fi
}

current_xdp_id()
{
	local state

	if ! state="$(bpftool net 2>&1)"; then
		echo "bpftool net failed: ${state}" >&2
		exit 2
	fi
	printf '%s\n' "${state}" | awk -v iface="${IFACE}" '
		/^xdp:/ { in_xdp = 1; next }
		/^[a-z]+:/ && $0 !~ /^xdp:/ { in_xdp = 0 }
		in_xdp {
			name = $1
			sub(/\(.*/, "", name)
			if (name == iface) {
				for (i = 1; i <= NF; i++) {
					if ($i == "id" && (i + 1) <= NF) {
						print $(i + 1)
						found = 1
						exit
					}
				}
			}
		}
		END { exit found ? 0 : 1 }
	' || true
}

current_xdp_attached()
{
	local id

	if ! id="$(current_xdp_id)"; then
		exit 2
	fi
	if [[ -n "${id}" ]]; then
		return 0
	fi
	return 1
}

if [[ -z "${IFACE}" ]]; then
	echo "usage: $0 IFACE" >&2
	exit 2
fi
if [[ "${EUID}" -ne 0 ]]; then
	echo "SKIP: physical profile needs root"
	exit 77
fi

for cmd in ip bpftool python3; do
	need_cmd "${cmd}"
done

if [[ ! -d "/sys/class/net/${IFACE}" ]]; then
	echo "interface not found: ${IFACE}" >&2
	exit 2
fi
if [[ ! -f "${PROBE_OBJ}" ]]; then
	echo "missing probe object: ${PROBE_OBJ}" >&2
	exit 2
fi
if current_xdp_attached; then
	echo "refusing: ${IFACE} already has XDP state; detach manually before probing" >&2
	exit 2
fi

mkdir -p "${OUT_DIR}"
OUT="${OUT_DIR}/physical-profile-${IFACE}.json"

driver_json="{}"
if command -v ethtool >/dev/null 2>&1; then
	driver_text="$(ethtool -i "${IFACE}" 2>/dev/null || true)"
	driver_json="$(printf '%s\n' "${driver_text}" | python3 -c '
import json, sys
data = {}
for line in sys.stdin:
    if ":" in line:
        k, v = line.rstrip().split(":", 1)
        data[k.strip().replace("-", "_")] = v.strip()
print(json.dumps(data))
')"
fi

offloads_json="{}"
if command -v ethtool >/dev/null 2>&1; then
	offloads_text="$(ethtool -k "${IFACE}" 2>/dev/null || true)"
	offloads_json="$(printf '%s\n' "${offloads_text}" | python3 -c '
import json, sys
data = {}
for line in sys.stdin:
    line = line.strip()
    if ":" in line and not line.endswith(":"):
        k, v = line.split(":", 1)
        data[k.strip().replace("-", "_")] = v.strip()
print(json.dumps(data))
')"
fi

link_json="$(ip -j link show dev "${IFACE}" | python3 -c '
import json, sys
items = json.load(sys.stdin)
item = items[0] if items else {}
print(json.dumps({
    "ifindex": item.get("ifindex"),
    "ifname": item.get("ifname"),
    "mtu": item.get("mtu"),
    "operstate": item.get("operstate"),
    "link_type": item.get("link_type"),
    "address": item.get("address"),
}))
')"

queue_count="$(find "/sys/class/net/${IFACE}/queues" -maxdepth 1 -type d -name '*-*' 2>/dev/null | wc -l)"
irq_matches="$(grep -c "${IFACE}" /proc/interrupts 2>/dev/null || true)"
bpftool_net="$(bpftool net)"
native_probe="$(probe_mode xdpdrv)"
generic_probe="$(probe_mode xdpgeneric)"
iface_json="$(json_string "${IFACE}")"
out_json="$(json_string "${OUT}")"
bpftool_net_json="$(json_string "${bpftool_net}")"
native_probe_json="$(json_string "${native_probe}")"
generic_probe_json="$(json_string "${generic_probe}")"

python3 - "${OUT}" <<PY
import json
import time

profile = {
    "created_at": time.time(),
    "interface": ${iface_json},
    "link": ${link_json},
    "driver": ${driver_json},
    "offloads": ${offloads_json},
    "queues": int(${queue_count@Q}),
    "irq_lines_matching_interface": int(${irq_matches@Q}),
    "xdp": {
        "current_bpftool_net": ${bpftool_net_json},
        "native": json.loads(${native_probe_json}),
        "generic": json.loads(${generic_probe_json}),
    },
    "notes": [
        "No traffic was generated.",
        "Native probe uses temporary xdpdrv attach and immediate detach.",
        "Generic probe uses temporary xdpgeneric attach and immediate detach."
    ],
}
with open(${out_json}, "w", encoding="utf-8") as f:
    json.dump(profile, f, indent=2)
print(${out_json})
print("native_xdp_supported=" + str(profile["xdp"]["native"]["supported"]))
print("generic_xdp_supported=" + str(profile["xdp"]["generic"]["supported"]))
PY
