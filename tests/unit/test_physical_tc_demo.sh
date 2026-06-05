#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="${ROOT_DIR}/scripts/physical_tc_demo.sh"

bash -n "${SCRIPT}"

if [[ "${EUID}" -eq 0 ]]; then
	echo "physical TC demo unit skipped non-root check under root"
	exit 0
fi

output="$(IFACE=lo PEER_IP=127.0.0.1 bash "${SCRIPT}" 2>&1 || true)"
if [[ "${output}" != *"SKIP: physical TC demo needs root"* ]]; then
	echo "${output}"
	echo "FAIL: physical TC demo should skip without root"
	exit 1
fi

echo "physical TC demo tests passed"
