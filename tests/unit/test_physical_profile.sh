#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="${ROOT_DIR}/scripts/physical_profile.sh"

bash -n "${SCRIPT}"

if [[ "${EUID}" -eq 0 ]]; then
	echo "physical profile unit skipped non-root check under root"
	exit 0
fi

output="$("${SCRIPT}" lo 2>&1 || true)"
if [[ "${output}" != *"SKIP: physical profile needs root"* ]]; then
	echo "${output}"
	echo "FAIL: physical profile should skip without root"
	exit 1
fi

echo "physical profile tests passed"
