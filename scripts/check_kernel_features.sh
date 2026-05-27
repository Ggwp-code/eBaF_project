#!/usr/bin/env sh
set -eu

fail() {
	printf 'FAIL: %s\n' "$1" >&2
	exit 1
}

pass() {
	printf 'PASS: %s\n' "$1"
}

[ -r /sys/kernel/btf/vmlinux ] || fail 'missing /sys/kernel/btf/vmlinux; enable CONFIG_DEBUG_INFO_BTF'
pass 'BTF available'

command -v clang >/dev/null 2>&1 || fail 'clang not found'
pass 'clang available'

command -v bpftool >/dev/null 2>&1 || fail 'bpftool not found'
pass 'bpftool available'

command -v ip >/dev/null 2>&1 || fail 'iproute2 ip command not found'
pass 'ip command available'

if bpftool btf dump file /sys/kernel/btf/vmlinux format raw | grep -q 'bpf_crypto_encrypt'; then
	pass 'bpf_crypto_encrypt kfunc visible in BTF'
else
	fail 'bpf_crypto_encrypt kfunc not visible in BTF; use a kernel with BPF crypto kfunc support'
fi

if bpftool btf dump file /sys/kernel/btf/vmlinux format raw | grep -q 'bpf_dynptr_from_xdp'; then
	pass 'bpf_dynptr_from_xdp kfunc visible in BTF'
else
	fail 'bpf_dynptr_from_xdp kfunc not visible in BTF'
fi
