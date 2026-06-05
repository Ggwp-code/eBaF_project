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

for kfunc in \
	bpf_crypto_ctx_create \
	bpf_crypto_ctx_release \
	bpf_crypto_encrypt \
	bpf_crypto_decrypt \
	bpf_dynptr_from_xdp \
	bpf_dynptr_from_skb \
	bpf_dynptr_adjust \
	bpf_dynptr_clone
do
	if bpftool btf dump file /sys/kernel/btf/vmlinux format raw | grep -q "$kfunc"; then
		pass "$kfunc kfunc visible in BTF"
	else
		fail "$kfunc kfunc not visible in BTF"
	fi
done
