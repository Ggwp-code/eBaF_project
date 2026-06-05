#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

SEC("xdp")
int xdp_probe(struct xdp_md *ctx)
{
	(void)ctx;
	return XDP_PASS;
}
