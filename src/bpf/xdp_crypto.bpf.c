#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "crypto_common.h"

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct ebaf_crypto_config);
} crypto_config SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct ebaf_crypto_ctx_slot);
} crypto_ctx_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct ebaf_crypto_stats);
} crypto_stats SEC(".maps");

extern int bpf_dynptr_from_xdp(struct xdp_md *xdp, __u64 flags, struct bpf_dynptr *ptr__uninit) __ksym;
extern int bpf_crypto_encrypt(struct bpf_crypto_ctx *ctx,
			      const struct bpf_dynptr *src,
			      const struct bpf_dynptr *dst,
			      const struct bpf_dynptr *iv) __ksym;
extern int bpf_crypto_decrypt(struct bpf_crypto_ctx *ctx,
			      const struct bpf_dynptr *src,
			      const struct bpf_dynptr *dst,
			      const struct bpf_dynptr *iv) __ksym;

static __always_inline void stat_inc(__u64 *counter)
{
	if (counter)
		__sync_fetch_and_add(counter, 1);
}

SEC("xdp")
int xdp_crypto(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ebaf_crypto_header *hdr = data;
	struct ebaf_crypto_ctx_slot *slot;
	struct ebaf_crypto_config *config;
	struct ebaf_crypto_stats *stats;
	struct bpf_dynptr pkt;
	struct bpf_dynptr iv;
	__u32 zero = 0;
	int rc;

	stats = bpf_map_lookup_elem(&crypto_stats, &zero);
	if (stats)
		stat_inc(&stats->packets_seen);

	if ((void *)(hdr + 1) > data_end) {
		if (stats)
			stat_inc(&stats->packets_malformed);
		return XDP_PASS;
	}

	if (hdr->magic != bpf_htonl(EBAF_CRYPTO_MAGIC) || hdr->version != EBAF_CRYPTO_VERSION) {
		if (stats)
			stat_inc(&stats->packets_passed);
		return XDP_PASS;
	}

	config = bpf_map_lookup_elem(&crypto_config, &zero);
	if (!config) {
		if (stats)
			stat_inc(&stats->packets_crypto_fail);
		return XDP_PASS;
	}

	slot = bpf_map_lookup_elem(&crypto_ctx_map, &zero);
	if (!slot || !slot->ctx) {
		if (stats)
			stat_inc(&stats->packets_crypto_fail);
		return XDP_PASS;
	}

	rc = bpf_dynptr_from_xdp(ctx, 0, &pkt);
	if (rc != 0) {
		if (stats)
			stat_inc(&stats->packets_crypto_fail);
		return XDP_PASS;
	}

	rc = bpf_dynptr_from_mem(hdr->iv, EBAF_CRYPTO_IV_BYTES, 0, &iv);
	if (rc != 0) {
		if (stats)
			stat_inc(&stats->packets_crypto_fail);
		return XDP_PASS;
	}

	if (config->action == EBAF_ACTION_ENCRYPT)
		rc = bpf_crypto_encrypt(slot->ctx, &pkt, &pkt, &iv);
	else if (config->action == EBAF_ACTION_DECRYPT)
		rc = bpf_crypto_decrypt(slot->ctx, &pkt, &pkt, &iv);
	else
		rc = -1;

	if (rc == 0) {
		if (stats)
			stat_inc(&stats->packets_crypto_ok);
	} else {
		if (stats)
			stat_inc(&stats->packets_crypto_fail);
	}

	return XDP_PASS;
}
