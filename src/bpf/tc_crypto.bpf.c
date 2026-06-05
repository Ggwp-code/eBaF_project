#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "crypto_common.h"

char LICENSE[] SEC("license") = "GPL";

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

#ifndef TC_ACT_OK
#define TC_ACT_OK 0
#endif

#ifndef IP_MF
#define IP_MF 0x2000
#endif

#ifndef IP_OFFSET
#define IP_OFFSET 0x1fff
#endif

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

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} crypto_events SEC(".maps");

extern int bpf_dynptr_from_skb(struct __sk_buff *skb, __u64 flags,
			       struct bpf_dynptr *ptr__uninit) __ksym;
extern int bpf_dynptr_adjust(const struct bpf_dynptr *ptr, __u32 start,
			     __u32 end) __ksym;
extern int bpf_dynptr_clone(const struct bpf_dynptr *ptr,
			    struct bpf_dynptr *clone__uninit) __ksym;
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

static __always_inline void stat_reason(struct ebaf_crypto_stats *stats, __u64 *counter)
{
	if (!stats || !counter)
		return;
	stat_inc(&stats->packets_malformed);
	stat_inc(counter);
}

static __always_inline void emit_crypto_event(struct iphdr *ip, struct udphdr *udp,
					      struct ebaf_crypto_header *hdr,
					      __u32 payload_len, __u32 data_len,
					      void *data_end,
					      const struct ebaf_crypto_config *config)
{
	struct ebaf_crypto_event *event;
	void *sample_base = (void *)(hdr + 1);

	event = bpf_ringbuf_reserve(&crypto_events, sizeof(*event), 0);
	if (!event)
		return;

	event->timestamp_ns = bpf_ktime_get_ns();
	event->src_ip = ip->saddr;
	event->dst_ip = ip->daddr;
	event->src_port = bpf_ntohs(udp->source);
	event->dst_port = bpf_ntohs(udp->dest);
	event->payload_len = (__u16)payload_len;
	event->data_len = (__u16)data_len;
	event->action = (__u8)config->action;
	event->algo = (__u8)config->algo;
	event->result = 0;
	event->sample_len = 0;

#pragma unroll
	for (int i = 0; i < EBAF_EVENT_SAMPLE_BYTES; i++) {
		void *byte = sample_base + i;

		if ((__u32)i >= data_len || byte + 1 > data_end)
			break;
		event->sample[i] = *(__u8 *)byte;
		event->sample_len++;
	}

	bpf_ringbuf_submit(event, 0);
}

SEC("tc")
int tc_crypto(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ebaf_crypto_header *hdr;
	struct ebaf_crypto_ctx_slot *slot;
	struct bpf_crypto_ctx *crypto_ctx;
	struct ebaf_crypto_config *config;
	struct ebaf_crypto_stats *stats;
	struct ethhdr *eth = data;
	struct iphdr *ip;
	struct udphdr *udp;
	struct bpf_dynptr pkt;
	struct bpf_dynptr body_ptr;
	struct bpf_dynptr iv_ptr;
	void *payload;
	__u32 payload_len;
	__u32 payload_off;
	__u32 body_len;
	__u32 body_off;
	__u32 iv_off;
	__u32 zero = 0;
	__u16 frag_off;
	__u8 saved_iv[EBAF_CRYPTO_IV_BYTES];
	int rc;

	stats = bpf_map_lookup_elem(&crypto_stats, &zero);
	if (stats)
		stat_inc(&stats->packets_seen);

	if ((void *)(eth + 1) > data_end) {
		stat_reason(stats, &stats->packets_bad_eth);
		return TC_ACT_OK;
	}

	if (eth->h_proto != bpf_htons(ETH_P_IP)) {
		if (stats)
			stat_inc(&stats->packets_passed);
		return TC_ACT_OK;
	}

	ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end || ip->ihl < 5) {
		stat_reason(stats, &stats->packets_bad_ip);
		return TC_ACT_OK;
	}
	if ((void *)ip + ip->ihl * 4 > data_end) {
		stat_reason(stats, &stats->packets_bad_ip);
		return TC_ACT_OK;
	}

	frag_off = bpf_ntohs(ip->frag_off);
	if ((frag_off & (IP_MF | IP_OFFSET)) != 0) {
		stat_reason(stats, &stats->packets_bad_ip);
		return TC_ACT_OK;
	}

	if (ip->protocol != IPPROTO_UDP) {
		if (stats)
			stat_inc(&stats->packets_passed);
		return TC_ACT_OK;
	}

	udp = (void *)ip + ip->ihl * 4;
	if ((void *)(udp + 1) > data_end) {
		stat_reason(stats, &stats->packets_bad_udp);
		return TC_ACT_OK;
	}

	config = bpf_map_lookup_elem(&crypto_config, &zero);
	if (!config) {
		if (stats)
			stat_inc(&stats->packets_crypto_fail);
		return TC_ACT_OK;
	}

	if ((config->action != EBAF_ACTION_ENCRYPT &&
	     config->action != EBAF_ACTION_DECRYPT) ||
	    config->algo != EBAF_ALGO_CBC_AES) {
		if (stats)
			stat_inc(&stats->packets_passed);
		return TC_ACT_OK;
	}

	if (bpf_ntohs(udp->dest) != config->udp_port) {
		if (stats)
			stat_inc(&stats->packets_passed);
		return TC_ACT_OK;
	}

	payload = (void *)(udp + 1);
	payload_len = bpf_ntohs(udp->len);
	if (payload_len < sizeof(*udp)) {
		stat_reason(stats, &stats->packets_bad_udp);
		return TC_ACT_OK;
	}
	payload_len -= sizeof(*udp);
	if (payload + payload_len > data_end) {
		stat_reason(stats, &stats->packets_bad_udp);
		return TC_ACT_OK;
	}

	hdr = payload;
	if (payload_len < sizeof(*hdr)) {
		stat_reason(stats, &stats->packets_bad_length);
		return TC_ACT_OK;
	}
	if ((void *)(hdr + 1) > data_end) {
		stat_reason(stats, &stats->packets_bad_length);
		return TC_ACT_OK;
	}

	if (hdr->magic != bpf_htonl(EBAF_CRYPTO_MAGIC) ||
	    hdr->version != EBAF_CRYPTO_VERSION ||
	    hdr->action != EBAF_ACTION_ENCRYPT) {
		stat_reason(stats, &stats->packets_bad_magic);
		return TC_ACT_OK;
	}

	body_len = payload_len - sizeof(*hdr);
	if (bpf_ntohs(hdr->payload_len) != body_len) {
		stat_reason(stats, &stats->packets_bad_length);
		return TC_ACT_OK;
	}
	if (body_len == 0) {
		stat_reason(stats, &stats->packets_bad_length);
		return TC_ACT_OK;
	}
	if ((body_len & (EBAF_CRYPTO_BLOCK_BYTES - 1)) != 0) {
		stat_reason(stats, &stats->packets_bad_alignment);
		return TC_ACT_OK;
	}

	__builtin_memcpy(saved_iv, hdr->iv, sizeof(saved_iv));

	slot = bpf_map_lookup_elem(&crypto_ctx_map, &zero);
	if (!slot) {
		stat_reason(stats, &stats->packets_no_crypto_ctx);
		return TC_ACT_OK;
	}

	crypto_ctx = slot->ctx;
	if (!crypto_ctx) {
		stat_reason(stats, &stats->packets_no_crypto_ctx);
		return TC_ACT_OK;
	}

	rc = bpf_dynptr_from_skb(skb, 0, &pkt);
	if (rc != 0) {
		if (stats)
			stat_inc(&stats->packets_crypto_fail);
		return TC_ACT_OK;
	}

	payload_off = payload - data;
	body_off = payload_off + sizeof(*hdr);
	iv_off = payload_off + EBAF_CRYPTO_IV_OFFSET;

	rc = bpf_dynptr_clone(&pkt, &body_ptr);
	if (rc != 0) {
		if (stats)
			stat_inc(&stats->packets_crypto_fail);
		return TC_ACT_OK;
	}

	rc = bpf_dynptr_adjust(&body_ptr, body_off, body_off + body_len);
	if (rc != 0) {
		if (stats)
			stat_inc(&stats->packets_crypto_fail);
		return TC_ACT_OK;
	}

	rc = bpf_dynptr_clone(&pkt, &iv_ptr);
	if (rc != 0) {
		if (stats)
			stat_inc(&stats->packets_crypto_fail);
		return TC_ACT_OK;
	}

	rc = bpf_dynptr_adjust(&iv_ptr, iv_off, iv_off + EBAF_CRYPTO_IV_BYTES);
	if (rc != 0) {
		if (stats)
			stat_inc(&stats->packets_crypto_fail);
		return TC_ACT_OK;
	}

	if (config->action == EBAF_ACTION_ENCRYPT)
		rc = bpf_crypto_encrypt(crypto_ctx, &body_ptr, &body_ptr, &iv_ptr);
	else
		rc = bpf_crypto_decrypt(crypto_ctx, &body_ptr, &body_ptr, &iv_ptr);
	if (rc == 0) {
		udp->check = 0;
		__builtin_memcpy(hdr->iv, saved_iv, sizeof(saved_iv));
		if (stats)
			stat_inc(&stats->packets_crypto_ok);
		emit_crypto_event(ip, udp, hdr, payload_len, body_len, data_end, config);
	} else {
		if (stats)
			stat_inc(&stats->packets_crypto_fail);
	}

	return TC_ACT_OK;
}
