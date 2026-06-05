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
#ifndef BPF_F_INVALIDATE_HASH
#define BPF_F_INVALIDATE_HASH (1ULL << 1)
#endif
#define IP_TOT_LEN_OFF 2
#define IP_CHECK_OFF 10
#define UDP_LEN_OFF 4
#define UDP_CHECK_OFF 6

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

static __always_inline void stat_bad(struct ebaf_crypto_stats *stats, __u64 *counter)
{
	if (!stats || !counter)
		return;
	stat_inc(&stats->packets_malformed);
	stat_inc(counter);
}

static __always_inline int update_lengths(struct __sk_buff *skb, __u32 ip_off,
					  __u32 udp_off, __u32 delta, int add)
{
	__u16 zero = 0;
	__u16 old_ip_len = 0;
	__u16 old_udp_len = 0;
	__u16 new_ip_len;
	__u16 new_udp_len;

	if (bpf_skb_load_bytes(skb, ip_off + IP_TOT_LEN_OFF, &old_ip_len,
			       sizeof(old_ip_len)) < 0)
		return -1;
	if (bpf_skb_load_bytes(skb, udp_off + UDP_LEN_OFF, &old_udp_len,
			       sizeof(old_udp_len)) < 0)
		return -1;

	new_ip_len = bpf_ntohs(old_ip_len);
	new_udp_len = bpf_ntohs(old_udp_len);
	if (add) {
		new_ip_len += (__u16)delta;
		new_udp_len += (__u16)delta;
	} else {
		if (new_ip_len < delta || new_udp_len < delta)
			return -1;
		new_ip_len -= (__u16)delta;
		new_udp_len -= (__u16)delta;
	}
	new_ip_len = bpf_htons(new_ip_len);
	new_udp_len = bpf_htons(new_udp_len);

	if (bpf_l3_csum_replace(skb, ip_off + IP_CHECK_OFF, old_ip_len,
				new_ip_len, sizeof(new_ip_len)) < 0)
		return -1;
	if (bpf_skb_store_bytes(skb, ip_off + IP_TOT_LEN_OFF, &new_ip_len,
				sizeof(new_ip_len), 0) < 0)
		return -1;
	if (bpf_skb_store_bytes(skb, udp_off + UDP_LEN_OFF, &new_udp_len,
				sizeof(new_udp_len), 0) < 0)
		return -1;
	if (bpf_skb_store_bytes(skb, udp_off + UDP_CHECK_OFF, &zero,
				sizeof(zero), 0) < 0)
		return -1;
	return 0;
}

static __always_inline void fill_iv(__u8 iv[EBAF_CRYPTO_IV_BYTES])
{
	__u64 now = bpf_ktime_get_ns();

#pragma unroll
	for (int i = 0; i < EBAF_CRYPTO_IV_BYTES; i++)
		iv[i] = (__u8)(now >> ((i & 7) * 8));
}

static __always_inline void emit_event(struct __sk_buff *skb, struct iphdr *ip,
				       struct udphdr *udp, __u32 payload_len,
				       __u32 data_len, __u32 body_off,
				       const struct ebaf_crypto_config *config)
{
	struct ebaf_crypto_event *event;

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
		__u8 byte = 0;

		if ((__u32)i >= data_len)
			break;
		if (bpf_skb_load_bytes(skb, body_off + i, &byte, sizeof(byte)) < 0)
			break;
		event->sample[i] = byte;
		event->sample_len++;
	}
	bpf_ringbuf_submit(event, 0);
}

SEC("tc")
int tc_transparent(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ebaf_crypto_config *config;
	struct ebaf_crypto_stats *stats;
	struct ebaf_crypto_ctx_slot *slot;
	struct bpf_crypto_ctx *crypto_ctx;
	struct ethhdr *eth = data;
	struct iphdr *ip;
	struct udphdr *udp;
	struct ebaf_crypto_header *hdr;
	struct ebaf_crypto_header new_hdr = {};
	struct ebaf_crypto_header tail_hdr = {};
	struct bpf_dynptr pkt;
	struct bpf_dynptr body_ptr;
	struct bpf_dynptr iv_ptr;
	void *payload;
	__u32 zero = 0;
	__u32 payload_len;
	__u32 body_len;
	__u32 ip_off;
	__u32 udp_off;
	__u32 payload_off;
	__u32 body_off;
	__u32 iv_off;
	__u32 pad_len;
	__u32 delta;
	__u16 frag_off;
	__u8 iv[EBAF_CRYPTO_IV_BYTES];
	int rc;

	stats = bpf_map_lookup_elem(&crypto_stats, &zero);
	if (stats)
		stat_inc(&stats->packets_seen);

	if ((void *)(eth + 1) > data_end) {
		stat_bad(stats, &stats->packets_bad_eth);
		return TC_ACT_OK;
	}
	if (eth->h_proto != bpf_htons(ETH_P_IP)) {
		if (stats)
			stat_inc(&stats->packets_passed);
		return TC_ACT_OK;
	}
	ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end || ip->ihl != 5) {
		stat_bad(stats, &stats->packets_bad_ip);
		return TC_ACT_OK;
	}
	if ((void *)ip + ip->ihl * 4 > data_end) {
		stat_bad(stats, &stats->packets_bad_ip);
		return TC_ACT_OK;
	}
	frag_off = bpf_ntohs(ip->frag_off);
	if ((frag_off & (IP_MF | IP_OFFSET)) != 0) {
		stat_bad(stats, &stats->packets_bad_ip);
		return TC_ACT_OK;
	}
	if (ip->protocol != IPPROTO_UDP) {
		if (stats)
			stat_inc(&stats->packets_passed);
		return TC_ACT_OK;
	}
	udp = (void *)ip + ip->ihl * 4;
	if ((void *)(udp + 1) > data_end) {
		stat_bad(stats, &stats->packets_bad_udp);
		return TC_ACT_OK;
	}
	ip_off = (void *)ip - data;
	udp_off = (void *)udp - data;

	config = bpf_map_lookup_elem(&crypto_config, &zero);
	if (!config) {
		if (stats)
			stat_inc(&stats->packets_crypto_fail);
		return TC_ACT_OK;
	}
	if (config->algo != EBAF_ALGO_CBC_AES ||
	    (config->action != EBAF_ACTION_ENCRYPT && config->action != EBAF_ACTION_DECRYPT)) {
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
		stat_bad(stats, &stats->packets_bad_udp);
		return TC_ACT_OK;
	}
	payload_len -= sizeof(*udp);
	if (payload + payload_len > data_end) {
		stat_bad(stats, &stats->packets_bad_udp);
		return TC_ACT_OK;
	}
	payload_off = payload - data;

	if (config->action == EBAF_ACTION_ENCRYPT) {
		if (payload_len == 0 || payload_len > EBAF_MAX_TRANSPARENT_PAYLOAD) {
			stat_bad(stats, &stats->packets_bad_length);
			return TC_ACT_OK;
		}
		pad_len = EBAF_CRYPTO_BLOCK_BYTES - (payload_len & (EBAF_CRYPTO_BLOCK_BYTES - 1));
		if (pad_len == 0)
			pad_len = EBAF_CRYPTO_BLOCK_BYTES;
		body_len = payload_len + pad_len;
		delta = pad_len + sizeof(*hdr);
		if (bpf_skb_change_tail(skb, skb->len + delta, 0) < 0) {
			stat_bad(stats, &stats->packets_bad_length);
			return TC_ACT_OK;
		}

		data = (void *)(long)skb->data;
		data_end = (void *)(long)skb->data_end;
		eth = data;
		if ((void *)(eth + 1) > data_end) {
			stat_bad(stats, &stats->packets_bad_eth);
			return TC_ACT_OK;
		}
		ip = (void *)(eth + 1);
		if ((void *)(ip + 1) > data_end) {
			stat_bad(stats, &stats->packets_bad_ip);
			return TC_ACT_OK;
		}
		udp = (void *)ip + ip->ihl * 4;
		if ((void *)(udp + 1) > data_end) {
			stat_bad(stats, &stats->packets_bad_udp);
			return TC_ACT_OK;
		}
		payload = (void *)(udp + 1);
		if (payload + body_len + sizeof(*hdr) > data_end) {
			stat_bad(stats, &stats->packets_bad_length);
			return TC_ACT_OK;
		}

#pragma unroll
		for (int i = 0; i < EBAF_CRYPTO_BLOCK_BYTES; i++) {
			__u8 pad_byte;

			if ((__u32)i >= pad_len)
				break;
			pad_byte = (__u8)pad_len;
			if (bpf_skb_store_bytes(skb, payload_off + payload_len + i,
						&pad_byte, sizeof(pad_byte), 0) < 0) {
				stat_bad(stats, &stats->packets_bad_udp);
				return TC_ACT_OK;
			}
		}
		fill_iv(iv);
		new_hdr.magic = bpf_htonl(EBAF_CRYPTO_MAGIC);
		new_hdr.version = EBAF_CRYPTO_VERSION;
		new_hdr.action = EBAF_ACTION_ENCRYPT;
		new_hdr.payload_len = bpf_htons((__u16)body_len);
		__builtin_memcpy(new_hdr.iv, iv, sizeof(new_hdr.iv));
		if (bpf_skb_store_bytes(skb, payload_off + body_len, &new_hdr,
					sizeof(new_hdr), 0) < 0) {
			stat_bad(stats, &stats->packets_bad_magic);
			return TC_ACT_OK;
		}

		data = (void *)(long)skb->data;
		data_end = (void *)(long)skb->data_end;
		eth = data;
		if ((void *)(eth + 1) > data_end)
			return TC_ACT_OK;
		ip = (void *)(eth + 1);
		if ((void *)(ip + 1) > data_end)
			return TC_ACT_OK;
		udp = (void *)ip + ip->ihl * 4;
		if ((void *)(udp + 1) > data_end)
			return TC_ACT_OK;
		payload = (void *)(udp + 1);
		if (payload + body_len + sizeof(*hdr) > data_end)
			return TC_ACT_OK;

			if (update_lengths(skb, ip_off, udp_off, delta, 1) < 0) {
				stat_bad(stats, &stats->packets_bad_ip);
				return TC_ACT_OK;
			}

			data = (void *)(long)skb->data;
			data_end = (void *)(long)skb->data_end;
			eth = data;
			if ((void *)(eth + 1) > data_end)
				return TC_ACT_OK;
			ip = (void *)(eth + 1);
			if ((void *)(ip + 1) > data_end)
				return TC_ACT_OK;
			udp = (void *)ip + ip->ihl * 4;
			if ((void *)(udp + 1) > data_end)
				return TC_ACT_OK;
			payload = (void *)(udp + 1);
			if (payload + body_len + sizeof(*hdr) > data_end)
				return TC_ACT_OK;
			hdr = payload + body_len;
			body_off = payload_off;
			iv_off = payload_off + body_len + EBAF_CRYPTO_IV_OFFSET;
	} else {
		if (payload_len < sizeof(*hdr)) {
			stat_bad(stats, &stats->packets_bad_length);
			return TC_ACT_OK;
		}
		body_len = payload_len - sizeof(*hdr);
		if (payload + body_len + sizeof(tail_hdr) > data_end) {
			stat_bad(stats, &stats->packets_bad_length);
			return TC_ACT_OK;
		}
		if (bpf_skb_load_bytes(skb, payload_off + body_len, &tail_hdr,
				       sizeof(tail_hdr)) < 0) {
			if (stats)
				stat_inc(&stats->packets_crypto_fail);
			return TC_ACT_OK;
		}
		if (tail_hdr.magic != bpf_htonl(EBAF_CRYPTO_MAGIC) ||
		    tail_hdr.version != EBAF_CRYPTO_VERSION) {
			stat_bad(stats, &stats->packets_bad_magic);
			return TC_ACT_OK;
		}
		body_off = payload_off;
		iv_off = payload_off + body_len + EBAF_CRYPTO_IV_OFFSET;
	}

	if (body_len == 0 ||
	    (body_len & (EBAF_CRYPTO_BLOCK_BYTES - 1)) != 0) {
		stat_bad(stats, &stats->packets_bad_length);
		return TC_ACT_OK;
	}
	if (config->action == EBAF_ACTION_DECRYPT &&
	    bpf_ntohs(tail_hdr.payload_len) != body_len) {
		stat_bad(stats, &stats->packets_bad_length);
		return TC_ACT_OK;
	}

	slot = bpf_map_lookup_elem(&crypto_ctx_map, &zero);
	if (!slot) {
		stat_bad(stats, &stats->packets_no_crypto_ctx);
		return TC_ACT_OK;
	}
	crypto_ctx = slot->ctx;
	if (!crypto_ctx) {
		stat_bad(stats, &stats->packets_no_crypto_ctx);
		return TC_ACT_OK;
	}
	if (bpf_dynptr_from_skb(skb, 0, &pkt) != 0) {
		stat_bad(stats, &stats->packets_bad_alignment);
		return TC_ACT_OK;
	}
	if (bpf_dynptr_clone(&pkt, &body_ptr) != 0) {
		stat_bad(stats, &stats->packets_bad_alignment);
		return TC_ACT_OK;
	}
	if (bpf_dynptr_adjust(&body_ptr, body_off, body_off + body_len) != 0) {
		stat_bad(stats, &stats->packets_bad_length);
		return TC_ACT_OK;
	}
	if (bpf_dynptr_clone(&pkt, &iv_ptr) != 0) {
		stat_bad(stats, &stats->packets_bad_alignment);
		return TC_ACT_OK;
	}
	if (bpf_dynptr_adjust(&iv_ptr, iv_off, iv_off + EBAF_CRYPTO_IV_BYTES) != 0) {
		stat_bad(stats, &stats->packets_bad_magic);
		return TC_ACT_OK;
	}

	if (config->action == EBAF_ACTION_ENCRYPT)
		rc = bpf_crypto_encrypt(crypto_ctx, &body_ptr, &body_ptr, &iv_ptr);
	else
		rc = bpf_crypto_decrypt(crypto_ctx, &body_ptr, &body_ptr, &iv_ptr);
	if (rc != 0) {
		stat_bad(stats, &stats->packets_crypto_fail);
		return TC_ACT_OK;
	}
	if (config->action == EBAF_ACTION_ENCRYPT &&
	    bpf_skb_store_bytes(skb, iv_off, iv, sizeof(iv), 0) < 0) {
		stat_bad(stats, &stats->packets_bad_magic);
		return TC_ACT_OK;
	}

		if (stats)
			stat_inc(&stats->packets_crypto_ok);

		data = (void *)(long)skb->data;
		data_end = (void *)(long)skb->data_end;
		eth = data;
		if ((void *)(eth + 1) > data_end)
			return TC_ACT_OK;
		ip = (void *)(eth + 1);
		if ((void *)(ip + 1) > data_end)
			return TC_ACT_OK;
		udp = (void *)ip + ip->ihl * 4;
		if ((void *)(udp + 1) > data_end)
			return TC_ACT_OK;
		payload = (void *)(udp + 1);
		if (payload + body_len > data_end)
			return TC_ACT_OK;
		emit_event(skb, ip, udp, payload_len, body_len, body_off, config);

		if (config->action == EBAF_ACTION_DECRYPT) {
			__u8 pad_byte = 0;
			__u32 pad_off = body_off + body_len - 1;

			if (bpf_skb_load_bytes(skb, pad_off, &pad_byte,
					       sizeof(pad_byte)) < 0) {
				if (stats)
					stat_inc(&stats->packets_crypto_fail);
				return TC_ACT_OK;
			}
			pad_len = pad_byte;
		if (pad_len < 1 || pad_len > EBAF_CRYPTO_BLOCK_BYTES || pad_len > body_len) {
			stat_bad(stats, &stats->packets_bad_length);
			return TC_ACT_OK;
		}
		delta = pad_len + sizeof(*hdr);
		if (bpf_skb_change_tail(skb, skb->len - delta, 0) < 0) {
			if (stats)
				stat_inc(&stats->packets_crypto_fail);
			return TC_ACT_OK;
		}
		data = (void *)(long)skb->data;
		data_end = (void *)(long)skb->data_end;
		eth = data;
		if ((void *)(eth + 1) > data_end)
			return TC_ACT_OK;
		ip = (void *)(eth + 1);
		if ((void *)(ip + 1) > data_end)
			return TC_ACT_OK;
		udp = (void *)ip + ip->ihl * 4;
		if ((void *)(udp + 1) > data_end)
			return TC_ACT_OK;
			if (update_lengths(skb, ip_off, udp_off, delta, 0) < 0) {
				if (stats)
					stat_inc(&stats->packets_crypto_fail);
				return TC_ACT_OK;
			}
		}

	return TC_ACT_OK;
}
