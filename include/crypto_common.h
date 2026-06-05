#ifndef CRYPTO_COMMON_H
#define CRYPTO_COMMON_H

#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

#ifndef __kptr
#define __kptr
#endif

#ifndef __be32
#define __be32 __u32
#endif

#define EBAF_AES128_KEY_BYTES 16
#define EBAF_CHACHA20_KEY_BYTES 32
#define EBAF_CRYPTO_KEY_BYTES EBAF_AES128_KEY_BYTES
#define EBAF_CRYPTO_MAX_KEY_BYTES EBAF_CHACHA20_KEY_BYTES
#define EBAF_CRYPTO_IV_BYTES 16
#define EBAF_CRYPTO_BLOCK_BYTES 16
#define EBAF_CRYPTO_IV_OFFSET 8
#define EBAF_CRYPTO_MAGIC 0x45424146u
#define EBAF_CRYPTO_VERSION 1
#define EBAF_DEFAULT_UDP_PORT 7777
#define EBAF_ACTION_PASS 0
#define EBAF_ACTION_ENCRYPT 1
#define EBAF_ACTION_DECRYPT 2
#define EBAF_ALGO_CBC_AES 1
#define EBAF_ALGO_CHACHA20 2
#define EBAF_EVENT_SAMPLE_BYTES 32
#define EBAF_CRYPTO_F_TRANSPARENT 1u
#define EBAF_MAX_TRANSPARENT_PAYLOAD 1408

struct ebaf_crypto_header {
	__be32 magic;
	__u8 version;
	__u8 action;
	__u16 payload_len;
	__u8 iv[EBAF_CRYPTO_IV_BYTES];
};

struct ebaf_crypto_config {
	__u8 key[EBAF_CRYPTO_MAX_KEY_BYTES];
	__u32 key_len;
	__u32 action;
	__u32 algo;
	__u32 flags;
	__u16 udp_port;
};

struct ebaf_crypto_stats {
	__u64 packets_seen;
	__u64 packets_passed;
	__u64 packets_crypto_ok;
	__u64 packets_crypto_fail;
	__u64 packets_malformed;
	__u64 packets_bad_eth;
	__u64 packets_bad_ip;
	__u64 packets_bad_udp;
	__u64 packets_bad_magic;
	__u64 packets_bad_length;
	__u64 packets_bad_alignment;
	__u64 packets_no_crypto_ctx;
};

struct ebaf_crypto_event {
	__u64 timestamp_ns;
	__be32 src_ip;
	__be32 dst_ip;
	__u16 src_port;
	__u16 dst_port;
	__u16 payload_len;
	__u16 data_len;
	__u8 action;
	__u8 algo;
	__u8 result;
	__u8 sample_len;
	__u8 sample[EBAF_EVENT_SAMPLE_BYTES];
};

struct ebaf_crypto_ctx_slot {
	struct bpf_crypto_ctx __kptr *ctx;
};

#endif
