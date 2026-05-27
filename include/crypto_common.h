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

#define EBAF_CRYPTO_KEY_BYTES 16
#define EBAF_CRYPTO_IV_BYTES 16
#define EBAF_CRYPTO_MAGIC 0x45424146u
#define EBAF_CRYPTO_VERSION 1
#define EBAF_DEFAULT_UDP_PORT 7777
#define EBAF_ACTION_PASS 0
#define EBAF_ACTION_ENCRYPT 1
#define EBAF_ACTION_DECRYPT 2

struct ebaf_crypto_header {
	__be32 magic;
	__u8 version;
	__u8 action;
	__u16 payload_len;
	__u8 iv[EBAF_CRYPTO_IV_BYTES];
};

struct ebaf_crypto_config {
	__u8 key[EBAF_CRYPTO_KEY_BYTES];
	__u32 key_len;
	__u32 action;
	__u16 udp_port;
};

struct ebaf_crypto_stats {
	__u64 packets_seen;
	__u64 packets_passed;
	__u64 packets_crypto_ok;
	__u64 packets_crypto_fail;
	__u64 packets_malformed;
};

struct ebaf_crypto_ctx_slot {
	struct bpf_crypto_ctx __kptr *ctx;
};

#endif
