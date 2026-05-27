#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
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

extern struct bpf_crypto_ctx *bpf_crypto_ctx_create(const struct bpf_crypto_params *params,
						    __u32 params__sz,
						    int *err) __ksym;
extern void bpf_crypto_ctx_release(struct bpf_crypto_ctx *ctx) __ksym;

SEC("syscall")
int create_crypto_ctx(void *ctx)
{
	__u32 key = 0;
	struct ebaf_crypto_config *config;
	struct ebaf_crypto_ctx_slot *slot;
	struct bpf_crypto_ctx *new_ctx;
	struct bpf_crypto_ctx *old_ctx;
	struct bpf_crypto_params params = {};
	int err = 0;

	config = bpf_map_lookup_elem(&crypto_config, &key);
	if (!config)
		return -1;
	if (config->algo == EBAF_ALGO_CBC_AES && config->key_len != EBAF_AES128_KEY_BYTES)
		return -2;
	if (config->algo == EBAF_ALGO_CHACHA20 && config->key_len != EBAF_CHACHA20_KEY_BYTES)
		return -2;
	if (config->algo != EBAF_ALGO_CBC_AES && config->algo != EBAF_ALGO_CHACHA20)
		return -2;

	__builtin_memcpy(params.type, "skcipher", sizeof("skcipher"));
	if (config->algo == EBAF_ALGO_CHACHA20) {
		__builtin_memcpy(params.algo, "chacha20", sizeof("chacha20"));
		__builtin_memcpy(params.key, config->key, EBAF_CHACHA20_KEY_BYTES);
	} else {
		__builtin_memcpy(params.algo, "cbc(aes)", sizeof("cbc(aes)"));
		__builtin_memcpy(params.key, config->key, EBAF_AES128_KEY_BYTES);
	}
	params.key_len = config->key_len;

	new_ctx = bpf_crypto_ctx_create(&params, sizeof(params), &err);
	if (!new_ctx)
		return err ? err : -3;

	slot = bpf_map_lookup_elem(&crypto_ctx_map, &key);
	if (!slot) {
		bpf_crypto_ctx_release(new_ctx);
		return -4;
	}

	old_ctx = bpf_kptr_xchg(&slot->ctx, new_ctx);
	if (old_ctx)
		bpf_crypto_ctx_release(old_ctx);

	return 0;
}
