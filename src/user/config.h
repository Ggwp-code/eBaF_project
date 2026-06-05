#ifndef EBAF_USER_CONFIG_H
#define EBAF_USER_CONFIG_H

#include <stddef.h>

#include "crypto_common.h"

#define EBAF_IFACE_NAME_MAX 64
#define EBAF_HOOK_XDP 1
#define EBAF_HOOK_TC 2
#define EBAF_HOOK_BOTH 3
#define EBAF_TC_ATTACH_AUTO 0
#define EBAF_TC_ATTACH_INGRESS 1
#define EBAF_TC_ATTACH_EGRESS 2

struct ebaf_user_config {
	char iface[EBAF_IFACE_NAME_MAX];
	struct ebaf_crypto_config crypto;
	unsigned int hook;
	unsigned int tc_attach;
	unsigned int stats_interval_sec;
	unsigned int duration_sec;
	int print_events;
	int output_jsonl;
};

int ebaf_parse_args(int argc, char **argv, struct ebaf_user_config *cfg);
int ebaf_parse_hex_key(const char *hex, unsigned char *out, size_t out_len);

#endif
