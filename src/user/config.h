#ifndef EBAF_USER_CONFIG_H
#define EBAF_USER_CONFIG_H

#include <stddef.h>

#include "crypto_common.h"

#define EBAF_IFACE_NAME_MAX 64

struct ebaf_user_config {
	char iface[EBAF_IFACE_NAME_MAX];
	struct ebaf_crypto_config crypto;
	unsigned int stats_interval_sec;
	unsigned int duration_sec;
	int print_events;
	int output_jsonl;
};

int ebaf_parse_args(int argc, char **argv, struct ebaf_user_config *cfg);
int ebaf_parse_hex_key(const char *hex, unsigned char *out, size_t out_len);

#endif
