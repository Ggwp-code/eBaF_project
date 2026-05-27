#include "config.h"

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

static int hex_value(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

int ebaf_parse_hex_key(const char *hex, unsigned char *out, size_t out_len)
{
	size_t hex_len;

	if (!hex || !out)
		return -1;

	hex_len = strlen(hex);
	if (hex_len != out_len * 2)
		return -1;

	for (size_t i = 0; i < out_len; i++) {
		int hi = hex_value(hex[i * 2]);
		int lo = hex_value(hex[i * 2 + 1]);

		if (hi < 0 || lo < 0)
			return -1;
		out[i] = (unsigned char)((hi << 4) | lo);
	}

	return 0;
}

static int parse_uint(const char *text, unsigned int min, unsigned int max,
		      unsigned int *out)
{
	char *end = NULL;
	unsigned long value;

	if (!text || !out || text[0] == '\0')
		return -1;

	errno = 0;
	value = strtoul(text, &end, 10);
	if (errno != 0 || end == text || *end != '\0' || value < min || value > max)
		return -1;

	*out = (unsigned int)value;
	return 0;
}

int ebaf_parse_args(int argc, char **argv, struct ebaf_user_config *cfg)
{
	const char *iface = NULL;
	const char *mode = NULL;
	const char *key = NULL;
	const char *algo = "cbc-aes";
	unsigned int port = EBAF_DEFAULT_UDP_PORT;
	unsigned int stats_interval_sec = 1;
	unsigned int duration_sec = 0;

	if (!cfg)
		return -1;

	memset(cfg, 0, sizeof(*cfg));

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--iface") == 0 && i + 1 < argc) {
			iface = argv[++i];
		} else if (strcmp(argv[i], "--mode") == 0 && i + 1 < argc) {
			mode = argv[++i];
		} else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) {
			key = argv[++i];
		} else if (strcmp(argv[i], "--algo") == 0 && i + 1 < argc) {
			algo = argv[++i];
		} else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
			if (parse_uint(argv[++i], 1, 65535, &port) != 0)
				return -1;
		} else if (strcmp(argv[i], "--stats-interval") == 0 && i + 1 < argc) {
			if (parse_uint(argv[++i], 1, UINT_MAX, &stats_interval_sec) != 0)
				return -1;
		} else if (strcmp(argv[i], "--duration") == 0 && i + 1 < argc) {
			if (parse_uint(argv[++i], 1, UINT_MAX, &duration_sec) != 0)
				return -1;
		} else if (strcmp(argv[i], "--events") == 0) {
			cfg->print_events = 1;
		} else if (strcmp(argv[i], "--jsonl") == 0) {
			cfg->output_jsonl = 1;
			cfg->print_events = 1;
		} else {
			return -1;
		}
	}

	if (!iface || !mode || !key)
		return -1;
	if (strlen(iface) >= sizeof(cfg->iface))
		return -1;

	strcpy(cfg->iface, iface);

	if (strcmp(mode, "encrypt") == 0)
		cfg->crypto.action = EBAF_ACTION_ENCRYPT;
	else if (strcmp(mode, "decrypt") == 0)
		cfg->crypto.action = EBAF_ACTION_DECRYPT;
	else
		return -1;

	if (strcmp(algo, "cbc-aes") == 0) {
		cfg->crypto.algo = EBAF_ALGO_CBC_AES;
		cfg->crypto.key_len = EBAF_AES128_KEY_BYTES;
	} else if (strcmp(algo, "chacha20") == 0) {
		cfg->crypto.algo = EBAF_ALGO_CHACHA20;
		cfg->crypto.key_len = EBAF_CHACHA20_KEY_BYTES;
	} else {
		return -1;
	}

	if (ebaf_parse_hex_key(key, cfg->crypto.key, cfg->crypto.key_len) != 0)
		return -1;

	cfg->crypto.udp_port = (__u16)port;
	cfg->stats_interval_sec = stats_interval_sec;
	cfg->duration_sec = duration_sec;
	return 0;
}
