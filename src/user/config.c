#include "config.h"

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

int ebaf_parse_args(int argc, char **argv, struct ebaf_user_config *cfg)
{
	const char *iface = NULL;
	const char *mode = NULL;
	const char *key = NULL;

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

	if (ebaf_parse_hex_key(key, cfg->crypto.key, EBAF_CRYPTO_KEY_BYTES) != 0)
		return -1;

	cfg->crypto.key_len = EBAF_CRYPTO_KEY_BYTES;
	return 0;
}
