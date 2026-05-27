#include <stdio.h>
#include <string.h>

#include "config.h"
#include "crypto_common.h"

static int failures;

static void expect_int(const char *name, int got, int want)
{
	if (got != want) {
		fprintf(stderr, "%s: got %d want %d\n", name, got, want);
		failures++;
	}
}

static void expect_str(const char *name, const char *got, const char *want)
{
	if (strcmp(got, want) != 0) {
		fprintf(stderr, "%s: got %s want %s\n", name, got, want);
		failures++;
	}
}

static void test_parse_decrypt_args(void)
{
	char *argv[] = {
		"ebaf-crypto",
		"--iface", "veth0",
		"--mode", "decrypt",
		"--key", "000102030405060708090a0b0c0d0e0f",
	};
	struct ebaf_user_config cfg;
	int rc = ebaf_parse_args(7, argv, &cfg);

	expect_int("parse decrypt rc", rc, 0);
	expect_str("iface", cfg.iface, "veth0");
	expect_int("action", cfg.crypto.action, EBAF_ACTION_DECRYPT);
	expect_int("key len", cfg.crypto.key_len, EBAF_CRYPTO_KEY_BYTES);
	expect_int("first key byte", cfg.crypto.key[0], 0x00);
	expect_int("last key byte", cfg.crypto.key[15], 0x0f);
}

static void test_parse_encrypt_args(void)
{
	char *argv[] = {
		"ebaf-crypto",
		"--iface", "veth1",
		"--mode", "encrypt",
		"--key", "101112131415161718191a1b1c1d1e1f",
	};
	struct ebaf_user_config cfg;
	int rc = ebaf_parse_args(7, argv, &cfg);

	expect_int("parse encrypt rc", rc, 0);
	expect_str("iface", cfg.iface, "veth1");
	expect_int("action", cfg.crypto.action, EBAF_ACTION_ENCRYPT);
	expect_int("first key byte", cfg.crypto.key[0], 0x10);
	expect_int("last key byte", cfg.crypto.key[15], 0x1f);
}

static void test_reject_short_key(void)
{
	char *argv[] = {
		"ebaf-crypto",
		"--iface", "veth0",
		"--mode", "decrypt",
		"--key", "0011",
	};
	struct ebaf_user_config cfg;
	int rc = ebaf_parse_args(7, argv, &cfg);

	expect_int("short key rejected", rc, -1);
}

static void test_reject_bad_mode(void)
{
	char *argv[] = {
		"ebaf-crypto",
		"--iface", "veth0",
		"--mode", "sign",
		"--key", "000102030405060708090a0b0c0d0e0f",
	};
	struct ebaf_user_config cfg;
	int rc = ebaf_parse_args(7, argv, &cfg);

	expect_int("bad mode rejected", rc, -1);
}

int main(void)
{
	test_parse_decrypt_args();
	test_parse_encrypt_args();
	test_reject_short_key();
	test_reject_bad_mode();

	if (failures != 0) {
		fprintf(stderr, "%d config tests failed\n", failures);
		return 1;
	}

	puts("config tests passed");
	return 0;
}
