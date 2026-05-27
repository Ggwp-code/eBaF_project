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
	expect_int("default algo", cfg.crypto.algo, EBAF_ALGO_CBC_AES);
	expect_int("default port", cfg.crypto.udp_port, EBAF_DEFAULT_UDP_PORT);
	expect_int("default stats interval", cfg.stats_interval_sec, 1);
	expect_int("default duration", cfg.duration_sec, 0);
	expect_int("first key byte", cfg.crypto.key[0], 0x00);
	expect_int("last key byte", cfg.crypto.key[15], 0x0f);
}

static void test_parse_runtime_options(void)
{
	char *argv[] = {
		"ebaf-crypto",
		"--iface", "veth0",
		"--mode", "encrypt",
		"--key", "000102030405060708090a0b0c0d0e0f",
		"--port", "4242",
		"--stats-interval", "3",
		"--duration", "9",
	};
	struct ebaf_user_config cfg;
	int rc = ebaf_parse_args(13, argv, &cfg);

	expect_int("parse runtime rc", rc, 0);
	expect_int("runtime port", cfg.crypto.udp_port, 4242);
	expect_int("runtime interval", cfg.stats_interval_sec, 3);
	expect_int("runtime duration", cfg.duration_sec, 9);
}

static void test_parse_chacha20_args(void)
{
	char *argv[] = {
		"ebaf-crypto",
		"--iface", "veth0",
		"--mode", "encrypt",
		"--key", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		"--algo", "chacha20",
	};
	struct ebaf_user_config cfg;
	int rc = ebaf_parse_args(9, argv, &cfg);

	expect_int("parse chacha20 rc", rc, 0);
	expect_int("chacha20 algo", cfg.crypto.algo, EBAF_ALGO_CHACHA20);
	expect_int("chacha20 key len", cfg.crypto.key_len, EBAF_CHACHA20_KEY_BYTES);
	expect_int("chacha20 first key byte", cfg.crypto.key[0], 0x00);
	expect_int("chacha20 last key byte", cfg.crypto.key[31], 0x1f);
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

static void test_reject_bad_runtime_options(void)
{
	char *bad_port[] = {
		"ebaf-crypto",
		"--iface", "veth0",
		"--mode", "encrypt",
		"--key", "000102030405060708090a0b0c0d0e0f",
		"--port", "70000",
	};
	char *bad_interval[] = {
		"ebaf-crypto",
		"--iface", "veth0",
		"--mode", "encrypt",
		"--key", "000102030405060708090a0b0c0d0e0f",
		"--stats-interval", "0",
	};
	struct ebaf_user_config cfg;

	expect_int("bad port rejected", ebaf_parse_args(9, bad_port, &cfg), -1);
	expect_int("bad interval rejected", ebaf_parse_args(9, bad_interval, &cfg), -1);
}

static void test_reject_bad_algo_options(void)
{
	char *bad_algo[] = {
		"ebaf-crypto",
		"--iface", "veth0",
		"--mode", "encrypt",
		"--key", "000102030405060708090a0b0c0d0e0f",
		"--algo", "chacha20poly1305",
	};
	char *short_chacha_key[] = {
		"ebaf-crypto",
		"--iface", "veth0",
		"--mode", "encrypt",
		"--key", "000102030405060708090a0b0c0d0e0f",
		"--algo", "chacha20",
	};
	struct ebaf_user_config cfg;

	expect_int("bad algo rejected", ebaf_parse_args(9, bad_algo, &cfg), -1);
	expect_int("short chacha key rejected", ebaf_parse_args(9, short_chacha_key, &cfg), -1);
}

int main(void)
{
	test_parse_decrypt_args();
	test_parse_encrypt_args();
	test_parse_runtime_options();
	test_parse_chacha20_args();
	test_reject_short_key();
	test_reject_bad_mode();
	test_reject_bad_runtime_options();
	test_reject_bad_algo_options();

	if (failures != 0) {
		fprintf(stderr, "%d config tests failed\n", failures);
		return 1;
	}

	puts("config tests passed");
	return 0;
}
