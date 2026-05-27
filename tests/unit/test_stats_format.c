#include <stdio.h>
#include <string.h>

#include "stats_format.h"

static int failures;

static void expect_contains(const char *name, const char *haystack, const char *needle)
{
	if (strstr(haystack, needle) == NULL) {
		fprintf(stderr, "%s: missing %s in %s\n", name, needle, haystack);
		failures++;
	}
}

static void test_formats_stats_json(void)
{
	struct ebaf_crypto_stats stats = {
		.packets_seen = 10,
		.packets_passed = 2,
		.packets_crypto_ok = 7,
		.packets_crypto_fail = 1,
		.packets_malformed = 3,
	};
	char out[256];

	if (ebaf_format_stats_json(&stats, out, sizeof(out)) <= 0) {
		fprintf(stderr, "format stats failed\n");
		failures++;
		return;
	}

	if (strcmp(out, "{\"type\":\"stats\",\"seen\":10,\"passed\":2,"
		       "\"crypto_ok\":7,\"crypto_fail\":1,\"malformed\":3}") != 0) {
		fprintf(stderr, "stats json mismatch: %s\n", out);
		failures++;
	}

	expect_contains("type", out, "\"type\":\"stats\"");
	expect_contains("seen", out, "\"seen\":10");
	expect_contains("passed", out, "\"passed\":2");
	expect_contains("crypto_ok", out, "\"crypto_ok\":7");
	expect_contains("crypto_fail", out, "\"crypto_fail\":1");
	expect_contains("malformed", out, "\"malformed\":3");
}

static void test_rejects_bad_stats_args(void)
{
	struct ebaf_crypto_stats stats = {};
	char out[16];

	if (ebaf_format_stats_json(NULL, out, sizeof(out)) >= 0)
		failures++;
	if (ebaf_format_stats_json(&stats, NULL, sizeof(out)) >= 0)
		failures++;
	if (ebaf_format_stats_json(&stats, out, 0) >= 0)
		failures++;
}

int main(void)
{
	test_formats_stats_json();
	test_rejects_bad_stats_args();

	if (failures != 0) {
		fprintf(stderr, "%d stats format tests failed\n", failures);
		return 1;
	}

	puts("stats format tests passed");
	return 0;
}
