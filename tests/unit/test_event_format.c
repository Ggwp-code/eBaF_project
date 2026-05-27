#include <stdio.h>
#include <string.h>

#include "event_format.h"

static int failures;

static void expect_contains(const char *name, const char *haystack, const char *needle)
{
	if (strstr(haystack, needle) == NULL) {
		fprintf(stderr, "%s: missing %s in %s\n", name, needle, haystack);
		failures++;
	}
}

static void test_formats_packet_event_json(void)
{
	struct ebaf_crypto_event event = {
		.timestamp_ns = 123,
		.src_ip = 0x0200630a,
		.dst_ip = 0x0100630a,
		.src_port = 4242,
		.dst_port = 7777,
		.payload_len = 56,
		.data_len = 32,
		.action = EBAF_ACTION_ENCRYPT,
		.algo = EBAF_ALGO_CBC_AES,
		.sample_len = 4,
		.sample = {0xde, 0xad, 0xbe, 0xef},
	};
	char out[512];

	if (ebaf_format_event_json(&event, out, sizeof(out)) <= 0) {
		fprintf(stderr, "format event failed\n");
		failures++;
		return;
	}

	expect_contains("type", out, "\"type\":\"packet\"");
	expect_contains("timestamp", out, "\"ts_ns\":123");
	expect_contains("action", out, "\"action\":\"encrypt\"");
	expect_contains("algo", out, "\"algo\":\"cbc-aes\"");
	expect_contains("src", out, "\"src\":\"10.99.0.2\"");
	expect_contains("dst", out, "\"dst\":\"10.99.0.1\"");
	expect_contains("src_port", out, "\"src_port\":4242");
	expect_contains("dst_port", out, "\"dst_port\":7777");
	expect_contains("payload_len", out, "\"payload_len\":56");
	expect_contains("data_len", out, "\"data_len\":32");
	expect_contains("sample", out, "\"sample\":\"deadbeef\"");
}

static void test_rejects_bad_event_args(void)
{
	struct ebaf_crypto_event event = {};
	char out[16];

	if (ebaf_format_event_json(NULL, out, sizeof(out)) >= 0)
		failures++;
	if (ebaf_format_event_json(&event, NULL, sizeof(out)) >= 0)
		failures++;
	if (ebaf_format_event_json(&event, out, 0) >= 0)
		failures++;
}

int main(void)
{
	test_formats_packet_event_json();
	test_rejects_bad_event_args();

	if (failures != 0) {
		fprintf(stderr, "%d event format tests failed\n", failures);
		return 1;
	}

	puts("event format tests passed");
	return 0;
}
