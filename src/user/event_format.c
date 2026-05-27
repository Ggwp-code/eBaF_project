#include "event_format.h"

#include <arpa/inet.h>
#include <stdio.h>

static const char *action_name(__u8 action)
{
	if (action == EBAF_ACTION_ENCRYPT)
		return "encrypt";
	if (action == EBAF_ACTION_DECRYPT)
		return "decrypt";
	return "pass";
}

static const char *algo_name(__u8 algo)
{
	if (algo == EBAF_ALGO_CBC_AES)
		return "cbc-aes";
	if (algo == EBAF_ALGO_CHACHA20)
		return "chacha20";
	return "unknown";
}

static void format_sample_hex(const struct ebaf_crypto_event *event,
			      char sample[EBAF_EVENT_SAMPLE_BYTES * 2 + 1])
{
	static const char hex[] = "0123456789abcdef";
	size_t sample_len = event->sample_len;

	if (sample_len > EBAF_EVENT_SAMPLE_BYTES)
		sample_len = EBAF_EVENT_SAMPLE_BYTES;

	for (size_t i = 0; i < sample_len; i++) {
		sample[i * 2] = hex[event->sample[i] >> 4];
		sample[i * 2 + 1] = hex[event->sample[i] & 0x0f];
	}
	sample[sample_len * 2] = '\0';
}

int ebaf_format_event_json(const struct ebaf_crypto_event *event, char *out, size_t out_len)
{
	char src_ip[INET_ADDRSTRLEN] = "?";
	char dst_ip[INET_ADDRSTRLEN] = "?";
	char sample[EBAF_EVENT_SAMPLE_BYTES * 2 + 1] = {};
	struct in_addr src;
	struct in_addr dst;
	int written;

	if (!event || !out || out_len == 0)
		return -1;

	src.s_addr = event->src_ip;
	dst.s_addr = event->dst_ip;
	inet_ntop(AF_INET, &src, src_ip, sizeof(src_ip));
	inet_ntop(AF_INET, &dst, dst_ip, sizeof(dst_ip));
	format_sample_hex(event, sample);

	written = snprintf(out, out_len,
			   "{\"type\":\"packet\",\"ts_ns\":%llu,\"action\":\"%s\",\"algo\":\"%s\","
			   "\"src\":\"%s\",\"src_port\":%u,\"dst\":\"%s\",\"dst_port\":%u,"
			   "\"payload_len\":%u,\"data_len\":%u,\"sample\":\"%s\"}",
			   (unsigned long long)event->timestamp_ns,
			   action_name(event->action),
			   algo_name(event->algo),
			   src_ip,
			   event->src_port,
			   dst_ip,
			   event->dst_port,
			   event->payload_len,
			   event->data_len,
			   sample);
	if (written < 0 || (size_t)written >= out_len)
		return -1;
	return written;
}
