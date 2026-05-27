#include "stats_format.h"

#include <stdio.h>

int ebaf_format_stats_json(const struct ebaf_crypto_stats *stats, char *out, size_t out_len)
{
	int written;

	if (!stats || !out || out_len == 0)
		return -1;

	written = snprintf(out, out_len,
			   "{\"type\":\"stats\",\"seen\":%llu,\"passed\":%llu,"
			   "\"crypto_ok\":%llu,\"crypto_fail\":%llu,\"malformed\":%llu}",
			   (unsigned long long)stats->packets_seen,
			   (unsigned long long)stats->packets_passed,
			   (unsigned long long)stats->packets_crypto_ok,
			   (unsigned long long)stats->packets_crypto_fail,
			   (unsigned long long)stats->packets_malformed);
	if (written < 0 || (size_t)written >= out_len)
		return -1;
	return written;
}
