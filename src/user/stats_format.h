#ifndef EBAF_STATS_FORMAT_H
#define EBAF_STATS_FORMAT_H

#include <stddef.h>

#include "crypto_common.h"

int ebaf_format_stats_json(const struct ebaf_crypto_stats *stats, char *out, size_t out_len);

#endif
