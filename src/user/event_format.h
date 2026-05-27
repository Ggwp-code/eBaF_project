#ifndef EBAF_EVENT_FORMAT_H
#define EBAF_EVENT_FORMAT_H

#include <stddef.h>

#include "crypto_common.h"

int ebaf_format_event_json(const struct ebaf_crypto_event *event, char *out, size_t out_len);

#endif
