#include "bpf_loader.h"

#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "crypto_common.h"
#include "crypto_ctx.bpf.skel.h"
#include "event_format.h"
#include "xdp_crypto.bpf.skel.h"

static struct crypto_ctx_bpf *ctx_skel;
static struct xdp_crypto_bpf *xdp_skel;

struct ebaf_event_printer {
	int jsonl;
};

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

static int handle_crypto_event(void *ctx, void *data, size_t data_sz)
{
	const struct ebaf_event_printer *printer = ctx;
	const struct ebaf_crypto_event *event = data;
	char src_ip[INET_ADDRSTRLEN] = "?";
	char dst_ip[INET_ADDRSTRLEN] = "?";
	struct in_addr src;
	struct in_addr dst;
	size_t sample_len;

	(void)ctx;

	if (data_sz < sizeof(*event))
		return 0;

	if (printer && printer->jsonl) {
		char line[512];

		if (ebaf_format_event_json(event, line, sizeof(line)) > 0)
			puts(line);
		return 0;
	}

	src.s_addr = event->src_ip;
	dst.s_addr = event->dst_ip;
	inet_ntop(AF_INET, &src, src_ip, sizeof(src_ip));
	inet_ntop(AF_INET, &dst, dst_ip, sizeof(dst_ip));

	printf("event ts=%llu action=%s algo=%s %s:%u -> %s:%u payload=%u data=%u sample=",
	       (unsigned long long)event->timestamp_ns,
	       action_name(event->action),
	       algo_name(event->algo),
	       src_ip,
	       event->src_port,
	       dst_ip,
	       event->dst_port,
	       event->payload_len,
	       event->data_len);

	sample_len = event->sample_len;
	if (sample_len > sizeof(event->sample))
		sample_len = sizeof(event->sample);
	for (size_t i = 0; i < sample_len; i++)
		printf("%02x", event->sample[i]);
	putchar('\n');
	return 0;
}

static int attach_xdp(int ifindex, int prog_fd, int *xdp_flags)
{
	const int driver_mode = XDP_FLAGS_DRV_MODE;
	const int generic_mode = XDP_FLAGS_SKB_MODE;
	const int no_replace = XDP_FLAGS_UPDATE_IF_NOEXIST;
	int err;

	err = bpf_xdp_attach(ifindex, prog_fd, driver_mode | no_replace, NULL);
	if (err == 0) {
		*xdp_flags = driver_mode;
		return 0;
	}

	err = bpf_xdp_attach(ifindex, prog_fd, generic_mode | no_replace, NULL);
	if (err == 0) {
		*xdp_flags = generic_mode;
		return 0;
	}

	return err;
}

int ebaf_bpf_start(const struct ebaf_user_config *cfg, struct ebaf_bpf_runtime *rt)
{
	LIBBPF_OPTS(bpf_test_run_opts, test_opts);
	static struct ebaf_event_printer event_printer;
	__u32 key = 0;
	int ctx_map_fd;
	int config_map_fd;
	int err;

	if (!cfg || !rt)
		return -EINVAL;

	memset(rt, 0, sizeof(*rt));
	rt->xdp_prog_fd = -1;
	rt->stats_map_fd = -1;
	rt->config_map_fd = -1;
	rt->event_ring = NULL;

	rt->ifindex = if_nametoindex(cfg->iface);
	if (rt->ifindex == 0)
		return -errno;

	ctx_skel = crypto_ctx_bpf__open();
	if (!ctx_skel)
		return -errno;

	err = crypto_ctx_bpf__load(ctx_skel);
	if (err)
		goto err_out;

	xdp_skel = xdp_crypto_bpf__open();
	if (!xdp_skel) {
		err = -errno;
		goto err_out;
	}

	config_map_fd = bpf_map__fd(ctx_skel->maps.crypto_config);
	ctx_map_fd = bpf_map__fd(ctx_skel->maps.crypto_ctx_map);
	err = bpf_map__reuse_fd(xdp_skel->maps.crypto_config, config_map_fd);
	if (err)
		goto err_out;
	err = bpf_map__reuse_fd(xdp_skel->maps.crypto_ctx_map, ctx_map_fd);
	if (err)
		goto err_out;

	err = xdp_crypto_bpf__load(xdp_skel);
	if (err)
		goto err_out;

	rt->config_map_fd = config_map_fd;
	err = bpf_map_update_elem(rt->config_map_fd, &key, &cfg->crypto, BPF_ANY);
	if (err) {
		err = -errno;
		goto err_out;
	}

	err = bpf_prog_test_run_opts(bpf_program__fd(ctx_skel->progs.create_crypto_ctx),
				     &test_opts);
	if (err) {
		err = -errno;
		goto err_out;
	}
	if (test_opts.retval != 0) {
		err = (int)test_opts.retval;
		goto err_out;
	}

	rt->xdp_prog_fd = bpf_program__fd(xdp_skel->progs.xdp_crypto);
	err = attach_xdp(rt->ifindex, rt->xdp_prog_fd, &rt->xdp_flags);
	if (err)
		goto err_out;

	rt->stats_map_fd = bpf_map__fd(xdp_skel->maps.crypto_stats);
	event_printer.jsonl = cfg->output_jsonl;
	rt->event_ring = ring_buffer__new(bpf_map__fd(xdp_skel->maps.crypto_events),
					  handle_crypto_event, &event_printer, NULL);
	if (!rt->event_ring) {
		err = -errno;
		goto err_out;
	}
	return 0;

err_out:
	ebaf_bpf_stop(cfg, rt);
	return err;
}

void ebaf_bpf_stop(const struct ebaf_user_config *cfg, struct ebaf_bpf_runtime *rt)
{
	(void)cfg;

	if (rt && rt->ifindex > 0 && rt->xdp_flags)
		bpf_xdp_detach(rt->ifindex, rt->xdp_flags, NULL);

	if (rt && rt->event_ring)
		ring_buffer__free(rt->event_ring);

	xdp_crypto_bpf__destroy(xdp_skel);
	crypto_ctx_bpf__destroy(ctx_skel);
	xdp_skel = NULL;
	ctx_skel = NULL;

	if (rt) {
		rt->ifindex = 0;
		rt->xdp_prog_fd = -1;
		rt->xdp_flags = 0;
		rt->stats_map_fd = -1;
		rt->config_map_fd = -1;
		rt->event_ring = NULL;
	}
}

int ebaf_bpf_print_stats(const struct ebaf_bpf_runtime *rt)
{
	struct ebaf_crypto_stats total = {};
	struct ebaf_crypto_stats *values;
	int cpu_count;
	__u32 key = 0;

	if (!rt || rt->stats_map_fd < 0)
		goto print;

	cpu_count = libbpf_num_possible_cpus();
	if (cpu_count <= 0)
		goto print;

	values = calloc((size_t)cpu_count, sizeof(*values));
	if (!values)
		goto print;

	if (bpf_map_lookup_elem(rt->stats_map_fd, &key, values) == 0) {
		for (int i = 0; i < cpu_count; i++) {
			total.packets_seen += values[i].packets_seen;
			total.packets_passed += values[i].packets_passed;
			total.packets_crypto_ok += values[i].packets_crypto_ok;
			total.packets_crypto_fail += values[i].packets_crypto_fail;
			total.packets_malformed += values[i].packets_malformed;
			total.packets_bad_eth += values[i].packets_bad_eth;
			total.packets_bad_ip += values[i].packets_bad_ip;
			total.packets_bad_udp += values[i].packets_bad_udp;
			total.packets_bad_magic += values[i].packets_bad_magic;
			total.packets_bad_length += values[i].packets_bad_length;
			total.packets_bad_alignment += values[i].packets_bad_alignment;
			total.packets_no_crypto_ctx += values[i].packets_no_crypto_ctx;
		}
	}

	free(values);

print:
	printf("seen=%llu passed=%llu crypto_ok=%llu crypto_fail=%llu malformed=%llu "
	       "bad_eth=%llu bad_ip=%llu bad_udp=%llu bad_magic=%llu bad_length=%llu "
	       "bad_alignment=%llu no_crypto_ctx=%llu\n",
	       (unsigned long long)total.packets_seen,
	       (unsigned long long)total.packets_passed,
	       (unsigned long long)total.packets_crypto_ok,
	       (unsigned long long)total.packets_crypto_fail,
	       (unsigned long long)total.packets_malformed,
	       (unsigned long long)total.packets_bad_eth,
	       (unsigned long long)total.packets_bad_ip,
	       (unsigned long long)total.packets_bad_udp,
	       (unsigned long long)total.packets_bad_magic,
	       (unsigned long long)total.packets_bad_length,
	       (unsigned long long)total.packets_bad_alignment,
	       (unsigned long long)total.packets_no_crypto_ctx);
	return 0;
}

int ebaf_bpf_poll_events(const struct ebaf_bpf_runtime *rt, int timeout_ms)
{
	if (!rt || !rt->event_ring)
		return -EINVAL;

	return ring_buffer__poll(rt->event_ring, timeout_ms);
}
