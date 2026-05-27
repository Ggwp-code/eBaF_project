#include "bpf_loader.h"

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
#include "xdp_crypto.bpf.skel.h"

static struct crypto_ctx_bpf *ctx_skel;
static struct xdp_crypto_bpf *xdp_skel;

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
		}
	}

	free(values);

print:
	printf("seen=%llu passed=%llu crypto_ok=%llu crypto_fail=%llu malformed=%llu\n",
	       (unsigned long long)total.packets_seen,
	       (unsigned long long)total.packets_passed,
	       (unsigned long long)total.packets_crypto_ok,
	       (unsigned long long)total.packets_crypto_fail,
	       (unsigned long long)total.packets_malformed);
	return 0;
}
