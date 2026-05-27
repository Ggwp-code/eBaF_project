#ifndef EBAF_BPF_LOADER_H
#define EBAF_BPF_LOADER_H

#include "config.h"

struct ebaf_bpf_runtime {
	int ifindex;
	int xdp_prog_fd;
	int xdp_flags;
	int stats_map_fd;
	int config_map_fd;
};

int ebaf_bpf_start(const struct ebaf_user_config *cfg, struct ebaf_bpf_runtime *rt);
void ebaf_bpf_stop(const struct ebaf_user_config *cfg, struct ebaf_bpf_runtime *rt);
int ebaf_bpf_print_stats(const struct ebaf_bpf_runtime *rt);

#endif
