#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "bpf_loader.h"
#include "config.h"

static volatile sig_atomic_t exiting;

static void handle_signal(int sig)
{
	(void)sig;
	exiting = 1;
}

static void usage(const char *prog)
{
	fprintf(stderr, "usage: %s --iface IFACE --mode encrypt|decrypt --key HEXKEY\n",
		prog);
}

int main(int argc, char **argv)
{
	struct ebaf_user_config cfg;
	struct ebaf_bpf_runtime rt;
	int err;

	if (ebaf_parse_args(argc, argv, &cfg) != 0) {
		usage(argv[0]);
		return 1;
	}

	if (signal(SIGINT, handle_signal) == SIG_ERR ||
	    signal(SIGTERM, handle_signal) == SIG_ERR) {
		fprintf(stderr, "signal setup failed: %s\n", strerror(errno));
		return 1;
	}

	err = ebaf_bpf_start(&cfg, &rt);
	if (err != 0) {
		fprintf(stderr, "BPF start failed: %s\n", strerror(-err));
		return 1;
	}

	while (!exiting) {
		ebaf_bpf_print_stats(&rt);
		sleep(1);
	}

	ebaf_bpf_stop(&cfg, &rt);
	return 0;
}
