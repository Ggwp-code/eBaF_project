#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
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
	fprintf(stderr,
		"usage: %s --iface IFACE --mode encrypt|decrypt --key HEXKEY [--algo cbc-aes|chacha20] [--port PORT] [--stats-interval SEC] [--duration SEC] [--hook xdp|tc|both] [--tc-ingress|--tc-egress] [--transparent] [--events] [--jsonl]\n",
		prog);
}

int main(int argc, char **argv)
{
	struct ebaf_user_config cfg;
	struct ebaf_bpf_runtime rt;
	time_t start_time;
	time_t last_stats_time;
	time_t now;
	int err;

	setvbuf(stdout, NULL, _IOLBF, 0);

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
		if (err == -EEXIST)
			fprintf(stderr, "BPF start failed: XDP program already attached on %s\n",
				cfg.iface);
		else
			fprintf(stderr, "BPF start failed: %s\n", strerror(-err));
		return 1;
	}

	start_time = time(NULL);
	last_stats_time = 0;
	while (!exiting) {
		now = time(NULL);
		if (last_stats_time == 0 ||
		    now - last_stats_time >= (time_t)cfg.stats_interval_sec) {
			ebaf_bpf_print_stats(&rt);
			last_stats_time = now;
		}
		if (cfg.print_events)
			ebaf_bpf_poll_events(&rt, 100);
		if (cfg.duration_sec > 0 && time(NULL) - start_time >= (time_t)cfg.duration_sec)
			break;
		if (!cfg.print_events)
			sleep(1);
	}

	ebaf_bpf_stop(&cfg, &rt);
	return 0;
}
