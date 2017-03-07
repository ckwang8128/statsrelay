#include "config.h"
#include "protocol.h"
#include "tcpserver.h"
#include "udpserver.h"
#include "server.h"
#include "stats.h"
#include "log.h"
#include "validate.h"
#include "yaml_config.h"

#include <assert.h>
#include <ctype.h>
#include <ev.h>
#include <getopt.h>
#include <inttypes.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

struct server_collection servers;
int per_second_stats = 0;
int fork_count = 0;

static struct option long_options[] = {
	{"config",		required_argument,	NULL, 'c'},
	{"check-config",	required_argument,	NULL, 't'},
	{"verbose",		no_argument,		NULL, 'v'},
	{"per-second-stats",	no_argument,		NULL, 'p'},
	{"log-level",		required_argument,	NULL, 'l'},
	{"fork-count",		required_argument,	NULL, 'f'},
	{"stats",		no_argument	,	NULL, 's'},
	{"help",		no_argument,		NULL, 'h'},
};

static void graceful_shutdown(struct ev_loop *loop, ev_signal *w, int revents) {
	stats_log("Received signal, shutting down.");
	destroy_server_collection(&servers);
	ev_break(loop, EVBREAK_ALL);
}

static void reload_config(struct ev_loop *loop, ev_signal *w, int revents) {
	stats_log("Received SIGHUP, reloading.");
	if (server != NULL) {
		stats_server_reload(server);
	}
}

static char* to_lower(const char *input) {
	char *output = strdup(input);
	for (int i  = 0; output[i] != '\0'; i++) {
		output[i] = tolower(output[i]);
	}
	return output;
}

static struct config *load_config(const char *filename) {
	FILE *file_handle = fopen(filename, "r");
	if (file_handle == NULL) {
		stats_error_log("failed to open file %s", servers.config_file);
		return NULL;
	}
	struct config *cfg = parse_config(file_handle);
	fclose(file_handle);
	return cfg;
}


static void print_help(const char *argv0) {
	printf("Usage: %s [options]\n"
		"  -h, --help                   Display this message\n"
		"  -v, --verbose                Write log messages to stderr in addition to syslog\n"
		"                               syslog\n"
		"  -p, --per-second-stats       Write a per second activity stats\n"
		"                               (default no activity stats)\n"
		"  -l, --log-level              Set the logging level to DEBUG, INFO, WARN, or ERROR\n"
		"                               (default: INFO)\n"
		"  -f, --fork-count             fork n (max 31) times\n"
		"                               (default: 0)\n"
		"  -c, --config=filename        Use the given hashring config file\n"
		"                               (default: %s)\n"
		"  -t, --check-config=filename  Check the config syntax\n"
		"                               (default: %s)\n"
		"  --version                    Print the version\n",
		argv0,
		default_config,
		default_config);
}

static void per_second_cb (EV_P_ ev_timer *w, int revents)
{
#define BUF_LEN (1024)
	char buf_packets[1 + BUF_LEN];
	char buf_bytes_read[1 + BUF_LEN];
	int  buf_packets_used    = 0;
	int  buf_bytes_read_used = 0;
	uint64_t this_packets_read      = 0;
	uint64_t this_packets_read_size = 0;
	for(int i = 0; i <= fork_count; i++) {
		uint64_t live_packets_read      = stats_per_second[i].live_packets_read;
		uint64_t live_packets_read_size = stats_per_second[i].live_packets_read_size;
		uint64_t last_packets_read      = stats_per_second[i].last_packets_read;
		uint64_t last_packets_read_size = stats_per_second[i].last_packets_read_size;

		uint64_t diff_packets_read      = (live_packets_read      - last_packets_read);
		uint64_t diff_packets_read_size = (live_packets_read_size - last_packets_read_size);

		this_packets_read      += diff_packets_read;
		this_packets_read_size += diff_packets_read_size;

		if (buf_packets_used    < BUF_LEN) { buf_packets_used    += snprintf(&buf_packets[buf_packets_used]      , BUF_LEN - buf_packets_used   , "+%lu", diff_packets_read     ); }
		if (buf_bytes_read_used < BUF_LEN) { buf_bytes_read_used += snprintf(&buf_bytes_read[buf_bytes_read_used], BUF_LEN - buf_bytes_read_used, "+%lu", diff_packets_read_size); }

		stats_per_second[i].last_packets_read      = live_packets_read;
		stats_per_second[i].last_packets_read_size = live_packets_read_size;
	}

	stats_log("read packets/s %lu (=%s) and bytes/s  %lu (=%s)", this_packets_read, &buf_packets[1], this_packets_read_size, &buf_bytes_read[1]);
}

int main(int argc, char **argv) {
	ev_signal sigint_watcher, sigterm_watcher, sighup_watcher;
	char *lower;
	int8_t c = 0;
	bool just_check_config = false;
	struct config *cfg = NULL;
	struct ev_loop *loop = ev_default_loop(0);

	servers.initialized = false;

	stats_set_log_level(STATSRELAY_LOG_INFO);  // set default value
	while (c != -1) {
		c = (int8_t)getopt_long(argc, argv, "t:c:l:vh", long_options, NULL);
		switch (c) {
		case -1:
			break;
		case 0:
		case 'h':
			print_help(argv[0]);
			return 1;
		case 'v':
			stats_log_verbose(true);
			break;
		case 'p':
			per_second_stats = 1;
			break;
		case 'V':
			puts(PACKAGE_STRING);
			return 0;
		case 'l':
			lower = to_lower(optarg);
			if (lower == NULL) {
				fprintf(stderr, "main: unable to allocate memory\n");
				goto err;
			}
			if (strcmp(lower, "debug") == 0) {
				stats_set_log_level(STATSRELAY_LOG_DEBUG);
				stats_log_verbose(true);
			} else if (strcmp(lower, "warn") == 0) {
				stats_set_log_level(STATSRELAY_LOG_WARN);
			} else if (strcmp(lower, "error") == 0) {
				stats_set_log_level(STATSRELAY_LOG_ERROR);
			}
			free(lower);
			break;
		case 'f':
			fork_count = atoi(optarg);
			if (fork_count < 0 || fork_count > (PID_MAX - 1)) {
				fprintf(stderr, "main: invalid fork-count; %d\n", fork_count);
				goto err;
			}
			break;
		case 'c':
			init_server_collection(&servers, optarg);
			break;
		case 't':
			init_server_collection(&servers, optarg);
			just_check_config = true;
			break;
		default:
			fprintf(stderr, "%s: Unknown argument %c\n", argv[0], c);
			goto err;
		}
	}
	stats_log(PACKAGE_STRING);

	if (!servers.initialized) {
		init_server_collection(&servers, default_config);
	}

	cfg = load_config(servers.config_file);
	if (cfg == NULL) {
		stats_error_log("failed to parse config");
		goto err;
	}
	if (just_check_config) {
		goto success;
	}

	bool worked_downstream = connect_server_collection(&servers, cfg, CONNECT_SERVER_COLLECTION_STATE_LISTEN_DOWNSTREAM);
	if (!worked_downstream) {
		goto err;
	}

	void *shared_memory = mmap(NULL, sizeof(stats_per_second_t) * PID_MAX, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (MAP_FAILED == stats_per_second) {
		stats_error_log("failed to allocated shared memory");
		goto err;
	}
	stats_per_second = (struct stats_per_second_t *)shared_memory;

	stats_debug_log("parent fork()ing %d kids", fork_count);
	for(pid_num = 1; pid_num <= fork_count; pid_num++) {
		pid_t pid = fork();
		if(pid == 0) {
			stats_debug_log("forked kid #%d with pid %d", pid_num, getpid());
			goto KIDS_DONT_FORK;
		} else {
			stats_debug_log("parent forked kid with pid %d", pid);
		}
	}
	pid_num = 0; // parent is pid_num 0
	KIDS_DONT_FORK:;

	ev_loop_fork (EV_DEFAULT);

	bool worked_upstream = connect_server_collection(&servers, cfg, CONNECT_SERVER_COLLECTION_STATE_UPSTREAM);
	if (!worked_upstream) {
		goto err;
	}

	ev_signal_init(&sigint_watcher, graceful_shutdown, SIGINT);
	ev_signal_start(loop, &sigint_watcher);

	ev_signal_init(&sigterm_watcher, graceful_shutdown, SIGTERM);
	ev_signal_start(loop, &sigterm_watcher);

	ev_signal_init(&sighup_watcher, reload_config, SIGHUP);
	ev_signal_start(loop, &sighup_watcher);

	ev_timer per_second_watcher;
	if (per_second_stats && 0 == pid_num) {
		ev_timer_init (&per_second_watcher, per_second_cb, 1.0, 1.0);
		ev_timer_start (loop, &per_second_watcher);
	}

	stats_log("main: Starting event loop");
	ev_run(loop, 0);

success:
	destroy_server_collection(&servers);
	destroy_config(cfg);
	stats_log_end();
	return 0;

err:
	destroy_server_collection(&servers);
	destroy_config(cfg);
	stats_log_end();
	return 1;
}
