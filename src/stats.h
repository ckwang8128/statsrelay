#ifndef STATSRELAY_STATS_H
#define STATSRELAY_STATS_H

#include <ev.h>
#include <stdint.h>

#include "protocol.h"
#include "validate.h"
#include "yaml_config.h"

typedef struct stats_server_t stats_server_t;

typedef struct {
	uint64_t live_packets_read;
	uint64_t live_packets_read_size;
	uint64_t last_packets_read;
	uint64_t last_packets_read_size;
} stats_per_second_t;

#define PID_MAX (32)

extern int pid_num;
extern stats_per_second_t *stats_per_second;

stats_server_t *stats_server_create(
	struct ev_loop *loop,
	struct proto_config *config,
	protocol_parser_t parser,
	validate_line_validator_t validator);
	stats_server_t *server;

size_t stats_num_backends(stats_server_t *server);

void stats_server_reload(stats_server_t *server);

void stats_server_destroy(stats_server_t *server);

// ctx is a (void *) cast of the stats_server_t instance.
void *stats_connection(int sd, void *ctx);

int stats_recv(int sd, void *data, void *ctx);

int stats_udp_recv(int sd, void *data);

#endif  // STATSRELAY_STATS_H
