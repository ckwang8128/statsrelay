#include "./server.h"

#include "./log.h"

#include <ev.h>
#include <string.h>

static void init_server(struct server *server) {
	server->enabled = false;
	server->server = NULL;
	server->ts = NULL;
	server->us = NULL;
}

static bool connect_server(struct server *server,
			   struct proto_config *config,
			   protocol_parser_t parser,
			   validate_line_validator_t validator,
			   const char *name,
			   enum connect_server_collection_state state) {
	stats_debug_log("connect_server(%s, %s)", name, CONNECT_SERVER_COLLECTION_STATE_LISTEN_DOWNSTREAM == state ? "CONNECT_SERVER_COLLECTION_STATE_LISTEN_DOWNSTREAM" : "CONNECT_SERVER_COLLECTION_STATE_UPSTREAM");

	if (config->ring->size == 0) {
		stats_log("%s has no backends, skipping", name);
		return false;
	}

	struct ev_loop *loop = ev_default_loop(0);

	if (CONNECT_SERVER_COLLECTION_STATE_LISTEN_DOWNSTREAM == state) {
		server->ts = tcpserver_create(loop);
		if (server->ts == NULL) {
			stats_error_log("failed to create tcpserver");
			return false;
		}

		server->us = udpserver_create(loop);
		if (server->us == NULL) {
			stats_error_log("failed to create udpserver");
			return false;
		}

		if (tcpserver_bind(server->ts, config->bind, stats_connection, stats_recv) != 0) {
			stats_error_log("unable to bind tcp %s", config->bind);
			return false;
		}
		if (udpserver_bind(server->us, config->bind, stats_udp_recv) != 0) {
			stats_error_log("unable to bind udp %s", config->bind);
			return false;
		}
	}

	if (CONNECT_SERVER_COLLECTION_STATE_UPSTREAM == state) {
		server->server = stats_server_create(
			loop, config, parser, validator);

		server->enabled = true;

		if (server->server == NULL) {
			stats_error_log("main: Unable to create stats_server");
			return false;
		}

		if (server->ts == NULL || server->us == NULL) {
			stats_error_log("main: Unable to create stats_server; please call connect_server(..., CONNECT_SERVER_COLLECTION_STATE_LISTEN_DOWNSTREAM) first");
			return false;
		}

		tcpserver_listeners_set_data(server->ts, server->server);
		udpserver_listeners_set_data(server->us, server->server);
	}

	return true;
}

static void destroy_server(struct server *server) {
	if (!server->enabled) {
		return;
	}
	if (server->ts != NULL) {
		tcpserver_destroy(server->ts);
	}
	if (server->us != NULL) {
		udpserver_destroy(server->us);
	}
	if (server->server != NULL) {
		stats_server_destroy(server->server);
	}
}

void init_server_collection(struct server_collection *server_collection,
			    const char *filename) {
	server_collection->initialized = true;
	server_collection->config_file = strdup(filename);
	init_server(&server_collection->carbon_server);
	init_server(&server_collection->statsd_server);
}

bool connect_server_collection(struct server_collection *server_collection,
			       struct config *config,
			       enum connect_server_collection_state state) {
	bool enabled_any = false;

	enabled_any |= connect_server(&server_collection->carbon_server,
				      &config->carbon_config,
				      protocol_parser_carbon,
				      validate_carbon,
				      "carbon",
				      state);

	enabled_any |= connect_server(&server_collection->statsd_server,
				      &config->statsd_config,
				      protocol_parser_statsd,
				      validate_statsd,
				      "statsd",
				      state);

	if (!enabled_any) {
		stats_error_log("failed to enable any backends");
	}
	return enabled_any;
}

void destroy_server_collection(struct server_collection *server_collection) {
	if (server_collection->initialized) {
		free(server_collection->config_file);
		destroy_server(&server_collection->carbon_server);
		destroy_server(&server_collection->statsd_server);
		server_collection->initialized = false;
	}
}
