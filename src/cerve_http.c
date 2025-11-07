/* SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * Copyright (C) 2025 Carter Williams
 *
 * This file is part of Cerve.
 *
 * Cerve is free software: you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * Cerve is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 */

#include <stddef.h>
#include <stdint.h>

#include <cerve_http.h>

#include "cerve_debug.h"
#include "cerve_tcp.h"

struct cerve_http_server_cfg {
	uint64_t req_read_timeout_ms;
	uint64_t keepalive_timeout_ms;
	size_t req_body_size_max;
	size_t req_headers_size_max;
	unsigned int connections_max;
	unsigned int socket_backlog;
};

struct cerve_http_server {
	struct cerve_tcp_conn listen_conn;

	struct cerve_http_server_cfg cfg;
};

static const struct cerve_http_server_cfg http_server_cfg_default = {
	.req_read_timeout_ms = 20000,
	.keepalive_timeout_ms = 5000,
	.req_body_size_max = 1024 * 1024,
	.req_headers_size_max = 1024 * 8,
	.connections_max = 1024,
	.socket_backlog = 4096,
};
