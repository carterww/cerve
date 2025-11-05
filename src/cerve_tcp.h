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

#ifndef CERVE_SRC_TCP_H
#define CERVE_SRC_TCP_H

#include <stddef.h>
#include <stdint.h>

#define CERVE_TCP_CONN_FLAG_RD_CLOSED (1U << 0)
#define CERVE_TCP_CONN_FLAG_WR_CLOSED (1U << 1)
#define CERVE_TCP_CONN_FLAG_IS_LISTENER (1U << 2)

enum cerve_tcp_conn_proto {
	CERVE_TCP_CONN_IP4 = 0,
	CERVE_TCP_CONN_IP6,
};

struct cerve_tcp_conn_addr {
	enum cerve_tcp_conn_proto proto;
	uint16_t port_netord;
	union {
		uint32_t addr4_netord;
		uint8_t addr6_netord[16];
	};
};

struct cerve_tcp_conn {
	int fd;
	uint32_t flags;
	struct cerve_tcp_conn_addr addr;
	uint64_t last_activity;
};

int cerve_tcp_bind(struct cerve_tcp_conn *conn, const char *ip_addr,
		   uint16_t port_hostord);
int cerve_tcp_bind_ip4(struct cerve_tcp_conn *conn, uint32_t ip4_addr_hostord,
		       uint16_t port_netord);
int cerve_tcp_bind_ip6(struct cerve_tcp_conn *conn, uint8_t ip6_addr_netord[16],
		       uint16_t port_netord);
int cerve_tcp_listen(struct cerve_tcp_conn *conn, size_t backlog_len);
int cerve_tcp_accept(struct cerve_tcp_conn *conn,
		     struct cerve_tcp_conn *conn_new);

uint64_t cerve_tcp_ms_since_activity(const struct cerve_tcp_conn *conn);
int64_t cerve_tcp_read(struct cerve_tcp_conn *conn, const void *buf,
		       size_t count);
int64_t cerve_tcp_write(struct cerve_tcp_conn *conn, void *buf, size_t count);
int cerve_tcp_shutdown_rd(struct cerve_tcp_conn *conn);
int cerve_tcp_shutdown_wr(struct cerve_tcp_conn *conn);
int cerve_tcp_close(struct cerve_tcp_conn *conn);

#endif /* CERVE_SRC_TCP_H */
