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

#define _GNU_SOURCE

#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <sys/socket.h>

#include "cerve_cc.h"
#include "cerve_debug.h"
#include "cerve_tcp.h"

#define CONN_TEST_FLAG(conn, val) (((conn)->flags & val) != 0)
#define CONN_SET_FLAG(conn, val) (conn)->flags |= val
#define CONN_NOT_FLAG(conn, val) (conn)->flags &= ~val

static uint64_t cerve_tcp_timestamp_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	uint64_t ms = (uint64_t)ts.tv_sec * 1000ULL;
	ms += (uint64_t)ts.tv_nsec / 1000000ULL;
	return ms;
}

static int cerve_tcp_ip4_parse(const char *ip_addr, uint32_t *ip4_addr_netord)
{
	cassert(ip_addr != NULL);
	cassert(ip4_addr_netord != NULL);

	uint32_t ip4 = 0;
	for (int i = 3; i >= 0; --i) {
		char *endptr;
		if (*ip_addr < '0' || *ip_addr > '9') {
			return EINVAL;
		}
		long byte = strtol(ip_addr, &endptr, 10);
		if (byte < 0 || byte > UINT8_MAX) {
			return EINVAL;
		}
		ip4 |= ((uint32_t)byte << (i * 8));
		ip_addr = endptr + 1;
	}
	*ip4_addr_netord = htonl(ip4);
	return 0;
}

static int cerve_tcp_ip6_parse(const char *ip_addr, uint8_t ip6_addr_netord[16])
{
	cassert(ip_addr != NULL);
	cassert(ip6_addr_netord != NULL);

	for (int i = 0; i < 16; i += 2) {
		char *endptr;
		if ((*ip_addr < '0' || *ip_addr > '9') &&
		    (*ip_addr < 'a' || *ip_addr > 'f') &&
		    (*ip_addr < 'A' || *ip_addr > 'F')) {
			if (*ip_addr == ':' && i == 8) {
				memset(&ip6_addr_netord[i], 0, 8);
				return 0;
			}
			return EINVAL;
		}
		long dbyte = strtol(ip_addr, &endptr, 16);
		if (dbyte < 0 || dbyte > UINT16_MAX) {
			return EINVAL;
		}
		uint16_t dbyte_no = htons((uint16_t)dbyte);
		memcpy(&ip6_addr_netord[i], &dbyte_no, 2);
		ip_addr = endptr + 1;
	}
	return 0;
}

static int cerve_tcp_bind_linux(struct cerve_tcp_conn *conn,
				const struct sockaddr *addr,
				socklen_t addr_size)
{
	int sockfd;
	int err;
	const int true_opt = 1;

	sockfd = socket(addr->sa_family, SOCK_STREAM | SOCK_NONBLOCK,
			IPPROTO_TCP);
	if (sockfd == -1) {
		return errno;
	}
	err = setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &true_opt,
			 sizeof(true_opt));
	if (err == -1) {
		return errno;
	}
	err = bind(sockfd, addr, addr_size);
	if (err == -1) {
		return errno;
	}
	conn->fd = sockfd;
	conn->flags = 0;
	// Caller responsible for setting addr
	conn->last_activity = cerve_tcp_timestamp_ms();
	return 0;
}

int cerve_tcp_bind(struct cerve_tcp_conn *conn, const char *ip_addr,
		   uint16_t port_hostord)
{
	cassert(conn != NULL);
	cassert(ip_addr != NULL);

	uint16_t port_netord = htons(port_hostord);
	if (strchr(ip_addr, ':')) {
		uint8_t ip6_addr_netord[16];
		int ip6_err = cerve_tcp_ip6_parse(ip_addr, ip6_addr_netord);
		if (ip6_err) {
			return ip6_err;
		}
		return cerve_tcp_bind_ip6(conn, ip6_addr_netord, port_netord);
	} else if (strchr(ip_addr, '.')) {
		uint32_t ip4_addr_netord;
		int valid_ip4 = cerve_tcp_ip4_parse(ip_addr, &ip4_addr_netord);
		if (valid_ip4) {
			return valid_ip4;
		}
		return cerve_tcp_bind_ip4(conn, ip4_addr_netord, port_netord);
	} else {
		return EINVAL;
	}
}

int cerve_tcp_bind_ip4(struct cerve_tcp_conn *conn, uint32_t ip4_addr_netord,
		       uint16_t port_netord)
{
	int err;

	cassert(conn != NULL);

	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = port_netord,
		.sin_addr = {
			.s_addr = ip4_addr_netord,
		},
	};
	if ((err = cerve_tcp_bind_linux(conn, (struct sockaddr *)&addr,
					sizeof(addr))) != 0) {
		return err;
	}
	conn->addr.proto = CERVE_TCP_CONN_IP4;
	conn->addr.port_netord = port_netord;
	conn->addr.addr4_netord = ip4_addr_netord;
	return 0;
}

int cerve_tcp_bind_ip6(struct cerve_tcp_conn *conn, uint8_t ip6_addr_netord[16],
		       uint16_t port_netord)
{
	int err;

	cassert(conn != NULL);
	cassert(ip6_addr_netord != NULL);

	struct sockaddr_in6 addr = {
		.sin6_family = AF_INET6,
		.sin6_port = port_netord,
		.sin6_flowinfo = 0,
		.sin6_scope_id = 0,
	};
	memcpy(&addr.sin6_addr, ip6_addr_netord, 16);
	if ((err = cerve_tcp_bind_linux(conn, (struct sockaddr *)&addr,
					sizeof(addr))) != 0) {
		return err;
	}
	conn->addr.proto = CERVE_TCP_CONN_IP6;
	conn->addr.port_netord = port_netord;
	memcpy(conn->addr.addr6_netord, ip6_addr_netord, 16);
	return 0;
}

// Stupid GCC thinks the fd is leaking here.
#if defined(CERVE_CC_GCC)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wanalyzer-fd-leak"
#endif
int cerve_tcp_listen(struct cerve_tcp_conn *conn, size_t backlog_len)
{
	cassert(conn != NULL);
	cassert(conn->fd >= 0);
	cassert(!CONN_TEST_FLAG(conn, CERVE_TCP_CONN_FLAG_IS_LISTENER));

	if (backlog_len > INT_MAX) {
		return ERANGE;
	}
	int err = listen(conn->fd, (int)backlog_len);
	if (err == -1) {
		return errno;
	}
	CONN_SET_FLAG(conn, CERVE_TCP_CONN_FLAG_IS_LISTENER);
	return 0;
}
#if defined(CERVE_CC_GCC)
#pragma GCC diagnostic pop
#endif

int cerve_tcp_accept(struct cerve_tcp_conn *conn,
		     struct cerve_tcp_conn *conn_new)
{
	cassert(conn != NULL);
	cassert(conn->fd >= 0);
	cassert(CONN_TEST_FLAG(conn, CERVE_TCP_CONN_FLAG_IS_LISTENER));

	struct sockaddr_storage strg;
	CC_ATTR_MAY_ALIAS struct sockaddr_in addr4;
	CC_ATTR_MAY_ALIAS struct sockaddr_in6 addr6;
	struct sockaddr *addr;
	socklen_t addr_size;

	if (conn->addr.proto == CERVE_TCP_CONN_IP4) {
		addr = (struct sockaddr *)&addr4;
		addr_size = sizeof(addr4);
	} else {
		addr = (struct sockaddr *)&addr6;
		addr_size = sizeof(addr6);
	}

	int fd = accept4(conn->fd, addr, &addr_size, SOCK_NONBLOCK);
	if (fd == -1) {
		return errno;
	}
	conn->last_activity = cerve_tcp_timestamp_ms();

	conn_new->fd = fd;
	conn_new->flags = 0;
	conn_new->addr.proto = conn->addr.proto;
	conn_new->addr.port_netord = addr4.sin_port;
	if (conn->addr.proto == CERVE_TCP_CONN_IP4) {
		conn_new->addr.addr4_netord = addr4.sin_addr.s_addr;
	} else {
		memcpy(conn_new->addr.addr6_netord, &addr6.sin6_addr, 16);
	}
	conn_new->last_activity = conn->last_activity;
	return 0;
}

uint64_t cerve_tcp_ms_since_activity(const struct cerve_tcp_conn *conn)
{
	cassert(conn != NULL);
	cassert(conn->fd >= 0);

	return cerve_tcp_timestamp_ms() - conn->last_activity;
}

int64_t cerve_tcp_read(struct cerve_tcp_conn *conn, const void *buf,
		       size_t count);
int64_t cerve_tcp_write(struct cerve_tcp_conn *conn, void *buf, size_t count);

int cerve_tcp_shutdown_rd(struct cerve_tcp_conn *conn)
{
	cassert(conn != NULL);
	cassert(conn->fd >= 0);
	cassert(!CONN_TEST_FLAG(conn, CERVE_TCP_CONN_FLAG_RD_CLOSED));

	int err = shutdown(conn->fd, SHUT_RD);
	if (err == -1) {
		return errno;
	}
	CONN_SET_FLAG(conn, CERVE_TCP_CONN_FLAG_RD_CLOSED);
	return 0;
}

int cerve_tcp_shutdown_wr(struct cerve_tcp_conn *conn)
{
	cassert(conn != NULL);
	cassert(conn->fd >= 0);
	cassert(!CONN_TEST_FLAG(conn, CERVE_TCP_CONN_FLAG_WR_CLOSED));

	int err = shutdown(conn->fd, SHUT_WR);
	if (err == -1) {
		return errno;
	}
	CONN_SET_FLAG(conn, CERVE_TCP_CONN_FLAG_WR_CLOSED);
	return 0;
}

int cerve_tcp_close(struct cerve_tcp_conn *conn)
{
	cassert(conn != NULL);
	cassert(conn->fd >= 0);
	cassert(!CONN_TEST_FLAG(conn, CERVE_TCP_CONN_FLAG_RD_CLOSED));
	cassert(!CONN_TEST_FLAG(conn, CERVE_TCP_CONN_FLAG_WR_CLOSED));

	int err = close(conn->fd);
	if (err == -1) {
		return errno;
	}
	conn->fd = -1;
	CONN_SET_FLAG(conn, CERVE_TCP_CONN_FLAG_RD_CLOSED);
	CONN_SET_FLAG(conn, CERVE_TCP_CONN_FLAG_WR_CLOSED);
	return 0;
}
