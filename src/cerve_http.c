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
#include <stdlib.h>
#include <string.h>

#include <cerve_http.h>

#include "cerve_cc.h"
#include "cerve_debug.h"
#include "cerve_http_headers.h"
#include "cerve_http_parse.h"
#include "cerve_tcp.h"

#define DEFAULT_HEADERS_LEN (24)

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

static const struct cerve_http_request_internal http_request_internal_default = {
	.buf = NULL,
	.buf_cap = 0,
	.parse_pos = NULL,
	.content_length = 0,
	.state = CERVE_HTTP_REQUEST_PARSE_STATUS_LINE,
	.req = (struct cerve_http_request) {
		.method = CERVE_HTTP_METHOD_INVALID,
		.version = CERVE_HTTP_VERSION_AUTO,
		.headers = NULL,
		.path = NULL,
		.path_len = 0,
		.query = NULL,
		.query_len = 0,
		.body = NULL,
		.body_len = 0,
		.raw = NULL,
		.raw_len = 0,
	},
	.headers_map = {
		.type = CERVE_HTTP_HEADERS_MAP,
		.map = { {0} },
	},
	.err_ctx = (void *)0,
};

struct cerve_http_request_internal *
cerve_http_request_internal_create(const struct cerve_http_server_cfg *cfg)
{
	int err;

	cassert(cfg != NULL);

	size_t buf_max_size =
		cfg->req_headers_size_max + cfg->req_body_size_max;
	// TODO: Swap this for my virtual arean
	void *area = malloc(sizeof(struct cerve_http_request_internal) +
			    buf_max_size);
	if (area == NULL) {
		return NULL;
	}

	struct cerve_http_request_internal *req = area;
	char *buf = (char *)area + sizeof(*req);
	memcpy(req, &http_request_internal_default, sizeof(*req));
	req->buf = buf;
	req->buf_cap = buf_max_size;
	req->parse_pos = buf;
	req->req.headers = &req->headers_map;
	req->req.raw = buf;
	req->req.raw_len = 0;
	err = cerve_http_headers_map_init(&req->headers_map.map,
					  DEFAULT_HEADERS_LEN);
	if (err == 0) {
		return req;
	}
	free(area);
	return NULL;
}

int cerve_http_request_internal_destroy(struct cerve_http_request_internal *req)
{
	int err;

	cassert(req != NULL);
	cassert(req->buf != NULL);
	cassert(req->headers_map.type == CERVE_HTTP_HEADERS_MAP);

	err = cerve_http_headers_map_deinit(&req->headers_map.map);
	if (err) {
		return err;
	}
	// This is pretty cheap and ensures we don't accidentally use old data
	memcpy(req, &http_request_internal_default, sizeof(*req));
	// This also frees the buf since they were the same allocation
	free(req);
	return 0;
}

int cerve_http_request_handle_new_data(struct cerve_http_request_internal *req)
{
	enum cerve_http_parse_status_line_err sl_err;
	enum cerve_http_parse_headers_err hdr_err;

	// This is all the way up here so we can check the assertions again
switch_parse_state:
	cassert(req != NULL);
	cassert(req->buf != NULL);
	cassert(req->parse_pos != NULL);
	cassert(req->state != CERVE_HTTP_REQUEST_PARSE_DONE);
	cassert(req->req.headers != NULL);
	cassert(req->req.raw != NULL);
	cassert(req->req.raw_len > 0);
	cassert(req->headers_map.type == CERVE_HTTP_HEADERS_MAP);

	switch (req->state) {
	case CERVE_HTTP_REQUEST_PARSE_STATUS_LINE:
		cassert(req->buf == req->parse_pos);
		cassert(req->content_length == 0);
		sl_err = cerve_http_parse_status_line(req);
		switch (sl_err) {
		case CERVE_HTTP_SL_ERR_OK:
			req->state = CERVE_HTTP_REQUEST_PARSE_HEADERS;
			goto switch_parse_state;
		case CERVE_HTTP_SL_ERR_INCOMPLETE:
			return 0;
		case CERVE_HTTP_SL_ERR_BAD_METHOD:
		case CERVE_HTTP_SL_ERR_BAD_PATH:
		case CERVE_HTTP_SL_ERR_BAD_VERSION:
		case CERVE_HTTP_SL_ERR_BAD_LINE:
			return 400;
		case CERVE_HTTP_SL_ERR_HTTP2:
			return 505;
		default:
			cpanic();
		}
	case CERVE_HTTP_REQUEST_PARSE_HEADERS:
		cassert(req->buf < req->parse_pos);
		cassert(*req->parse_pos != '\r');
		cassert(*req->parse_pos != '\n');
		cassert(req->content_length == 0);
		cassert(req->req.method != CERVE_HTTP_METHOD_INVALID);
		cassert(req->req.version == CERVE_HTTP_VERSION_10 ||
			req->req.version == CERVE_HTTP_VERSION_11);
		cassert(req->req.path != NULL);
		cassert(req->req.path_len > 0);
		hdr_err = cerve_http_parse_headers(req);
		switch (hdr_err) {
		case CERVE_HTTP_HDR_ERR_OK:
			req->state = CERVE_HTTP_REQUEST_PARSE_BODY;
			goto switch_parse_state;
		case CERVE_HTTP_HDR_ERR_INCOMPLETE:
			return 0;
		case CERVE_HTTP_HDR_ERR_MISSING_COLON:
			CC_ATTR_FALLTHROUGH;
		case CERVE_HTTP_HDR_ERR_NAME_NOT_TOKEN:
			return 400;
		case CERVE_HTTP_HDR_ERR_MAP_ADD_FAIL:
			return 500;
		default:
			cpanic();
		}
	case CERVE_HTTP_REQUEST_PARSE_BODY:
		return 200;
	case CERVE_HTTP_REQUEST_PARSE_DONE:
		CC_ATTR_FALLTHROUGH;
	default:
		cpanic();
	}
}
