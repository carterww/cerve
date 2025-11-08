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

#ifndef CERVE_SRC_HTTP_PARSE_H
#define CERVE_SRC_HTTP_PARSE_H

#include <stddef.h>
#include <stdint.h>

#include <cerve_http.h>

#include "cerve_http_headers.h"

enum cerve_http_request_parse_state {
	CERVE_HTTP_REQUEST_PARSE_STATUS_LINE = 0,
	CERVE_HTTP_REQUEST_PARSE_HEADERS,
	CERVE_HTTP_REQUEST_PARSE_BODY,
	CERVE_HTTP_REQUEST_PARSE_DONE,
};

enum cerve_http_parse_path_err {
	CERVE_HTTP_PATH_ERR_OK = 0,
	CERVE_HTTP_PATH_ERR_NOT_FOUND,
	CERVE_HTTP_PATH_ERR_BAD_FORM,
	CERVE_HTTP_PATH_ERR_BAD_CHAR,
	CERVE_HTTP_PATH_ERR_BAD_PCT_ENCODE,
};

enum cerve_http_parse_status_line_err {
	CERVE_HTTP_SL_ERR_OK = 0,
	CERVE_HTTP_SL_ERR_INCOMPLETE,
	CERVE_HTTP_SL_ERR_BAD_METHOD,
	CERVE_HTTP_SL_ERR_BAD_PATH,
	CERVE_HTTP_SL_ERR_BAD_VERSION,
	CERVE_HTTP_SL_ERR_BAD_LINE,
	CERVE_HTTP_SL_ERR_HTTP2,
};

enum cerve_http_parse_headers_err {
	CERVE_HTTP_HDR_ERR_OK = 0,
	CERVE_HTTP_HDR_ERR_INCOMPLETE,
	CERVE_HTTP_HDR_ERR_MISSING_COLON,
	CERVE_HTTP_HDR_ERR_NAME_NOT_TOKEN,
	CERVE_HTTP_HDR_ERR_MAP_ADD_FAIL,
};

struct cerve_http_request_internal {
	// Same as req.raw but not const. This allows Cerve to mutate it while
	// preventing the user from doing it.
	char *buf;
	char *parse_pos;
	size_t content_length;
	enum cerve_http_request_parse_state state;
	struct cerve_http_request req;
	struct cerve_http_headers headers_map;

	// Context that a parsing function may set to provide more details
	// on error. Think of this like an errno
	void *err_ctx;
};

int cerve_http_is_tchar(char c);
int cerve_http_is_pchar(char c);
int cerve_http_is_ows(char c);
int cerve_http_is_pchar_or_nonascii(char c);
int cerve_http_is_token(const char *s, size_t len);

enum cerve_http_method cerve_http_parse_method(const char *method, size_t len);
enum cerve_http_version cerve_http_parse_version(const char *version,
						 size_t len);
enum cerve_http_parse_path_err cerve_http_parse_path(char *path, size_t len,
					       size_t *len_new, char **query,
					       size_t *query_len);

enum cerve_http_parse_status_line_err
cerve_http_parse_status_line(struct cerve_http_request_internal *state);

enum cerve_http_parse_headers_err
cerve_http_parse_headers(struct cerve_http_request_internal *state);

#endif /* CERVE_SRC_HTTP_PARSE_H */
