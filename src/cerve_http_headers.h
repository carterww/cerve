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

#ifndef CERVE_SRC_HTTP_HEADERS_H
#define CERVE_SRC_HTTP_HEADERS_H

#include <cerve_http.h>

#include "cerve_map.h"
#include "cerve_list.h"

enum cerve_http_headers_type {
	CERVE_HTTP_HEADERS_MAP = 0,
	CERVE_HTTP_HEADERS_RAW,
};

enum cerve_http_headers_map_value_type {
	CERVE_HTTP_HEADERS_MAP_VALUE_RAW = 0,
	CERVE_HTTP_HEADERS_MAP_VALUE_LIST,
};

struct cerve_http_headers_map {
	struct cerve_map map;
};

struct cerve_http_headers_map_entry {
	// Always 0x80 (invalid ASCII). In the common case of 1 header name -> 1 header value,
	// we store the value directly (avoiding an allocation). If the first byte of the
	// value is 0x80, we assume its a map entry.
	uint8_t magic;
	unsigned int value_len;
	slist_link next;
	char *value;
	// We don't store value len because it can be cheaply computed and will
	// not be needed often
};

struct cerve_http_headers_raw {};

struct cerve_http_headers {
	enum cerve_http_headers_type type;
	union {
		struct cerve_http_headers_map map;
		struct cerve_http_headers_raw raw;
	};
};

int cerve_http_headers_map_init(struct cerve_http_headers_map *headers,
				size_t len);
int cerve_http_headers_map_deinit(struct cerve_http_headers_map *headers);
int cerve_http_headers_map_add(struct cerve_http_headers_map *headers,
			       const struct cerve_http_header *header);
int cerve_http_headers_map_get(struct cerve_http_headers_map *headers,
			       struct cerve_http_header *header,
			       struct cerve_http_headers_map_entry **entry,
			       enum cerve_http_headers_map_value_type *which);

#endif /* CERVE_SRC_HTTP_HEADERS_H */
