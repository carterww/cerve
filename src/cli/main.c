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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "cerve_http_headers.h"
#include "cerve_http_parse.h"
#include "cerve_list.h"

#include <cpuid.h>
#include <immintrin.h>
#include <x86intrin.h>

static double tsc_freq_hz =
	3.6096e9; // Specific to my CPU (which also has constant_tsc)

static unsigned long long time_start(void)
{
	unsigned int a, b, c, d, aux;
	__cpuid(0, a, b, c, d);
	return __rdtsc();
}

static unsigned long long time_end(void)
{
	unsigned long long end;
	unsigned int a, b, c, d, aux;

	end = __rdtscp(&aux);
	__cpuid(0, a, b, c, d);
	return end;
}

static void time_print(unsigned long long start, unsigned long long end,
		       const char *ctx)
{
	unsigned long long cycles = end - start;

	double elapsed_us = ((double)cycles * 1000000.0) / tsc_freq_hz;

	printf("%s elapsed us: %0.4f\n", ctx, elapsed_us);
}

struct cerve_http_server_cfg {
	uint64_t req_read_timeout_ms;
	uint64_t keepalive_timeout_ms;
	size_t req_body_size_max;
	size_t req_headers_size_max;
	unsigned int connections_max;
	unsigned int socket_backlog;
};

static const struct cerve_http_server_cfg http_server_cfg_default = {
	.req_read_timeout_ms = 20000,
	.keepalive_timeout_ms = 5000,
	.req_body_size_max = 1024 * 1024,
	.req_headers_size_max = 1024 * 8,
	.connections_max = 1024,
	.socket_backlog = 4096,
};

static void print_request(struct cerve_http_request_internal *req)
{
	printf("Method: %u\n", req->req.method);
	printf("Version: %u\n", req->req.version);
	printf("Path: %.*s\n", (int)req->req.path_len, req->req.path);
	printf("Query: %.*s\n", (int)req->req.query_len, req->req.query);
	printf("Buf:\n%s", req->buf);

	static char *headers[] = {
		"user-agent",
		"host",
		"accept",
		"accept-language",
		"accept-encoding",
		"referer",
		"connection",
		"cookie",
		"upgrade-insecure-requests",
		"sec-fetch-dest",
		"sec-fetch-mode",
		"sec-fetch-site",
		"sec-fetch-user",
		"priority",
	};

	for (unsigned long i = 0; i < sizeof(headers) / sizeof(*headers); ++i) {
		struct cerve_http_header h;
		struct cerve_http_headers_map_entry *e;
		enum cerve_http_headers_map_value_type type;
		h.name = headers[i];
		h.name_len = (unsigned int)strlen(headers[i]);
		int err = cerve_http_headers_map_get(&req->headers_map.map, &h, &e, &type);
		if (err) {
			printf("Failed to get %s\n", headers[i]);
			exit(1);
		}
		if (type == CERVE_HTTP_HEADERS_MAP_VALUE_RAW) {
			printf("%s: %.*s\n", headers[i], (int)h.value_len, h.value);
		} else {
			slist_link *head = &e->next;
			do {
				printf("%s: %.*s\n", headers[i], (int)e->value_len, e->value);
				e = list_entry(e->next.next, struct cerve_http_headers_map_entry, next);
			} while (&e->next != head);
		}
	}
}

struct cerve_http_request_internal *
cerve_http_request_internal_create(const struct cerve_http_server_cfg *cfg);

int cerve_http_request_internal_destroy(struct cerve_http_request_internal *req);

int cerve_http_request_handle_new_data(struct cerve_http_request_internal *req);

int main(void)
{
	static const char example_request[] =
		"PATCH /blog/2024/08/03/converting-ascii-strings-to-lower-case-at-crazy-speeds-with-avx-512/ HTTP/1.0\r\n"
		"Host: lemire.me\r\n"
		"User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:144.0) Gecko/20100101 Firefox/144.0\r\n"
		"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
		"Accept-Language: en-US,en;q=0.5\r\n"
		"Accept-Encoding: gzip, deflate, br, zstd\r\n"
		"Referer: https://www.google.com/\r\n"
		"Connection: keep-alive\r\n"
		"Cookie: _I_=a6d506bf85e2e76c8f13125310430480ae62c2d2ecb2fc24c00c09ff4cc6feec-1762548063\r\n"
		"Cookie: _I_=a6d506bf85e2e76c8f13125310430480ae62c2d2ecb2fc24c00c09ff4cc6feec-1762548063\r\n"
		"Cookie: _I_=a6d506bf85e2e76c8f13125310430480ae62c2d2ecb2fc24c00c09ff4cc6feec-1762548063\r\n"
		"Cookie: _I_=a6d506bf85e2e76c8f13125310430480ae62c2d2ecb2fc24c00c09ff4cc6feec-1762548063\r\n"
		"Cookie: _I_=a6d506bf85e2e76c8f13125310430480ae62c2d2ecb2fc24c00c09ff4cc6feec-1762548063\r\n"
		"Upgrade-Insecure-Requests: 1\r\n"
		"Sec-Fetch-Dest: document\r\n"
		"Sec-Fetch-Mode: navigate\r\n"
		"Sec-Fetch-Site: cross-site\r\n"
		"Sec-Fetch-User: ?1\r\n"
		"Priority: u=0, i\r\n\r\n\0";
	struct cerve_http_request_internal *req = cerve_http_request_internal_create(&http_server_cfg_default);
	if (!req) {
		printf("Failed to create request\n");
		return 1;
	}

	unsigned long long start, end;
	strcpy(req->buf, example_request);
	req->req.raw_len = sizeof(example_request) - 1;
	start = time_start();
	int res = cerve_http_request_handle_new_data(req);
	end = time_end();
	time_print(start, end, "Handle new data");
	if (res == 200) {
		print_request(req);
	} else {
		printf("Failed to handle: %d\n", res);
	}

	cerve_http_request_internal_destroy(req);
	return 0;
}
