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

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <cerve_http.h>

#include "cerve_cc.h"
#include "cerve_debug.h"
#include "cerve_http_parse.h"

static const char *method_to_str[] = {
	[CERVE_HTTP_METHOD_GET] = "GET",
	[CERVE_HTTP_METHOD_POST] = "POST",
	[CERVE_HTTP_METHOD_PUT] = "PUT",
	[CERVE_HTTP_METHOD_PATCH] = "PATCH",
	[CERVE_HTTP_METHOD_DELETE] = "DELETE",
	[CERVE_HTTP_METHOD_HEAD] = "HEAD",
	[CERVE_HTTP_METHOD_CONNECT] = "CONNECT",
	[CERVE_HTTP_METHOD_OPTIONS] = "OPTIONS",
	[CERVE_HTTP_METHOD_TRACE] = "TRACE",
	[CERVE_HTTP_METHOD_INVALID] = "",
};

// HTTP defines tokens as a sequence of "tchars." This bitmask
// will hold a bit for every extended ASCII char. If the bit
// is set, it is a tchar.
static const uint8_t tchar_bitmask[32] = {
	// 0x00–0x1F: control chars
	0, 0, 0, 0,
	// 0x20–0x27: <SP>!"#$%&'
	0xFA, // <SP>" not allowed
	// 0x28–0x2F: ()*+,-./
	0x6C, // (),/ not allowed
	// 0x30–0x37: 0–7
	0xFF,
	// 0x38–0x3F: 89:;<=>?
	0x03, // Only 89 allowed
	// 0x40–0x47: @ABCDEFG
	0x7E, // @ not allowed
	// 0x48–0x4F: HIJKLMNO
	0xFF,
	// 0x50–0x57: PQRSTUVW
	0xFF,
	// 0x58–0x5F: XYZ[\]^_
	0xC7, // [\] not allowed
	// 0x60–0x67: `abcdefg
	0xFF,
	// 0x68–0x6F: hijklmno
	0xFF,
	// 0x70–0x77: pqrstuvw
	0xFF,
	// 0x78–0x7F: xyz{|}~<DEL>
	0x57, // {}<DEL> not allowed
	// 0x80–0xFF
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

// HTTP defines segments as a sequence of "pchars." This bitmask
// will hold a bit for every extended ASCII char. If the bit
// is set, it is a pchar or its upper bit is set (not normal ASCII).
// This isn't spec conformant but I want users to be able to have
// UTF-8 request targets.
static const uint8_t pchar_nonascii_bitmask[32] = {
	// 0x00–0x1F: control chars
	0, 0, 0, 0,
	// 0x20–0x27: <SP>!"#$%&'
	0xD2, // <SP>"#% not allowed
	// 0x28–0x2F: ()*+,-./
	0x7F, // / not allowed
	// 0x30–0x37: 0–7
	0xFF,
	// 0x38–0x3F: 89:;<=>?
	0x2F, // <>? not allowed
	// 0x40–0x47: @ABCDEFG
	0xFF,
	// 0x48–0x4F: HIJKLMNO
	0xFF,
	// 0x50–0x57: PQRSTUVW
	0xFF,
	// 0x58–0x5F: XYZ[\]^_
	0x87, // [\]^ not allowed
	// 0x60–0x67: `abcdefg
	0xFE, // ` not allowed
	// 0x68–0x6F: hijklmno
	0xFF,
	// 0x70–0x77: pqrstuvw
	0xFF,
	// 0x78–0x7F: xyz{|}~<DEL>
	0x47, // {|}<DEL> not allowed
	// 0x80–0xFF
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF
};

// I tested 4 implementations on small strings:
// 1. Branching Add
// 2. Branching bitwise OR
// 3. Branchless
// 4. Lookup
//
// Lookup was ~1-1.4ns faster/run on my machine on some of the most common
// HTTP headers (camelcase and lowercase). This implementation has 1
// major issue: if the lookup table is ever evicted from the L1 cache
// it is almost certainly the slowest implementation by at least an
// order of magnitude.
static const unsigned char tchar_lower_lookup[127] = {
	0x00,
	0x01,
	0x02,
	0x03,
	0x04,
	0x05,
	0x06,
	0x07,
	0x08,
	0x09,
	0x0A,
	0x0B,
	0x0C,
	0x0D,
	0x0E,
	0x0F,
	0x10,
	0x11,
	0x12,
	0x13,
	0x14,
	0x15,
	0x16,
	0x17,
	0x18,
	0x19,
	0x1A,
	0x1B,
	0x1C,
	0x1D,
	0x1E,
	0x1F,
	0x20,
	0x21,
	0x22,
	0x23,
	0x24,
	0x25,
	0x26,
	0x27,
	0x28,
	0x29,
	0x2A,
	0x2B,
	0x2C,
	0x2D,
	0x2E,
	0x2F,
	0x30,
	0x31,
	0x32,
	0x33,
	0x34,
	0x35,
	0x36,
	0x37,
	0x38,
	0x39,
	0x3A,
	0x3B,
	0x3C,
	0x3D,
	0x3E,
	0x3F,
	0x40,
	// 'A'
	0x61,
	0x62,
	0x63,
	0x64,
	0x65,
	0x66,
	0x67,
	0x68,
	0x69,
	0x6A,
	0x6B,
	0x6C,
	0x6D,
	0x6E,
	0x6F,
	0x70,
	0x71,
	0x72,
	0x73,
	0x74,
	0x75,
	0x76,
	0x77,
	0x78,
	0x79,
	// 'Z'
	0x7A,
	0x5B,
	0x5C,
	0x5D,
	0x5E,
	0x5F,
	0x60,
	0x61,
	0x62,
	0x63,
	0x64,
	0x65,
	0x66,
	0x67,
	0x68,
	0x69,
	0x6A,
	0x6B,
	0x6C,
	0x6D,
	0x6E,
	0x6F,
	0x70,
	0x71,
	0x72,
	0x73,
	0x74,
	0x75,
	0x76,
	0x77,
	0x78,
	0x79,
	0x7A,
	0x7B,
	0x7C,
	0x7D,
	0x7E,
};

// If c is not a valid hex digit, a number > 15 will be returned
static unsigned char from_hex(char c)
{
	int base;
	int ic = (int)c;
	// TODO: Maybe make this explicitly branchless
	if (c >= '0' && c <= '9') {
		base = '0';
	} else if (c >= 'a' && c <= 'f') {
		base = 'a' - 10;
	} else if (c >= 'A' && c <= 'F') {
		base = 'A' - 10;
	} else {
		base = ic - 16;
	}
	return (unsigned char)(ic - base);
}

CC_ATTR_NONNULL(1, 2)
static int cerve_http_validate_and_normalize_header_name(char *name,
							 char *name_end)
{
	while (name < name_end && cerve_http_is_tchar(*name)) {
		int c = *name;
		*name++ = (char)tchar_lower_lookup[c];
	}
	return name == name_end;
}

int cerve_http_is_tchar(char c)
{
	unsigned char uc = (unsigned char)c;
	return tchar_bitmask[uc >> 3] & ((uint8_t)1 << (uc & 7));
}

int cerve_http_is_pchar(char c)
{
	unsigned char uc = (unsigned char)c;
	// Filter out non-ascii
	if (uc & 0x80) {
		return 0;
	}
	return cerve_http_is_pchar_or_nonascii(c);
}

int cerve_http_is_ows(char c)
{
	return c == ' ' || c == '\t';
}

int cerve_http_is_pchar_or_nonascii(char c)
{
	unsigned char uc = (unsigned char)c;
	return pchar_nonascii_bitmask[uc >> 3] & ((uint8_t)1 << (uc & 7));
}

CC_ATTR_NONNULL(1)
int cerve_http_is_token(const char *s, size_t len)
{
	size_t i;
	for (i = 0; i < len && cerve_http_is_tchar(s[i]); ++i)
		;
	return i == len;
}

CC_ATTR_NONNULL(1)
enum cerve_http_method cerve_http_parse_method(const char *method, size_t len)
{
#define RET_METHOD_OR_BREAK(enm)                         \
	if (!strncmp(method, method_to_str[enm], len)) { \
		return enm;                              \
	}                                                \
	break

	switch (*method) {
	case 'G':
		RET_METHOD_OR_BREAK(CERVE_HTTP_METHOD_GET);
	case 'P':
		switch (method[1]) {
		case 'O':
			RET_METHOD_OR_BREAK(CERVE_HTTP_METHOD_POST);
		case 'U':
			RET_METHOD_OR_BREAK(CERVE_HTTP_METHOD_PUT);
		case 'A':
			RET_METHOD_OR_BREAK(CERVE_HTTP_METHOD_PATCH);
		default:
			break;
		}
		break;
	case 'D':
		RET_METHOD_OR_BREAK(CERVE_HTTP_METHOD_DELETE);
	case 'H':
		RET_METHOD_OR_BREAK(CERVE_HTTP_METHOD_HEAD);
	case 'C':
		RET_METHOD_OR_BREAK(CERVE_HTTP_METHOD_CONNECT);
	case 'O':
		RET_METHOD_OR_BREAK(CERVE_HTTP_METHOD_OPTIONS);
	case 'T':
		RET_METHOD_OR_BREAK(CERVE_HTTP_METHOD_TRACE);
	default:
		break;
	}
	return CERVE_HTTP_METHOD_INVALID;
#undef RET_METHOD_OR_BREAK
}

CC_ATTR_NONNULL(1)
enum cerve_http_version cerve_http_parse_version(const char *version,
						 size_t len)
{
	static const char *http_version_1st_5 = "HTTP/";
	if (len != 8 || strncmp(version, http_version_1st_5, 5) ||
	    version[6] != '.') {
		return CERVE_HTTP_VERSION_AUTO;
	}
	char d1 = version[5];
	char d2 = version[7];
	switch (d1) {
	case '1':
		switch (d2) {
		case '0':
			return CERVE_HTTP_VERSION_10;
		case '1':
			return CERVE_HTTP_VERSION_11;
		default:
			break;
		}
		break;
	case '2':
		switch (d2) {
		case '0':
			return CERVE_HTTP_VERSION_20;
		default:
			break;
		}
		break;
	case '3':
		switch (d2) {
		case '0':
			return CERVE_HTTP_VERSION_30;
		default:
			break;
		}
		break;
	default:
		break;
	}
	return CERVE_HTTP_VERSION_AUTO;
}

CC_ATTR_NONNULL(1, 3, 4, 5)
enum cerve_http_parse_path_err cerve_http_parse_path(char *path, size_t len,
						     size_t *len_new,
						     char **query,
						     size_t *query_len)
{
	*query = NULL;
	*query_len = 0;
	if (path[0] != '/') {
		// Support asterisk-form
		if (path[0] == '*' && path[1] == ' ') {
			*len_new = 1;
			return CERVE_HTTP_PATH_ERR_OK;
		} else {
			return CERVE_HTTP_PATH_ERR_BAD_FORM;
		}
	}
	size_t len_loss = 0;
	char *end = path + len;
	char *read = path + 1;
	char *write = path + 1;
	char *path_start = path + 1;

	char c = *read;
	while (read < end) {
		if (cerve_http_is_pchar_or_nonascii(c)) {
			*write++ = c;
			c = *(++read);
			continue;
		}

		if (c == '/') {
			path_start = read + 1;
			goto copy_and_inc;
		} else if (c == '%') {
			if (read + 2 >= end) {
				return CERVE_HTTP_PATH_ERR_BAD_PCT_ENCODE;
			}
			uint8_t d1 = from_hex(read[1]);
			uint8_t d2 = from_hex(read[2]);
			if (d1 > 15 || d2 > 15) {
				return CERVE_HTTP_PATH_ERR_BAD_PCT_ENCODE;
			}
			uint8_t val = (uint8_t)((d1 << 4) | d2);
			if (val < 0x20 || val == 0x7F) {
				return CERVE_HTTP_PATH_ERR_BAD_PCT_ENCODE;
			}
			c = (char)val;
			read += 2;
			len_loss += 2;
			goto copy_and_inc;
		} else if (c == '?') {
			size_t move_bytes = (size_t)(end - read);
			memmove(write, read, move_bytes);
			write += move_bytes;
			*query = read;
			*query_len = move_bytes;
			break;
		}
		return CERVE_HTTP_PATH_ERR_BAD_CHAR;
copy_and_inc:
		*write++ = c;
		c = *(++read);
	}
	*len_new = len - len_loss;
	if (end > write) {
		// Fill replaced bytes with white space
		memset(write, ' ', (size_t)(end - write));
	}
	return CERVE_HTTP_PATH_ERR_OK;
}

enum cerve_http_parse_status_line_err
cerve_http_parse_status_line(struct cerve_http_request_internal *state)
{
	cassert(state != NULL);
	cassert(state->req.raw != NULL);
	cassert(state->state == CERVE_HTTP_REQUEST_PARSE_STATUS_LINE);

	char *buf = state->buf;
	// Check if entire status line is here
	char *sl_end = memmem(buf, state->req.raw_len, "\r\n", 2);
	if (sl_end == NULL) {
		return CERVE_HTTP_SL_ERR_INCOMPLETE;
	}
	cassert(sl_end < state->buf + state->req.raw_len);
	// Detect if this is an HTTP2 or HTTP3 request. If so, we get status line
	// info in headers stage.
	if (*buf == ':') {
		return CERVE_HTTP_SL_ERR_HTTP2;
	}

	char *method, *path, *version;
	size_t method_len, path_len, version_len;
	char *method_end, *path_end, *version_end;

	method = buf;
	method_end = strchr(method, ' ');
	if (method_end == NULL) {
		return CERVE_HTTP_SL_ERR_BAD_LINE;
	}
	method_len = (size_t)(method_end - method);

	path = method_end + 1;
	path_end = strchr(path, ' ');
	if (path_end == NULL) {
		return CERVE_HTTP_SL_ERR_BAD_LINE;
	}
	path_len = (size_t)(path_end - path);

	version = path_end + 1;
	version_end = sl_end;
	version_len = (size_t)(version_end - version);

	struct cerve_http_request *req = &state->req;
	req->method = cerve_http_parse_method(method, method_len);
	if (req->method == CERVE_HTTP_METHOD_INVALID) {
		return CERVE_HTTP_SL_ERR_BAD_METHOD;
	}

	req->version = cerve_http_parse_version(version, version_len);
	if (req->version == CERVE_HTTP_VERSION_AUTO) {
		return CERVE_HTTP_SL_ERR_BAD_VERSION;
	}

	char *query;
	size_t query_len;
	enum cerve_http_parse_path_err path_err = cerve_http_parse_path(
		path, path_len, &path_len, &query, &query_len);
	if (path_err != CERVE_HTTP_PATH_ERR_OK) {
		// Give the actual error to the caller
		state->err_ctx = (void *)path_err;
		return CERVE_HTTP_SL_ERR_BAD_PATH;
	}

	req->path = path;
	req->path_len = path_len;
	req->query = query;
	req->query_len = query_len;

	// Point just after the \r\n
	state->parse_pos = sl_end + 2;
	// We don't udpate the state enum. The caller is responsible for that

	return CERVE_HTTP_SL_ERR_OK;
}

enum cerve_http_parse_headers_err
cerve_http_parse_headers(struct cerve_http_request_internal *state)
{
	cassert(state != NULL);
	cassert(state->req.raw != NULL);
	cassert(state->state == CERVE_HTTP_REQUEST_PARSE_HEADERS);
	cassert(state->headers_map.type == CERVE_HTTP_HEADERS_MAP);

	char *buf_end = state->buf + state->req.raw_len;
	while (state->parse_pos < buf_end) {
		size_t line_len;
		char *hline_start = state->parse_pos;
		char *hline_end = memmem(hline_start,
					 (size_t)(buf_end - hline_start),
					 "\r\n", 2);
		// Check common case first
		if (hline_end > hline_start) {
			goto parse_line;
		} else if (hline_end == hline_start) {
			// End of headers section
			state->parse_pos = hline_start + 2;
			return CERVE_HTTP_HDR_ERR_OK;
		} else {
			// hline_end is NULL or less than hline_start. Second
			// case isn't possible
			return CERVE_HTTP_HDR_ERR_INCOMPLETE;
		}
parse_line:
		// At this point we know there is a header to parse. We need to
		// normalize it (set name to lowercase), validate it, and add it
		// to the headers_map.
		line_len = (size_t)(hline_end - hline_start);
		char *colon = memchr(hline_start, ':', line_len);
		if (colon == NULL) {
			return CERVE_HTTP_HDR_ERR_MISSING_COLON;
		}

		if (!cerve_http_validate_and_normalize_header_name(hline_start,
								   colon)) {
			return CERVE_HTTP_HDR_ERR_NAME_NOT_TOKEN;
		}

		char *value = colon + 1;
		while (cerve_http_is_ows(*value))
			value += 1;

		size_t name_len = (size_t)(colon - hline_start);
		size_t value_len = (size_t)(hline_end - value);
		// Is this possible? Not realistically. Could this cause major
		// issues if it happened? Most definitely.
		cassert(name_len <= UINT_MAX);
		cassert(value_len <= UINT_MAX);

		struct cerve_http_header header;
		header.name = hline_start;
		header.value = value;
		header.name_len = (unsigned int)name_len;
		header.value_len = (unsigned int)value_len;

		int err = cerve_http_headers_map_add(&state->headers_map.map,
						     &header);
		if (err) {
			state->err_ctx = (void *)(intptr_t)err;
			return CERVE_HTTP_HDR_ERR_MAP_ADD_FAIL;
		}

		state->parse_pos = hline_end + 2;
	}
	return CERVE_HTTP_HDR_ERR_INCOMPLETE;
}
