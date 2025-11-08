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

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <cerve_http.h>

#include "cerve_cc.h"
#include "cerve_debug.h"
#include "cerve_http_headers.h"
#include "cerve_http_parse.h"
#include "cerve_list.h"
#include "cerve_map.h"

#define CERVE_HTTP_HEADERS_MAP_ENTRY_MAGIC_BYTE ((unsigned char)0x80)

// INTERNAL HEADERS MAP FUNCTIONS
// NOTE: I abuse my list library by not using a sentinal node. Each node contains
// valid data. Because of this, I can't use macros like list_for_each.

static bool cerve_http_headers_map_is_entry(const char *value)
{
	return (unsigned char)*value == CERVE_HTTP_HEADERS_MAP_ENTRY_MAGIC_BYTE;
}

static struct cerve_http_headers_map_entry *
cerve_http_headers_map_entry_from_raw(char *raw)
{
	// This suppresses compiler alignment cast warnings
	return (struct cerve_http_headers_map_entry *)cc_assume_aligned(
		raw, cc_alignof(struct cerve_http_headers_map_entry));
}

static unsigned int cerve_http_headers_map_value_len(const char *value)
{
	char *end = strstr(value, "\r\n");
	if (end != NULL) {
		return (unsigned int)(end - value);
	}
	return (unsigned int)strlen(value);
}

static void cerve_http_map_free_entry(void *key, size_t key_len, void *data)
{
	(void)key;
	(void)key_len;
	cassert(key != NULL);
	cassert(key_len > 0);
	cassert(data != NULL);

	char *entry_raw = (char *)data;
	if (!cerve_http_headers_map_is_entry((char *)data)) {
		return;
	}

	// Linked list of values. Need to free them.
	struct cerve_http_headers_map_entry *entry =
		(struct cerve_http_headers_map_entry *)data;

	struct slist_link *head, *next;
	head = &entry->next;
	do {
		next = entry->next.next;
		free(entry);
		entry = list_entry(next, struct cerve_http_headers_map_entry,
				   next);
	} while (head != next);
}

int cerve_http_headers_map_init(struct cerve_http_headers_map *headers,
				size_t len)
{
	cassert(headers != NULL);
	cassert(len > 0);

	return cerve_map_init_default(&headers->map, len,
				      cerve_http_map_free_entry);
}

int cerve_http_headers_map_deinit(struct cerve_http_headers_map *headers)
{
	cassert(headers != NULL);

	cerve_map_deinit(&headers->map);
	return 0;
}

int cerve_http_headers_map_add(struct cerve_http_headers_map *headers,
			       const struct cerve_http_header *header)
{
	cassert(headers != NULL);
	cassert(header != NULL);
	cassert(header->name != NULL);
	cassert(header->value != NULL);
	cassert(header->name_len > 0);
	cassert(header->value_len > 0);

	// We may need to use this hash twice. Let's compute once and reuse
	uint64_t hash = headers->map.hash_fn(
		(void *)header->name, header->name_len, headers->map.hash_seed);

	char *entry_old = cerve_map_get_precomp_hash(
		&headers->map, header->name, header->name_len, hash);

	if (entry_old == NULL) {
		// Store the value directly to avoid an allocation in the common case.
		return cerve_map_set_no_rehash_precomp_hash(
			&headers->map, header->name, header->name_len,
			header->value, hash);
	}

	struct cerve_http_headers_map_entry *entry_new, *entry_old_head;
	// Value already in map. Need to determine if it is a single or linked list of
	// values
	entry_new = malloc(sizeof(*entry_new));
	if (entry_new == NULL) {
		return ENOMEM;
	}
	entry_new->magic = CERVE_HTTP_HEADERS_MAP_ENTRY_MAGIC_BYTE;
	entry_new->value_len = header->value_len;
	slist_init(&entry_new->next);
	entry_new->value = header->value;
	if (!cerve_http_headers_map_is_entry(entry_old)) {
		// Upgrade the single value to a linked list
		entry_old_head = malloc(sizeof(*entry_old_head));
		if (entry_old_head == NULL) {
			free(entry_new);
			return ENOMEM;
		}
		entry_old_head->magic = CERVE_HTTP_HEADERS_MAP_ENTRY_MAGIC_BYTE;
		entry_old_head->value_len = cerve_http_headers_map_value_len(entry_old);
		slist_init(&entry_old_head->next);
		entry_old_head->value = entry_old;
		int err = cerve_map_set_no_rehash_precomp_hash(
			&headers->map, header->name, header->name_len,
			entry_old_head, hash);
		if (err) {
			free(entry_new);
			free(entry_old_head);
			return err;
		}
	} else {
		// Already a linked list
		entry_old_head =
			cerve_http_headers_map_entry_from_raw(entry_old);
	}
	slist_add(&entry_new->next, &entry_old_head->next);
	return 0;
}

int cerve_http_headers_map_get(struct cerve_http_headers_map *headers,
			       struct cerve_http_header *header,
			       struct cerve_http_headers_map_entry **entry,
			       enum cerve_http_headers_map_value_type *which)
{
	char *entry_raw =
		cerve_map_get(&headers->map, header->name, header->name_len);
	if (entry_raw == NULL) {
		return ENOENT;
	}

	if (!cerve_http_headers_map_is_entry(entry_raw)) {
		header->value = entry_raw;
		header->value_len = cerve_http_headers_map_value_len(entry_raw);
		*entry = NULL;
		*which = CERVE_HTTP_HEADERS_MAP_VALUE_RAW;
	} else {
		header->value = NULL;
		header->value_len = 0;
		*entry = cerve_http_headers_map_entry_from_raw(entry_raw);
		*which = CERVE_HTTP_HEADERS_MAP_VALUE_LIST;
	}
	return 0;
}

// PUBLIC HEADERS FUNCTIONS

/*
int cerve_http_headers_get(const struct cerve_http_headers *headers,
			   struct cerve_http_header *header)
{
	// assert_headers_valid(headers);
	cassert(header != NULL);
	cassert(header->name != NULL);
	cassert(header->name_len > 0);

	cpanic();
}

int cerve_http_headers_add(struct cerve_http_headers *headers,
			   const struct cerve_http_header *header)
{
	// assert_headers_valid(headers);
	cassert(headers->type == CERVE_HTTP_HEADERS_RAW);
	cassert(header != NULL);
	cassert(header->name != NULL);
	cassert(header->name_len > 0);
	cassert(header->value != NULL);
	cassert(header->value_len > 0);

	cpanic();
}

size_t cerve_http_headers_count(const struct cerve_http_headers *headers)
{
	// assert_headers_valid(headers);

	cpanic();
}

void cerve_http_headers_iter_init(const struct cerve_http_headers *headers,
				  struct cerve_http_headers_iter *iter)
{
	// assert_headers_valid(headers);

	cpanic();
}

bool cerve_http_headers_iter_next(struct cerve_http_headers_iter *iter,
				  struct cerve_http_header *header_next)
{
	cpanic();
}
*/

bool cerve_http_header_valid_name(const char *name, size_t len)
{
	return !!cerve_http_is_token(name, len);
}
