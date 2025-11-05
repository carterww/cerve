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
#include <math.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "cerve_debug.h"
#include "cerve_hash.h"
#include "cerve_map.h"

#define CERVE_MAP_LEN_MIN (4)

#define MAX(a, b) (((a) > (b)) ? (a) : (b))

enum cerve_map_entry_state {
	CERVE_MAP_ENTRY_EMPTY = 0,
	CERVE_MAP_ENTRY_TOMBSTONE,
	CERVE_MAP_ENTRY_TAKEN,
};

static enum cerve_map_entry_state entry_state(const struct cerve_map *m,
					      size_t idx)
{
	uint8_t hash_trunc = m->hashes[idx];
	if (hash_trunc == 0) {
		// Lowest bit = 0 means entry is empty
		return CERVE_MAP_ENTRY_EMPTY;
	} else if (hash_trunc == 1 && m->keys[idx].key_len == 0) {
		// Upper 7 bits all 0s w/ lowest bit set means one of two things:
		// 1. Tombstone entry.
		// 2. 7 bits from hash really all 0s
		// We need to check if the key exists to see which it is
		return CERVE_MAP_ENTRY_TOMBSTONE;
	} else {
		return CERVE_MAP_ENTRY_TAKEN;
	}
}

// Round v up to the nearest power of 2
static size_t p2_roundup(size_t v)
{
	v -= 1;
	v |= v >> 1;
	v |= v >> 2;
	v |= v >> 4;
	v |= v >> 8;
	v |= v >> 16;
	v += 1;
	return v;
}

static bool isp2(size_t v)
{
	return (v & (v - 1)) == 0;
}

// Find a capacity value that fits the following criteria:
// 1. Is a power of 2.
// 2. (len/cap) <= load_factor_max
static size_t calc_p2cap(size_t len, float load_factor_max)
{
	// Gives the cap needed to maintain cap * load_factor_max = len
	// rounded up to nearest int
	float cap_rnd = ceilf((float)len / load_factor_max);
	// Round up to power of 2
	return p2_roundup((size_t)cap_rnd);
}

// Calculate the effective load factor. Effective load factor is
// the same as the load factor, but it takes the number of tombstones
// into account since those act as taken slots.
static float calc_load_factor(size_t len, size_t tombstones, size_t cap)
{
	return ((float)len + (float)tombstones) / (float)cap;
}

// Truncate the 64 bit hash value so we can store it in the map's hashes
// array. The upper 7 bits from hash are used as the upper 7 bits in
// the returned value. The lowest bit = 0 if empty, 1 if taken/tombstone.
// This function sets the lowest bit because it assumes you are marking
// the slot as taken.
static uint8_t hash_truncate(uint64_t hash)
{
	return (uint8_t)((hash >> 56) | 1);
}

// Returns cerve_map->hashes cap based on the map's cap to make it
// safe for SIMD loads/cmps.
static size_t hashes_cap_simd_safe(size_t cap)
{
	return cap + CERVE_MAP_SIMD_WIDTH - 1;
}

// Find the best capacity for the rehash if items_to_add items will
// be added.
static size_t calc_rehash_p2cap(const struct cerve_map *m, size_t len_new)
{
	size_t cap_from_len = calc_p2cap(len_new, m->load_factor_max);
	size_t cap_from_lf = m->cap;

	float lf = calc_load_factor(len_new, 0, m->cap);
	if (lf > m->load_factor_max) {
		cap_from_lf *= 2;
	}
	return MAX(cap_from_len, cap_from_lf);
}

static void assert_map_initialized(const struct cerve_map *map)
{
	cassert(map != NULL);
	cassert(map->hashes != NULL);
	cassert(map->keys != NULL);
	cassert(map->data != NULL);
	cassert(map->cap > CERVE_MAP_LEN_MIN);
}

static int cerve_alloc_arrs(uint8_t **hashes, struct cerve_map_key_entry **keys,
			    void ***data, size_t cap)
{
	int err;
	size_t cap_hashes = hashes_cap_simd_safe(cap);
	size_t hashes_size = cap_hashes * sizeof(**hashes);
	size_t keys_size = cap * sizeof(**keys);
	size_t data_size = cap * sizeof(**data);
	*hashes = malloc(hashes_size);
	if (*hashes == NULL) {
		err = ENOMEM;
		goto err_alloc_hash;
	}
	*keys = malloc(keys_size);
	if (*keys == NULL) {
		err = ENOMEM;
		goto err_alloc_keys;
	}
	*data = malloc(data_size);
	if (*data == NULL) {
		err = ENOMEM;
		goto err_alloc_data;
	}
	memset(*hashes, 0, hashes_size);
	memset(*keys, 0, keys_size);
	memset(*data, 0, data_size);
	return 0;
err_alloc_data:
	free(*keys);
err_alloc_keys:
	free(*hashes);
err_alloc_hash:
	return err;
}

static int cerve_map_rehash_internal(struct cerve_map *map, size_t p2cap)
{
	int err;

	cassert(isp2(p2cap));
	cassert(p2cap >= map->len);

	if (map->cap == p2cap && map->tombstones == 0) {
		// No reason to rehash
		return 0;
	}
	struct cerve_map map_new = *map;
	if ((err = cerve_alloc_arrs(&map_new.hashes, &map_new.keys,
				    &map_new.data, p2cap)) != 0) {
		return err;
	}
	map_new.len = 0;
	map_new.tombstones = 0;
	map_new.cap = p2cap;

	for (size_t i = 0; i < map->cap; ++i) {
		enum cerve_map_entry_state st = entry_state(map, i);
		if (st != CERVE_MAP_ENTRY_TAKEN) {
			continue;
		}
		struct cerve_map_key_entry *entry = &map->keys[i];
		if ((err = cerve_map_set_no_rehash(&map_new, entry->key,
						   entry->key_len,
						   map->data[i])) != 0) {
			goto err;
		}
	}
	free(map->hashes);
	free(map->keys);
	free(map->data);
	*map = map_new;
	return 0;
err:
	free(map_new.hashes);
	free(map_new.keys);
	free(map_new.data);
	return err;
}

int cerve_map_init(struct cerve_map *map, size_t len,
		   void (*free_data)(void *key, size_t key_len, void *data),
		   uint64_t hash_seed,
		   uint64_t (*hash)(void *key, size_t key_len, uint64_t seed),
		   float load_factor_max)
{
	int err;

	cassert(map != NULL);
	cassert(free_data != NULL);
	cassert(load_factor_max > 0.0f && load_factor_max <= 1.0f);

	if (len < CERVE_MAP_LEN_MIN) {
		len = CERVE_MAP_LEN_MIN;
	}
	size_t cap = calc_p2cap(len, load_factor_max);
	if ((err = cerve_alloc_arrs(&map->hashes, &map->keys, &map->data,
				    cap)) != 0) {
		return err;
	}
	map->len = 0;
	map->tombstones = 0;
	map->cap = cap;
	map->hash_seed = hash_seed;
	map->free_data = free_data;
	map->hash_fn = hash;
	map->load_factor_max = load_factor_max;

	// Set to default hash function
	if (map->hash_fn == NULL) {
		map->hash_seed = 0;
		map->hash_fn = cerve_hash_xxh64_seed;
	}
	return 0;
}

int cerve_map_init_default(struct cerve_map *map, size_t len,
			   void (*free_data)(void *key, size_t key_len,
					     void *data))
{
	return cerve_map_init(map, len, free_data, 0, NULL, 0.65f);
}

void cerve_map_deinit(struct cerve_map *map)
{
	assert_map_initialized(map);

	if (map->len != 0) {
		// Call free_data for each kv pair
		for (size_t i = 0; i < map->cap; ++i) {
			if (entry_state(map, i) == CERVE_MAP_ENTRY_TAKEN) {
				map->free_data(map->keys[i].key,
					       map->keys[i].key_len,
					       map->data[i]);
			}
		}
	}
	free(map->hashes);
	free(map->keys);
	free(map->data);
	memset(map, 0, sizeof(*map));
}

static bool cerve_map_get_index_with_context(const struct cerve_map *map,
					     void *key, size_t key_len,
					     size_t *idx, uint8_t hash_trunc,
					     size_t start_idx)
{
	assert_map_initialized(map);

	cassert(key != NULL);
	cassert(key_len != 0);

	for (size_t offset = 0; offset < map->cap; ++offset) {
		size_t pos = (start_idx + offset) & (map->cap - 1);
		uint8_t hash = map->hashes[pos];
		if (hash != hash_trunc) {
			if (entry_state(map, pos) == CERVE_MAP_ENTRY_EMPTY) {
				*idx = pos;
				return false;
			}
			continue;
		}
		struct cerve_map_key_entry *entry = &map->keys[pos];
		if (entry->key_len == key_len &&
		    !memcmp(entry->key, key, key_len)) {
			*idx = pos;
			return true;
		}
	}

	*idx = map->cap;
	return false;
}

static bool cerve_map_get_index(const struct cerve_map *map, void *key,
				size_t key_len, size_t *idx)
{
	assert_map_initialized(map);
	cassert(key != NULL);
	cassert(key_len != 0);

	uint64_t hash_full = map->hash_fn(key, key_len, map->hash_seed);
	uint8_t hash_trunc = hash_truncate(hash_full);
	size_t start_idx = hash_full & (map->cap - 1);

	return cerve_map_get_index_with_context(map, key, key_len, idx,
						hash_trunc, start_idx);
}

void *cerve_map_get(const struct cerve_map *map, void *key, size_t key_len)
{
	size_t idx;
	bool found = cerve_map_get_index(map, key, key_len, &idx);
	if (!found) {
		return NULL;
	}
	cassert(idx < map->cap);
	return map->data[idx];
}

int cerve_map_set(struct cerve_map *map, void *key, size_t key_len, void *data)
{
	assert_map_initialized(map);

	float lf = calc_load_factor(map->len + 1, map->tombstones, map->cap);
	if (lf > map->load_factor_max) {
		int rehash_res = cerve_map_rehash_internal(map, map->cap * 2);
		if (rehash_res) {
			return rehash_res;
		}
	}
	return cerve_map_set_no_rehash(map, key, key_len, data);
}

int cerve_map_set_no_rehash(struct cerve_map *map, void *key, size_t key_len,
			    void *data)
{
	size_t idx;

	assert_map_initialized(map);
	cassert(key != NULL);
	cassert(key_len != 0);

	uint64_t hash_full = map->hash_fn(key, key_len, map->hash_seed);
	uint8_t hash_trunc = hash_truncate(hash_full);
	size_t cap_mask = map->cap - 1;
	size_t start_idx = hash_full & cap_mask;

	bool found = cerve_map_get_index_with_context(map, key, key_len, &idx, hash_trunc, start_idx);
	if (found) {
		map->free_data(map->keys[idx].key, map->keys[idx].key_len,
			       map->data[idx]);
		goto found_slot;
	} else {
		if (idx < map->cap) {
			goto found_slot;
		}
	}

	// Searched whole map and found no empty or existing slot. Check for tombstones
	for (size_t offset = 0; offset < map->cap; ++offset) {
		idx = (start_idx + offset) & cap_mask;
		uint8_t hash = map->hashes[idx];
		if (entry_state(map, idx) == CERVE_MAP_ENTRY_TOMBSTONE) {
			map->tombstones -= 1;
			goto found_slot;
		}
	}

	return EAGAIN;

found_slot:
	cassert(idx < map->cap);
	map->hashes[idx] = hash_trunc;
	map->keys[idx].key = key;
	map->keys[idx].key_len = key_len;
	map->data[idx] = data;
	map->len += 1;

	return 0;
}

int cerve_map_delete(struct cerve_map *map, void *key, size_t key_len, void **data)
{
	size_t idx;

	assert_map_initialized(map);
	cassert(key != NULL);
	cassert(key_len != 0);

	bool found = cerve_map_get_index(map, key, key_len, &idx);
	if (!found) {
		*data = NULL;
		return ENOENT;
	}
	cassert(idx < map->cap);

	map->free_data(map->keys[idx].key, map->keys[idx].key_len,
			map->data[idx]);
	map->hashes[idx] = 1;
	map->keys[idx].key = NULL;
	map->keys[idx].key_len = 0;
	*data = map->data[idx];
	map->data[idx] = NULL;
	map->len -= 1;
	map->tombstones += 1;

	return 0;
}

int cerve_map_rehash(struct cerve_map *map, size_t len)
{
	assert_map_initialized(map);
	cassert(len > 0);

	if (len < CERVE_MAP_LEN_MIN) {
		len = CERVE_MAP_LEN_MIN;
	}
	size_t cap = calc_rehash_p2cap(map, len);
	return cerve_map_rehash_internal(map, cap);
}
