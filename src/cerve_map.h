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

#ifndef CERVE_SRC_MAP_H
#define CERVE_SRC_MAP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// Support up to AVX512
#define CERVE_MAP_SIMD_WIDTH (64)

struct cerve_map_key_entry {
	size_t key_len;
	void *key;
};

struct cerve_map {
	uint8_t *hashes;
	struct cerve_map_key_entry *keys;
	void **data;
	size_t len;
	size_t tombstones;
	size_t cap;
	uint64_t hash_seed;
	void (*free_data)(void *key, size_t key_len, void *data);
	uint64_t (*hash_fn)(void *key, size_t key_len, uint64_t seed);
	float load_factor_max;
};

int cerve_map_init(struct cerve_map *map, size_t len,
		   void (*free_data)(void *key, size_t key_len, void *data),
		   uint64_t hash_seed,
		   uint64_t (*hash)(void *key, size_t key_len, uint64_t seed),
		   float load_factor_max);
int cerve_map_init_default(struct cerve_map *map, size_t len,
			   void (*free_data)(void *key, size_t key_len,
					     void *data));

void cerve_map_deinit(struct cerve_map *map);

void *cerve_map_get(const struct cerve_map *map, void *key, size_t key_len);
void *cerve_map_get_precomp_hash(const struct cerve_map *map, void *key,
				 size_t key_len, uint64_t hash);
int cerve_map_set(struct cerve_map *map, void *key, size_t key_len, void *data);
int cerve_map_set_precomp_hash(struct cerve_map *map, void *key, size_t key_len,
			       void *data, uint64_t hash);
int cerve_map_set_no_rehash(struct cerve_map *map, void *key, size_t key_len,
			    void *data);
int cerve_map_set_no_rehash_precomp_hash(struct cerve_map *map, void *key,
					 size_t key_len, void *data,
					 uint64_t hash);
int cerve_map_delete(struct cerve_map *map, void *key, size_t key_len,
		     void **data);
int cerve_map_delete_precomp_hash(struct cerve_map *map, void *key,
				  size_t key_len, void **data, uint64_t hash);
int cerve_map_rehash(struct cerve_map *map, size_t len);

#endif /* CERVE_SRC_MAP_H */
