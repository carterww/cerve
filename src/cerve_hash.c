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
#include <string.h>

#include "cerve_cc.h"
#include "cerve_hash.h"
#include "cerve_platform.h"

static uint64_t rotl64(uint64_t val, uint64_t shift)
{
	shift &= 63;
#if cc_has_builtin(__builtin_rotateleft64)
	return __builtin_rotateleft64(val, shift);
#else
	return (val << shift) | (val >> (64 - shift));
#endif
}

/* xxh64 hash section */

#define PRIME64_1 ((uint64_t)0x9E3779B185EBCA87)
#define PRIME64_2 ((uint64_t)0xC2B2AE3D27D4EB4F)
#define PRIME64_3 ((uint64_t)0x165667B19E3779F9)
#define PRIME64_4 ((uint64_t)0x85EBCA77C2B2AE63)
#define PRIME64_5 ((uint64_t)0x27D4EB2F165667C5)

static uint64_t xxh64_round_generic(uint64_t acc, uint64_t lane)
{
	acc = acc + (lane * PRIME64_2);
	acc = rotl64(acc, 31);
	return acc * PRIME64_1;
}

static uint64_t xxh64_finish_generic(void *data, size_t len, uint64_t acc)
{
	acc += len;
	uint8_t *d = (uint8_t *)data;
	while (len >= 8) {
		uint64_t lane;
		__builtin_memcpy(&lane, d, sizeof(lane));
		acc = acc ^ xxh64_round_generic(0, lane);
		acc = rotl64(acc, 27) * PRIME64_1;
		acc = acc + PRIME64_4;
		d += 8;
		len -= 8;
	}
	while (len >= 4) {
		uint32_t lane;
		__builtin_memcpy(&lane, d, sizeof(lane));
		acc = acc ^ (lane * PRIME64_1);
		acc = rotl64(acc, 23) * PRIME64_2;
		acc = acc + PRIME64_3;
		d += 4;
		len -= 4;
	}
	while (len >= 1) {
		uint8_t lane = *d;
		acc = acc ^ (lane * PRIME64_5);
		acc = rotl64(acc, 11) * PRIME64_1;
		d += 1;
		len -= 1;
	}
	acc = acc ^ (acc >> 33);
	acc = acc * PRIME64_2;
	acc = acc ^ (acc >> 29);
	acc = acc * PRIME64_3;
	acc = acc ^ (acc >> 32);
	return acc;
}

static uint64_t xxh64_merge_generic(uint64_t acc, uint64_t accn)
{
	acc = acc ^ xxh64_round_generic(0, accn);
	acc = acc * PRIME64_1;
	return acc + PRIME64_4;
}

static uint64_t cerve_hash_xxh64_seed_generic(void *data, size_t len,
					      uint64_t seed)
{
	uintptr_t data_uptr = (uintptr_t)data;
	uintptr_t data_end = data_uptr + len;
	if (len < 32) {
		uint64_t accum = seed + PRIME64_5;
		return xxh64_finish_generic(data, len, accum);
	}
	uint64_t acc1 = seed + PRIME64_1 + PRIME64_2;
	uint64_t acc2 = seed + PRIME64_2;
	uint64_t acc3 = seed;
	uint64_t acc4 = seed - PRIME64_1;

	uint8_t *d = (uint8_t *)data;
	size_t i;
	for (i = 0; i < len - 32 + 1; i += 32) {
		uint64_t lane1, lane2, lane3, lane4;
		memcpy(&lane1, &d[i], sizeof(lane1));
		memcpy(&lane2, &d[i + 8], sizeof(lane2));
		memcpy(&lane3, &d[i + 16], sizeof(lane3));
		memcpy(&lane4, &d[i + 24], sizeof(lane4));
		acc1 = xxh64_round_generic(acc1, lane1);
		acc2 = xxh64_round_generic(acc2, lane2);
		acc3 = xxh64_round_generic(acc3, lane3);
		acc4 = xxh64_round_generic(acc4, lane4);
	}
	uint64_t acc = 0;
	acc += rotl64(acc1, 1);
	acc += rotl64(acc2, 7);
	acc += rotl64(acc3, 12);
	acc += rotl64(acc4, 18);

	acc = xxh64_merge_generic(acc, acc1);
	acc = xxh64_merge_generic(acc, acc2);
	acc = xxh64_merge_generic(acc, acc3);
	acc = xxh64_merge_generic(acc, acc4);

	data_uptr += i;
	return xxh64_finish_generic((uint8_t *)data_uptr, data_end - data_uptr,
				    acc);
}

static uint64_t (*cerve_hash_xxh64_seed_resolve(void))(void *data, size_t len,
						       uint64_t seed)
{
	return cerve_hash_xxh64_seed_generic;
	// #if !defined(CERVE_ARCH_X86_64)
	// 	return cerve_hash_xxh64_seed_generic;
	// #else
	// 	if (__builtin_cpu_supports("avx2")) {
	// 		return cerve_hash_xxh64_seed_avx2;
	// 	} else if (__builtin_cpu_supports("sse2")) {
	// 		return cerve_hash_xxh64_seed_sse2;
	// 	} else {
	// 		return cerve_hash_xxh64_seed_generic;
	// 	}
	// #endif
}

__attribute__((ifunc("cerve_hash_xxh64_seed_resolve"))) uint64_t
cerve_hash_xxh64_seed(void *data, size_t len, uint64_t seed);

uint64_t cerve_hash_xxh64(void *data, size_t len)
{
	return cerve_hash_xxh64_seed(data, len, 0);
}
