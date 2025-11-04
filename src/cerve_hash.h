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

#ifndef CERVE_SRC_HASH_H
#define CERVE_SRC_HASH_H

#include <stddef.h>
#include <stdint.h>

uint64_t cerve_hash_xxh64(void *data, size_t len);
uint64_t cerve_hash_xxh64_seed(void *data, size_t len, uint64_t seed);

#endif /* CERVE_SRC_HASH_H */
