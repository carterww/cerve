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

#include "cerve_cc.h"

#ifndef CERVE_SRC_DEBUG_H
#define CERVE_SRC_DEBUG_H

#ifndef static_assert
#define static_assert(x) _Static_assert(x, "")
#endif

#ifndef static_assert_msg
#define static_assert_msg _Static_assert
#endif

CC_ATTR_NORETURN
static void print_and_fail(const char *context, const char *file_name,
			   int line_number)
{
	fprintf(stderr, "[%s:%d] %s\n", file_name, line_number, context);
	abort();
}

#if defined(CERVE_COMPILE_ASSERTS) && CERVE_COMPILE_ASSERTS != 0
#define cassert(expr)                                                   \
	do {                                                            \
		if (cc_unlikely(!(expr))) {                             \
			print_and_fail(assert_failed_context, __FILE__, \
				       __LINE__);                       \
		}                                                       \
	} while (0)

#define cpanic()                                                           \
	do {                                                               \
		print_and_fail(assert_failed_context, __FILE__, __LINE__); \
	} while (0)
#else
#define cassert(expr) \
	do {          \
	} while (0)

#define cpanic() cc_unreachable()
#endif /* CERVE_COMPILE_ASSERTS */

#endif /* CERVE_SRC_DEBUG_H */
