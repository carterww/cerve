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

#ifndef CERVE_SRC_CC_H
#define CERVE_SRC_CC_H

/* clang also defines __GNUC__ because it's "compatible" but I want to
 * know if it is really gcc.
 */
#if defined(__clang__)
#define CERVE_CC_CLANG
#elif defined(__GNUC__)
#define CERVE_CC_GCC
#else
#error Detected an unsupported compiler.
#endif

#if defined(CERVE_CC_GCC) || defined(CERVE_CC_CLANG)

#define cc_alignof(t) __alignof__(t)
#define cc_typeof(e) __typeof__(e)
#define cc_expect(expr, expect) __builtin_expect(expr, expect)
#define cc_likely(expr) __builtin_expect(!!(expr), 1)
#define cc_unlikely(expr) __builtin_expect(!!(expr), 0)

#define cc_barrier() __asm__ __volatile__("" ::: "memory");
#define cc_unreachable() __builtin_unreachable()
#define cc_assume_aligned(p, a) __builtin_assume_aligned(p, a)
#define cc_prefetch(p) __builtin_prefetch(p)
#define cc_has_builtin(b) __has_builtin(b)

#define CC_ATTR_ALIGNED(a) __attribute__((aligned(a)))
#define CC_ATTR_ALLOC_ALIGNED(arg_p) __attribute__((alloc_align(arg_p)))
#define CC_ATTR_NORETURN __attribute__((noreturn))
#define CC_ATTR_PACKED __attribute__((packed))
#define CC_ATTR_ALWAYS_INLINE __inline__ __attribute__((always_inline))
#define CC_ATTR_COLD __attribute__((cold))
#define CC_ATTR_HOT __attribute__((hot))
#define CC_ATTR_CONST __attribute__((const))
#define CC_ATTR_WEAK __attribute__((weak))
#define CC_ATTR_PUBLIC __attribute__((visibility("default")))
#define CC_ATTR_PRIVATE __attribute__((visibility("hidden")))
#define CC_ATTR_MAY_ALIAS __attribute__((__may_alias__))

#endif /* gcc or clang */

#endif /* CERVE_SRC_CC_H */
