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

#ifndef CERVE_SRC_PLATFORM_H
#define CERVE_SRC_PLATFORM_H

/* Figure out the architecture */
#if defined(__x86_64__) || defined(__amd64__)

#define CERVE_ARCH_X86_64

#elif defined(__arm__)

#define CERVE_ARCH_ARM32

#if defined(__thumb__)
#define CERVE_ARCH_ARM32_THUMB2
#else
#define CERVE_ARCH_ARM32_NO_THUMB2
#endif /* __thumb__ */

#elif defined(__aarch64__)

#define CERVE_ARCH_ARM64

#elif defined(__x86__) || defined(__i386__)

#define CERVE_ARCH_X86

#elif defined(__riscv)

#define CERVE_ARCH_RISCV

#if (__riscv_xlen == 64)
#define CERVE_ARCH_RISCV64
#elif (__riscv_xlen == 32)
#define CERVE_ARCH_RISCV32
#else
#error RISCV detected but not RV64 or RV32
#endif /* riscv_xlen */

#else
#error Detected an unsupported architecture.
#endif /* arch */

#endif /* CERVE_SRC_PLATFORM_H */
