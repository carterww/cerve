-include config.local.mk

# release, debug, or reldebug
CERVE_BUILD_TYPE ?= reldebug
# 0 or 1
CERVE_COMPILE_ASSERTS ?= 1
# 0 or 1
VERBOSE ?= 0

CERVE_VERSION_MAJOR ?= 0
CERVE_VERSION_MINOR ?= 1
CERVE_VERSION_PATCH ?= 0
CERVE_VERSION_STRING := $(CERVE_VERSION_MAJOR).$(CERVE_VERSION_MINOR).$(CERVE_VERSION_PATCH)

CC ?= cc
LD := $(CC)

DESTDIR ?=
PREFIX ?= $(DESTDIR)/usr/local
LIBDIR ?= $(PREFIX)/lib
INCLUDEDIR ?= $(PREFIX)/include
PKGCONFIGDIR ?= $(LIBDIR)/pkgconfig

ROOTDIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
SRCDIR := $(ROOTDIR)/src
CLI_SRCDIR := $(SRCDIR)/cli

BUILDDIR ?= $(ROOTDIR)/build

LIBNAME ?= libcerve
LDNAME := $(LIBNAME).so
LDNAME_MAJOR := $(LDNAME).$(CERVE_VERSION_MAJOR)
LDNAME_VERSION := $(LDNAME).$(CERVE_VERSION_STRING)
ARCHIVE_NAME ?= $(LIBNAME).a
CLI_NAME ?= cerve

SHARED_LIB_OUT := $(BUILDDIR)/$(LDNAME)
STATIC_LIB_OUT := $(BUILDDIR)/$(ARCHIVE_NAME)
CLI_OUT := $(BUILDDIR)/$(CLI_NAME)

CFLAGS += -std=gnu99 -fPIC -I$(ROOTDIR)/include -I$(SRCDIR)
CFLAGS += -MMD -MP

# Warning flags
CFLAGS += -Werror -Wall -Wextra -Wpedantic -Wno-unused -Wfloat-equal
CFLAGS += -Wdouble-promotion -Wformat=2 -Wformat-security -Wstack-protector
CFLAGS += -Walloca -Wvla -Wcast-qual -Wconversion -Wformat-signedness -Wshadow
CFLAGS += -Wstrict-overflow=4 -Wundef -Wstrict-prototypes -Wswitch-default
CFLAGS += -Wswitch-enum -Wnull-dereference -Wmissing-include-dirs -Wstrict-aliasing

# Security flags
CFLAGS += -fstack-protector-strong -fvisibility=hidden

LDFLAGS += -fPIC -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack -Wl,-z,separate-code

# Add custom GCC or clang flags
CC_VERSION_OUT := $(shell $(CC) --version 2>/dev/null | tr A-Z a-z)

ifneq ($(findstring clang,$(CC_VERSION_OUT)),)
# Warning flags
CFLAGS += -Warray-bounds -Warray-bounds-pointer-arithmetic -Wassign-enum
CFLAGS += -Wbad-function-cast -Wconditional-uninitialized -Wformat-type-confusion
CFLAGS += -Widiomatic-parentheses -Wimplicit-fallthrough -Wloop-analysis
CFLAGS += -Wpointer-arith -Wshift-sign-overflow -Wshorten-64-to-32
CFLAGS += -Wtautological-constant-in-range-compare -Wunreachable-code-aggressive
CFLAGS += -Wthread-safety -Wthread-safety-beta -Wcomma

# Security flags
CFLAGS += -fsanitize=safe-stack
LDFLAGS += -fsanitize=safe-stack
else ifneq ($(findstring gcc,$(CC_VERSION_OUT)),)
# Warning flags
CFLAGS += -Wformat-overflow=2 -Wformat-truncation=2 -Wtrampolines
CFLAGS += -Warray-bounds=2 -Wimplicit-fallthrough=3 -Wlogical-op
CFLAGS += -Wshift-overflow=2 -Wstringop-overflow=4 -Warith-conversion
CFLAGS += -Wduplicated-cond -Wduplicated-branches -Wstack-usage=10000
CFLAGS += -Wcast-align=strict

# Security flags
CFLAGS += -fsanitize=bounds-strict -fanalyzer
endif

CFLAGS_RELEASE := -D_FORTIFY_SOURCE=2
CFLAGS_DEBUG := -g -fsanitize=undefined,address,pointer-compare,pointer-subtract \
		-fstack-clash-protection -fno-omit-frame-pointer

ifeq ($(CERVE_BUILD_TYPE),release)
CFLAGS += -O2 $(CFLAGS_RELEASE)
CFLAGS += -DCERVE_RELEASE
else ifeq ($(CERVE_BUILD_TYPE),debug)
CFLAGS += -Og $(CFLAGS_DEBUG)
CFLAGS += -DCERVE_DEBUG
else ifeq ($(CERVE_BUILD_TYPE),reldebug)
CFLAGS += -O2 $(CFLAGS_DEBUG) $(CFLAGS_RELEASE)
CFLAGS += -DCERVE_RELDEBUG
else
$(error Invalid CERVE_BUILD_TYPE '$(CERVE_BUILD_TYPE)'. Expected one of: release, debug, reldebug)
endif

CFLAGS += -DCERVE_VERSION_MAJOR=$(CERVE_VERSION_MAJOR)
CFLAGS += -DCERVE_VERSION_MINOR=$(CERVE_VERSION_MINOR)
CFLAGS += -DCERVE_VERSION_PATCH=$(CERVE_VERSION_PATCH)
CFLAGS += -DCERVE_VERSION_STRING=\"$(CERVE_VERSION_STRING)\"
CFLAGS += -DCERVE_COMPILE_ASSERTS=$(CERVE_COMPILE_ASSERTS)

ifeq ($(VERBOSE),1)
quiet_CC =
quiet_LD =
quiet_AR =
Q =
else
quiet_CC = echo " CC    $(subst $(ROOTDIR)/,,$@)"
quiet_LD = echo " LD    $(subst $(ROOTDIR)/,,$@)"
quiet_AR = echo " AR    $(subst $(ROOTDIR)/,,$@)"
Q = @
endif

LIB_SRCS := $(SRCDIR)/cerve_hash.c $(SRCDIR)/cerve_map.c
CLI_SRCS := $(CLI_SRCDIR)/main.c

LIB_OBJS := $(patsubst $(ROOTDIR)/%.c,$(BUILDDIR)/%.o,$(LIB_SRCS))
CLI_OBJS := $(patsubst $(ROOTDIR)/%.c,$(BUILDDIR)/%.o,$(CLI_SRCS))
