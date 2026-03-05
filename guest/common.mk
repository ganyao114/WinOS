TOOLCHAIN := /Users/swift/CLionProjects/WinEmuBuild/toolchains/llvm-mingw-macos-universal/bin
CC        := $(TOOLCHAIN)/aarch64-w64-mingw32-gcc
CFLAGS    := -O2 -nostdlib -nostartfiles -fno-builtin -fdeclspec -Wall

SYSROOT   := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))sysroot
GUEST_ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
WINE_INCLUDE_DIR := $(GUEST_ROOT)/wine/include
WINE_COMPAT_DIR := $(GUEST_ROOT)/wine/compat
WINE_CFLAGS := -I$(WINE_COMPAT_DIR) -I$(WINE_INCLUDE_DIR) -DWINE_NO_DEBUG_MSGS -DWINE_NO_TRACE_MSGS
