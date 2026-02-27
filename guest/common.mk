TOOLCHAIN := /Users/swift/CLionProjects/WinEmuBuild/toolchains/llvm-mingw-macos-universal/bin
CC        := $(TOOLCHAIN)/aarch64-w64-mingw32-gcc
CFLAGS    := -O2 -nostdlib -nostartfiles -fno-builtin -fdeclspec -Wall

SYSROOT   := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))sysroot
