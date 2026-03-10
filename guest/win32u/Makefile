include ../common.mk

ROOT            := $(abspath $(CURDIR)/../..)
PORT_DIR        := $(CURDIR)
GEN_DIR         := $(PORT_DIR)/generated
GEN_SCRIPT      := $(ROOT)/scripts/gen_win32u_exports.py
WINE_SRC        ?= /Users/swift/wine-proton-macos
LOCAL_SPEC      := $(abspath $(CURDIR)/win32u.spec)
FALLBACK_SPEC   := $(WINE_SRC)/dlls/win32u/win32u.spec
SPEC            := $(firstword $(wildcard $(LOCAL_SPEC) $(FALLBACK_SPEC)))
SPEC_DEPS       := $(wildcard $(LOCAL_SPEC) $(FALLBACK_SPEC))
PASSTHROUGH     := $(abspath $(CURDIR)/passthrough_exports.txt)
PASSTHROUGH_DEP := $(wildcard $(PASSTHROUGH))
# Windows build number — controls which win32k syscall reference table is used.
# Override with: make WINDOWS_BUILD=26100
WINDOWS_BUILD   ?= 22631
SYSCALL_REF     ?= /Users/swift/Downloads/SyscallTables-master/data/Composition/ARM64/win32k/$(WINDOWS_BUILD).txt
SYSCALL_REF_DEP := $(wildcard $(SYSCALL_REF))
SYSCALL_REF_OPT := $(if $(SYSCALL_REF_DEP),--syscall-ref "$(SYSCALL_REF)",)
GEN_C           := $(GEN_DIR)/win32u_exports.generated.c
GEN_DEF         := $(GEN_DIR)/win32u_exports.generated.def
GEN_SYSNO       := $(GEN_DIR)/win32k_sysno_generated.h
GEN_SYSCALLS_H  := $(GEN_DIR)/win32syscalls.h
GEN_MAP         := $(GEN_DIR)/win32k_sysno_map.csv
GEN_SYSNO_RS    := $(ROOT)/crates/winemu-shared/src/win32k_sysno_generated.rs
REAL_OBJ_DIR    := $(GEN_DIR)/real
OBJCPY          ?= objcopy
REAL_FULL_OBJS  := $(REAL_OBJ_DIR)/main.full.o
REAL_OBJS       := $(REAL_OBJ_DIR)/main.o \
                   $(REAL_OBJ_DIR)/syscall.o
REAL_CFLAGS     := $(CFLAGS) $(WINE_CFLAGS) -I$(GEN_DIR) -I$(WINE_INCLUDE_DIR)/msvcrt -D_CRTIMP= -D__WINESRC__ -D__WINE_PE_BUILD -ffunction-sections -fdata-sections
REAL_SYSCALL_CFLAGS := $(REAL_CFLAGS) -DWINEMU_PE_GUEST
GEN_STAMP       := $(GEN_DIR)/.exports.stamp
OUT             := $(SYSROOT)/win32u.dll

all: $(OUT)

$(GEN_DIR):
	mkdir -p $@

$(REAL_OBJ_DIR):
	mkdir -p $@

$(GEN_STAMP): $(GEN_SCRIPT) $(SPEC_DEPS) $(PASSTHROUGH_DEP) $(SYSCALL_REF_DEP) | $(GEN_DIR)
	@[ -n "$(SPEC)" ] || { \
		echo "win32u.spec not found. Run: ./scripts/sync_wine_sources.sh"; \
		exit 1; \
	}
	python3 $(GEN_SCRIPT) \
		--spec "$(SPEC)" \
		--out-c "$(GEN_C)" \
		--out-def "$(GEN_DEF)" \
		--out-sysno "$(GEN_SYSNO)" \
		--out-win32syscalls "$(GEN_SYSCALLS_H)" \
		--out-rust "$(GEN_SYSNO_RS)" \
		--out-map "$(GEN_MAP)" \
		--no-dllmain \
		$(SYSCALL_REF_OPT) \
		--passthrough "$(PASSTHROUGH)"
	@touch "$@"

$(GEN_C) $(GEN_DEF) $(GEN_SYSNO) $(GEN_SYSCALLS_H): $(GEN_STAMP)

$(REAL_OBJ_DIR)/main.full.o: main.c $(GEN_SYSCALLS_H) | $(REAL_OBJ_DIR)
	$(CC) $(REAL_CFLAGS) -c $< -o $@

$(REAL_OBJ_DIR)/syscall.o: syscall.c $(GEN_SYSCALLS_H) | $(REAL_OBJ_DIR)
	$(CC) $(REAL_SYSCALL_CFLAGS) -c $< -o $@

$(REAL_OBJ_DIR)/main.o: $(REAL_OBJ_DIR)/main.full.o
	$(OBJCPY) -w \
		-j '.text$$DllMain' \
		-j '.xdata$$DllMain' \
		-j '.pdata$$DllMain' \
		-j '.text$$__wine_spec_unimplemented_stub' \
		-j '.xdata$$__wine_spec_unimplemented_stub' \
		-j '.pdata$$__wine_spec_unimplemented_stub' \
		-j '.bss$$__wine_syscall_dispatcher' \
		-j '.rdata$$.refptr.__wine_unix_call_dispatcher' \
		-j '.rdata$$.refptr.__wine_unixlib_handle' \
		-j '.data$$dummy' \
		-j '.rdata*' \
		$< $@
	$(OBJCPY) --strip-unneeded \
		-K DllMain \
		-K __wine_spec_unimplemented_stub \
		-K __wine_syscall_dispatcher \
		-K dummy \
		$@

$(OUT): $(GEN_C) $(GEN_DEF) $(REAL_OBJS) | $(SYSROOT)
	rm -f "$@"
	$(CC) $(CFLAGS) $(WINE_CFLAGS) -shared -o $@ $(GEN_C) $(GEN_DEF) $(REAL_OBJS) -Wl,--gc-sections -Wl,--out-implib,$(SYSROOT)/win32u.lib

.PHONY: all clean
clean:
	rm -f "$(OUT)" "$(SYSROOT)/win32u.lib"
	rm -rf "$(GEN_DIR)"
