include ../common.mk

ROOT            := $(abspath $(CURDIR)/../..)
PORT_DIR        := $(CURDIR)
GEN_DIR         := $(PORT_DIR)/generated
GEN_SCRIPT      := $(ROOT)/scripts/gen_msvcrt_exports.py
WINE_SRC        ?= /Users/swift/wine-proton-macos
LOCAL_SPEC      := $(abspath $(CURDIR)/msvcrt.spec)
FALLBACK_SPEC   := $(WINE_SRC)/dlls/msvcrt/msvcrt.spec
SPEC            := $(firstword $(wildcard $(LOCAL_SPEC) $(FALLBACK_SPEC)))
SPEC_DEPS       := $(wildcard $(LOCAL_SPEC) $(FALLBACK_SPEC))
PASSTHROUGH     := $(abspath $(CURDIR)/passthrough_exports.txt)
PASSTHROUGH_DEP := $(wildcard $(PASSTHROUGH))
GEN_C           := $(GEN_DIR)/msvcrt_exports.generated.c
GEN_DEF         := $(GEN_DIR)/msvcrt_exports.generated.def
REAL_OBJ_DIR    := $(GEN_DIR)/real
OBJCPY          ?= objcopy
REAL_FULL_OBJS  := $(REAL_OBJ_DIR)/string.full.o \
                   $(REAL_OBJ_DIR)/wcs.full.o \
                   $(REAL_OBJ_DIR)/errno.full.o
REAL_OBJS       := $(REAL_OBJ_DIR)/string.o \
                   $(REAL_OBJ_DIR)/wcs.o \
                   $(REAL_OBJ_DIR)/errno.o
REAL_CFLAGS     := $(CFLAGS) $(WINE_CFLAGS) -I$(WINE_INCLUDE_DIR)/msvcrt -D_CRTIMP= -D__WINESRC__ -ffunction-sections -fdata-sections
REAL_WCS_CFLAGS := $(REAL_CFLAGS) -DWINEMU_MSVCRT_NO_WTYPES
GEN_STAMP       := $(GEN_DIR)/.exports.stamp
OUT             := $(SYSROOT)/msvcrt.dll

all: $(OUT)

$(GEN_DIR):
	mkdir -p $@

$(REAL_OBJ_DIR):
	mkdir -p $@

$(GEN_STAMP): $(GEN_SCRIPT) $(SPEC_DEPS) $(PASSTHROUGH_DEP) | $(GEN_DIR)
	@[ -n "$(SPEC)" ] || { \
		echo "msvcrt.spec not found. Run: ./scripts/sync_wine_sources.sh"; \
		exit 1; \
	}
	python3 $(GEN_SCRIPT) \
		--spec "$(SPEC)" \
		--out-c "$(GEN_C)" \
		--out-def "$(GEN_DEF)" \
		--passthrough "$(PASSTHROUGH)"
	@touch "$@"

$(GEN_C) $(GEN_DEF): $(GEN_STAMP)

$(REAL_OBJ_DIR)/string.full.o: string.c | $(REAL_OBJ_DIR)
	$(CC) $(REAL_CFLAGS) -c $< -o $@

$(REAL_OBJ_DIR)/wcs.full.o: wcs.c | $(REAL_OBJ_DIR)
	$(CC) $(REAL_WCS_CFLAGS) -c $< -o $@

$(REAL_OBJ_DIR)/errno.full.o: errno.c | $(REAL_OBJ_DIR)
	$(CC) $(REAL_CFLAGS) -c $< -o $@

$(REAL_OBJ_DIR)/string.o: $(REAL_OBJ_DIR)/string.full.o
	$(OBJCPY) -w \
		-j .text -j .data -j .bss -j '.rdata*' \
		-j '.text$$_memccpy' \
		-j '.text$$memchr' \
		-j '.text$$memcmp' \
		-j '.text$$memcpy' \
		-j '.text$$memmove' \
		-j '.text$$memset' \
		-j '.text$$strcat' \
		-j '.text$$strchr' \
		-j '.text$$strcmp' \
		-j '.text$$strcpy' \
		-j '.text$$strlen' \
		-j '.text$$strncmp' \
		-j '.text$$strncpy' \
		-j '.text$$strnlen' \
		-j '.text$$strrchr' \
		-j '.text$$strcspn' \
		-j '.text$$strncat' \
		-j '.text$$strpbrk' \
		-j '.text$$strspn' \
		-j '.text$$strstr' \
		-j '.text$$strcpy_s' \
		-j '.text$$strcat_s' \
		-j '.text$$strncpy_s' \
		-j '.text$$strncat_s' \
		$< $@
	$(OBJCPY) --strip-unneeded \
		-K _memccpy \
		-K memchr \
		-K memcmp \
		-K memcpy \
		-K memmove \
		-K memset \
		-K strcat \
		-K strchr \
		-K strcmp \
		-K strcpy \
		-K strlen \
		-K strncmp \
		-K strncpy \
		-K strnlen \
		-K strrchr \
		-K strcspn \
		-K strncat \
		-K strpbrk \
		-K strspn \
		-K strstr \
		-K strcpy_s \
		-K strcat_s \
		-K strncpy_s \
		-K strncat_s \
		$@

$(REAL_OBJ_DIR)/wcs.o: $(REAL_OBJ_DIR)/wcs.full.o
	$(OBJCPY) -w \
		-j .text -j .data -j .bss -j '.rdata*' \
		-j '.text$$wcscat' \
		-j '.text$$wcscat_s' \
		-j '.text$$wcschr' \
		-j '.text$$wcscmp' \
		-j '.text$$wcscpy' \
		-j '.text$$wcscpy_s' \
		-j '.text$$wcscspn' \
		-j '.text$$wcslen' \
		-j '.text$$wcsncat' \
		-j '.text$$wcsncat_s' \
		-j '.text$$wcsncmp' \
		-j '.text$$wcsncpy' \
		-j '.text$$wcsncpy_s' \
		-j '.text$$wcsnlen' \
		-j '.text$$wcspbrk' \
		-j '.text$$wcsrchr' \
		-j '.text$$wcsrtombs' \
		-j '.text$$wcsrtombs_s' \
		-j '.text$$wcsspn' \
		-j '.text$$wcsstr' \
		-j '.text$$wcstod' \
		-j '.text$$wcstok' \
		-j '.text$$wcstok_s' \
		-j '.text$$wcstol' \
		-j '.text$$wcstombs' \
		-j '.text$$wcstombs_s' \
		-j '.text$$wcstoul' \
		-j '.text$$wctob' \
		-j '.text$$wctomb' \
		-j '.text$$wctomb_s' \
		-j '.text$$_wcslwr' \
		-j '.text$$_wcslwr_l' \
		-j '.text$$_wcslwr_s' \
		-j '.text$$_wcslwr_s_l' \
		-j '.text$$_wcsnset' \
		-j '.text$$_wcsnset_s' \
		-j '.text$$_wcsrev' \
		-j '.text$$_wcsset' \
		-j '.text$$_wcsset_s' \
		-j '.text$$_wcstoi64_l' \
		-j '.text$$_wcstol_l' \
		-j '.text$$_wcstoui64_l' \
		-j '.text$$_wcstoul_l' \
		-j '.text$$_wcsupr' \
		-j '.text$$_wcsupr_l' \
		-j '.text$$_wcsupr_s' \
		-j '.text$$_wcsupr_s_l' \
		-j '.text$$_wtoi' \
		-j '.text$$_wtoi64' \
		-j '.text$$_wtoi64_l' \
		-j '.text$$_wtoi_l' \
		-j '.text$$_wtol' \
		-j '.text$$_wtol_l' \
		-j '.xdata$$wcstok' \
		-j '.pdata$$wcstok' \
		-j '.xdata$$wcstok_s' \
		-j '.pdata$$wcstok_s' \
		$< $@
	$(OBJCPY) --strip-unneeded \
		-K wcscat \
		-K wcscat_s \
		-K wcschr \
		-K wcscmp \
		-K wcscpy \
		-K wcscpy_s \
		-K wcscspn \
		-K wcslen \
		-K wcsncat \
		-K wcsncat_s \
		-K wcsncmp \
		-K wcsncpy \
		-K wcsncpy_s \
		-K wcsnlen \
		-K wcspbrk \
		-K wcsrchr \
		-K wcsrtombs \
		-K wcsrtombs_s \
		-K wcsspn \
		-K wcsstr \
		-K wcstod \
		-K wcstok \
		-K wcstok_s \
		-K wcstol \
		-K wcstombs \
		-K wcstombs_s \
		-K wcstoul \
		-K wctob \
		-K wctomb \
		-K wctomb_s \
		-K _wcslwr \
		-K _wcslwr_l \
		-K _wcslwr_s \
		-K _wcslwr_s_l \
		-K _wcsnset \
		-K _wcsnset_s \
		-K _wcsrev \
		-K _wcsset \
		-K _wcsset_s \
		-K _wcstoi64_l \
		-K _wcstol_l \
		-K _wcstoui64_l \
		-K _wcstoul_l \
		-K _wcsupr \
		-K _wcsupr_l \
		-K _wcsupr_s \
		-K _wcsupr_s_l \
		-K _wtoi \
		-K _wtoi64 \
		-K _wtoi64_l \
		-K _wtoi_l \
		-K _wtol \
		-K _wtol_l \
		$@

$(REAL_OBJ_DIR)/errno.o: $(REAL_OBJ_DIR)/errno.full.o
	$(OBJCPY) -w \
		-j '.text$$__doserrno' \
		-j '.text$$_errno' \
		-j '.text$$_get_doserrno' \
		-j '.text$$_get_errno' \
		-j '.text$$_set_doserrno' \
		-j '.text$$_set_errno' \
		-j '.text$$msvcrt_set_errno' \
		-j '.data*' \
		-j '.rdata*' \
		-j '.bss*' \
		$< $@
	$(OBJCPY) --strip-unneeded \
		-K __doserrno \
		-K _errno \
		-K _get_doserrno \
		-K _get_errno \
		-K _set_doserrno \
		-K _set_errno \
		-K msvcrt_set_errno \
		-K MSVCRT__sys_errlist \
		-K MSVCRT__sys_nerr \
		$@

$(OUT): $(GEN_C) $(GEN_DEF) $(REAL_OBJS) | $(SYSROOT)
	rm -f "$@"
	$(CC) $(CFLAGS) $(WINE_CFLAGS) -shared -o $@ $(GEN_C) $(GEN_DEF) $(REAL_OBJS) -Wl,--gc-sections -Wl,--out-implib,$(SYSROOT)/msvcrt.lib

.PHONY: all clean
clean:
	rm -f "$(OUT)" "$(SYSROOT)/msvcrt.lib"
	rm -rf "$(GEN_DIR)"
