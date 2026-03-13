include ../common.mk

ROOT            := $(abspath $(CURDIR)/../..)
PORT_DIR        := $(CURDIR)
GEN_DIR         := $(PORT_DIR)/generated
GEN_SCRIPT      := $(ROOT)/scripts/gen_pe_exports.py
WINE_SRC        ?= /Users/swift/wine-proton-macos
LOCAL_SPEC      := $(abspath $(CURDIR)/shell32.spec)
FALLBACK_SPEC   := $(WINE_SRC)/dlls/shell32/shell32.spec
SPEC            := $(firstword $(wildcard $(LOCAL_SPEC) $(FALLBACK_SPEC)))
SPEC_DEPS       := $(wildcard $(LOCAL_SPEC) $(FALLBACK_SPEC))
PASSTHROUGH     := $(abspath $(CURDIR)/passthrough_exports.txt)
PASSTHROUGH_DEP := $(wildcard $(PASSTHROUGH))
GEN_C           := $(GEN_DIR)/shell32_exports.generated.c
GEN_DEF         := $(GEN_DIR)/shell32_exports.generated.def
REAL_OBJ_DIR    := $(GEN_DIR)/real
REAL_OBJS       := $(REAL_OBJ_DIR)/winemu_shellole.o \
                   $(REAL_OBJ_DIR)/winemu_shellpath.o
GEN_STAMP       := $(GEN_DIR)/.exports.stamp
OUT             := $(SYSROOT)/shell32.dll
IMAGE_BASE      := 0x72000000

all: $(OUT)

$(GEN_DIR):
	mkdir -p $@

$(REAL_OBJ_DIR):
	mkdir -p $@

$(GEN_STAMP): $(GEN_SCRIPT) $(SPEC_DEPS) $(PASSTHROUGH_DEP) | $(GEN_DIR)
	@[ -n "$(SPEC)" ] || { \
		echo "shell32.spec not found. Run: ./scripts/sync_wine_sources.sh"; \
		exit 1; \
	}
	python3 $(GEN_SCRIPT) \
		--module shell32 \
		--spec "$(SPEC)" \
		--out-c "$(GEN_C)" \
		--out-def "$(GEN_DEF)" \
		--passthrough "$(PASSTHROUGH)"
	@touch "$@"

$(GEN_C) $(GEN_DEF): $(GEN_STAMP)

$(REAL_OBJ_DIR)/winemu_shellole.o: winemu_shellole.c | $(REAL_OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(REAL_OBJ_DIR)/winemu_shellpath.o: winemu_shellpath.c | $(REAL_OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OUT): $(GEN_C) $(GEN_DEF) $(REAL_OBJS) | $(SYSROOT)
	rm -f "$@"
	$(CC) $(CFLAGS) -shared -o $@ $(GEN_C) $(GEN_DEF) $(REAL_OBJS) -lole32 -lkernel32 -luuid -Wl,--gc-sections -Wl,--image-base,$(IMAGE_BASE) -Wl,--out-implib,$(SYSROOT)/shell32.lib

.PHONY: all clean
clean:
	rm -f "$(OUT)" "$(SYSROOT)/shell32.lib"
	rm -rf "$(GEN_DIR)"
