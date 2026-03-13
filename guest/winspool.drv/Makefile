include ../common.mk

ROOT            := $(abspath $(CURDIR)/../..)
PORT_DIR        := $(CURDIR)
GEN_DIR         := $(PORT_DIR)/generated
GEN_SCRIPT      := $(ROOT)/scripts/gen_pe_exports.py
WINE_SRC        ?= /Users/swift/wine-proton-macos
FALLBACK_SPEC   := $(WINE_SRC)/dlls/winspool.drv/winspool.drv.spec
SPEC            := $(firstword $(wildcard $(FALLBACK_SPEC)))
SPEC_DEPS       := $(wildcard $(FALLBACK_SPEC))
PASSTHROUGH     := $(abspath $(CURDIR)/passthrough_exports.txt)
PASSTHROUGH_DEP := $(wildcard $(PASSTHROUGH))
GEN_C           := $(GEN_DIR)/winspool_exports.generated.c
GEN_DEF         := $(GEN_DIR)/winspool_exports.generated.def
REAL_OBJ_DIR    := $(GEN_DIR)/real
REAL_OBJS       := $(REAL_OBJ_DIR)/bootstrap.o
GEN_STAMP       := $(GEN_DIR)/.exports.stamp
OUT             := $(SYSROOT)/winspool.drv
IMAGE_BASE      := 0x70c80000

all: $(OUT)

$(GEN_DIR):
	mkdir -p $@

$(REAL_OBJ_DIR):
	mkdir -p $@

$(GEN_STAMP): $(GEN_SCRIPT) $(SPEC_DEPS) $(PASSTHROUGH_DEP) | $(GEN_DIR)
	@[ -n "$(SPEC)" ] || { \
		echo "winspool.drv.spec not found. Run: ./scripts/sync_wine_sources.sh"; \
		exit 1; \
	}
	python3 $(GEN_SCRIPT) \
		--module winspool \
		--spec "$(SPEC)" \
		--out-c "$(GEN_C)" \
		--out-def "$(GEN_DEF)" \
		--no-dllmain \
		--passthrough "$(PASSTHROUGH)"
	printf '    __wine_unix_call_funcs DATA\n    __wine_unix_call_wow64_funcs DATA\n' >> "$(GEN_DEF)"
	@touch "$@"

$(GEN_C) $(GEN_DEF): $(GEN_STAMP)

$(REAL_OBJ_DIR)/bootstrap.o: bootstrap.c | $(REAL_OBJ_DIR)
	$(CC) $(CFLAGS) $(WINE_CFLAGS) -c $< -o $@

$(OUT): $(GEN_C) $(GEN_DEF) $(REAL_OBJS) | $(SYSROOT)
	rm -f "$@"
	$(CC) $(CFLAGS) $(WINE_CFLAGS) -shared -o $@ $(GEN_C) $(GEN_DEF) $(REAL_OBJS) -Wl,--gc-sections -Wl,--image-base,$(IMAGE_BASE) -Wl,--out-implib,$(SYSROOT)/winspool.lib

.PHONY: all clean
clean:
	rm -f "$(OUT)" "$(SYSROOT)/winspool.lib"
	rm -rf "$(GEN_DIR)"
