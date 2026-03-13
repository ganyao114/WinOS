include ../common.mk

OUT := $(SYSROOT)/fastprox.dll
IMAGE_BASE := 0x72300000

all: $(OUT)

$(OUT): fastprox.c fastprox.def | $(SYSROOT)
	rm -f "$@"
	$(CC) $(CFLAGS) -shared -o $@ fastprox.c fastprox.def \
		-lole32 -loleaut32 -luuid -lkernel32 \
		-Wl,--gc-sections \
		-Wl,--image-base,$(IMAGE_BASE) \
		-Wl,--out-implib,$(SYSROOT)/fastprox.lib

.PHONY: all clean
clean:
	rm -f "$(OUT)" "$(SYSROOT)/fastprox.lib"
