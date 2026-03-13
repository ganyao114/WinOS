include ../common.mk

OUT := $(SYSROOT)/com_wbem_test.exe

$(OUT): com_wbem_test.c | $(SYSROOT)
	$(CC) $(CFLAGS) -nostartfiles -o $@ $< \
		-lole32 -loleaut32 -luuid -lntdll \
		-Wl,--image-base,0x70000000 \
		-Wl,-e,mainCRTStartup

.PHONY: clean
clean:
	rm -f $(OUT)
