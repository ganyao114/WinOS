include ../common.mk

OUT := $(SYSROOT)/process_test.exe

$(OUT): process_test.c | $(SYSROOT)
	$(CC) $(CFLAGS) -nostartfiles -o $@ $< \
		-Wl,--image-base,0x70000000 \
		-Wl,-e,mainCRTStartup

.PHONY: clean
clean:
	rm -f $(OUT)
