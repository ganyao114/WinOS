include ../common.mk

OUT := $(SYSROOT)/process_test.exe

$(OUT): process_test.c | $(SYSROOT)
	$(CC) $(CFLAGS) -nostartfiles -o $@ $< \
		-Wl,-e,mainCRTStartup

.PHONY: clean
clean:
	rm -f $(OUT)
