include ../common.mk

OUT := $(SYSROOT)/syscall_sysinfo_test.exe

$(OUT): syscall_sysinfo_test.c | $(SYSROOT)
	$(CC) $(CFLAGS) -nostartfiles -o $@ $< \
		-Wl,-e,mainCRTStartup

.PHONY: clean
clean:
	rm -f $(OUT)
