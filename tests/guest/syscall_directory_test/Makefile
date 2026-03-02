include ../common.mk

OUT := $(SYSROOT)/syscall_directory_test.exe

$(OUT): syscall_directory_test.c | $(SYSROOT)
	$(CC) $(CFLAGS) -nostartfiles -o $@ $< \
		-L$(SYSROOT) -lntdll \
		-Wl,-e,mainCRTStartup

.PHONY: clean
clean:
	rm -f $(OUT)
