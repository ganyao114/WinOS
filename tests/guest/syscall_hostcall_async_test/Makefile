include ../common.mk

OUT := $(SYSROOT)/syscall_hostcall_async_test.exe

$(OUT): syscall_hostcall_async_test.c | $(SYSROOT)
	$(CC) $(CFLAGS) -nostartfiles -o $@ $< \
		-L$(SYSROOT) -lntdll \
		-Wl,-e,mainCRTStartup

.PHONY: clean
clean:
	rm -f $(OUT)
