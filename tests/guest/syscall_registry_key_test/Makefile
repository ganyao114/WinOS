include ../common.mk

OUT := $(SYSROOT)/syscall_registry_key_test.exe

$(OUT): syscall_registry_key_test.c | $(SYSROOT)
	$(CC) $(CFLAGS) -nostartfiles -o $@ $< \
		-L$(SYSROOT) -lntdll \
		-Wl,-e,mainCRTStartup

.PHONY: clean
clean:
	rm -f $(OUT)
