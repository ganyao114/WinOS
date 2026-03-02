include ../common.mk

OUT := $(SYSROOT)/syscall_file_control_test.exe

$(OUT): syscall_file_control_test.c | $(SYSROOT)
	$(CC) $(CFLAGS) -nostartfiles -o $@ $< \
		-L$(SYSROOT) -lntdll \
		-Wl,-e,mainCRTStartup

.PHONY: clean
clean:
	rm -f $(OUT)
