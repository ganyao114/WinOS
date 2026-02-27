include ../common.mk

OUT := $(SYSROOT)/ntdll.dll

$(OUT): ntdll.c | $(SYSROOT)
	$(CC) $(CFLAGS) -shared -o $@ $< -Wl,--out-implib,$(SYSROOT)/ntdll.lib

.PHONY: clean
clean:
	rm -f $(SYSROOT)/ntdll.dll $(SYSROOT)/ntdll.lib
