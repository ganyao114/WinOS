include ../common.mk

OUT := $(SYSROOT)/win32u.dll

$(OUT): win32u.c | $(SYSROOT)
	$(CC) $(CFLAGS) -shared -o $@ $< -Wl,--out-implib,$(SYSROOT)/win32u.lib

.PHONY: clean
clean:
	rm -f $(SYSROOT)/win32u.dll $(SYSROOT)/win32u.lib
