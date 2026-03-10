include ../common.mk

# Windows build number — controls which syscall number table is used.
# Override with: make WINDOWS_BUILD=26100
WINDOWS_BUILD ?= 22631

SYSCALL_NRS_H := src/syscall_nrs_$(WINDOWS_BUILD).h

OUT := $(SYSROOT)/ntdll.dll

$(OUT): ntdll.c $(SYSCALL_NRS_H) | $(SYSROOT)
	$(CC) $(CFLAGS) -include $(SYSCALL_NRS_H) -shared -o $@ ntdll.c -Wl,--out-implib,$(SYSROOT)/ntdll.lib

.PHONY: clean
clean:
	rm -f $(SYSROOT)/ntdll.dll $(SYSROOT)/ntdll.lib
