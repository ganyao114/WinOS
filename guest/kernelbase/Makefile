include ../common.mk

# Keep wine-provided kernelbase.dll symlink intact by default.
# To produce a drop-in replacement, invoke:
#   make -C guest/kernelbase OUT=$(SYSROOT)/kernelbase.dll
OUT ?= $(SYSROOT)/kernelbase.winemu.dll

$(OUT): kernelbase.c | $(SYSROOT)
	$(CC) $(CFLAGS) -shared -o $@ $<

.PHONY: clean
clean:
	rm -f $(SYSROOT)/kernelbase.winemu.dll
