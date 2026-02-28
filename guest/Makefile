include common.mk

DLLS := ntdll
EXES := hello_win process_test syscall_sysinfo_test vm_rw_test

.PHONY: all clean $(DLLS) $(EXES)

all: $(DLLS) $(EXES)

$(DLLS): | $(SYSROOT)
	$(MAKE) -C $@ SYSROOT=$(SYSROOT)

# EXEs depend on DLLs being built first
$(EXES): $(DLLS) | $(SYSROOT)
	$(MAKE) -C $@ SYSROOT=$(SYSROOT)

$(SYSROOT):
	mkdir -p $(SYSROOT)

clean:
	for d in $(DLLS) $(EXES); do $(MAKE) -C $$d clean SYSROOT=$(SYSROOT); done
	rm -rf $(SYSROOT)
