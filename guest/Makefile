include common.mk

DLLS := ntdll
EXES := hello_win open_process_test process_test syscall_sysinfo_test syscall_process_token_test syscall_registry_key_test syscall_file_volume_test syscall_file_control_test syscall_directory_test syscall_directory_notify_test syscall_sync_test syscall_thread_vm_test syscall_section_open_test vm_rw_test

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
