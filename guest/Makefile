include common.mk

DLLS := ntdll win32u msvcrt
TEST_EXE_DIR := ../tests/guest
EXES := \
	$(TEST_EXE_DIR)/hello_win \
	$(TEST_EXE_DIR)/open_process_test \
	$(TEST_EXE_DIR)/process_test \
	$(TEST_EXE_DIR)/syscall_sysinfo_test \
	$(TEST_EXE_DIR)/syscall_process_token_test \
	$(TEST_EXE_DIR)/syscall_registry_key_test \
	$(TEST_EXE_DIR)/syscall_file_volume_test \
	$(TEST_EXE_DIR)/syscall_file_control_test \
	$(TEST_EXE_DIR)/syscall_directory_test \
	$(TEST_EXE_DIR)/syscall_directory_notify_test \
	$(TEST_EXE_DIR)/syscall_sync_test \
	$(TEST_EXE_DIR)/syscall_thread_vm_test \
	$(TEST_EXE_DIR)/syscall_section_open_test \
	$(TEST_EXE_DIR)/vm_rw_test

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
