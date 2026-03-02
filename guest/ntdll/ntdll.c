/*
 * Minimal ntdll.dll stub for WinEmu (ARM64)
 * Compiled with aarch64-w64-mingw32-gcc from llvm-mingw
 *
 * NOTE: implementation is split by responsibility under src/ while still
 * compiled as a single translation unit to keep symbol/ABI behavior stable.
 */

#include "src/preamble.c"
#include "src/process.c"
#include "src/teb.c"
#include "src/fls.c"
#include "src/virtual_memory.c"
#include "src/heap.c"
#include "src/global_local.c"
#include "src/sync.c"
#include "src/rtl_string.c"
#include "src/crt.c"
#include "src/misc.c"
#include "src/loader.c"
#include "src/file.c"
#include "src/section_thread.c"
#include "src/registry.c"
#include "src/exception.c"
#include "src/startup.c"

#include "ntdll_missing_exports.generated.h"

#include "src/dllmain.c"
