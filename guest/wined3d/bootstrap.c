/*
 * Force a base relocation into the stub DLL so the guest loader can place
 * it at an alternate VA when the preferred image base is occupied.
 */

__attribute__((used))
void *winemu_force_reloc_anchor = &winemu_force_reloc_anchor;
