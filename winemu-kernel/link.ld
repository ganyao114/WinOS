ENTRY(_start)

SECTIONS {
    . = 0x40000000;

    .text : {
        KEEP(*(.text.start))
        KEEP(*(.text.vectors))
        *(.text .text.*)
    }

    .rodata : { *(.rodata .rodata.*) }

    .data : { *(.data .data.*) }

    .bss (NOLOAD) : {
        __bss_start = .;
        *(.bss .bss.*)
        __bss_end = .;
    }

    . = ALIGN(4096);
    __kernel_end = .;

    /* 栈在镜像末尾之后，堆在栈之后 */
    __kernel_stack_bottom = .;
    __kernel_stack_top = . + 0x10000; /* 64KB stack */
    . = __kernel_stack_top;

    /* 独立 SVC 栈，每次 SVC 从栈顶重置，避免 SP_EL1 泄漏 */
    __kernel_svc_stack_bottom = .;
    __kernel_svc_stack_top = . + 0x4000; /* 16KB SVC stack */
    . = __kernel_svc_stack_top;

    /* Keep kernel image/stacks in low 2MB and start heap at 0x4020_0000
       so user allocations live in a separate MMU permission region. */
    . = 0x40200000;
    __heap_start = .;

    /DISCARD/ : {
        *(.eh_frame .eh_frame_hdr)
        *(.note .note.*)
        *(.comment)
    }
}
