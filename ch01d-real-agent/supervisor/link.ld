ENTRY(_start)
SECTIONS
{
    . = 0x80000000;                       /* the vCPU starts here, at guest level 0 */
    .text   : { KEEP(*(.text.entry)) *(.text .text.*) }
    .rodata : { *(.rodata .rodata.*) }
    .data   : { *(.data .data.*) }
    .bss    : { *(.bss .bss.* COMMON) }   /* guest RAM starts zeroed, so .bss needs no loading */
    /DISCARD/ : { *(.eh_frame*) *(.comment) }
}
