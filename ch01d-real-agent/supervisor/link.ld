ENTRY(_start)
/* Three segments, each on its own pages, so the VMM can map them W^X:
   code (read + execute), constants (read), data (read + write, never execute). */
PHDRS
{
    text   PT_LOAD FLAGS(5);
    rodata PT_LOAD FLAGS(4);
    data   PT_LOAD FLAGS(6);
}
SECTIONS
{
    . = 0x80000000;                       /* the vCPU starts here, at guest level 0 */
    .text   : { KEEP(*(.text.entry)) *(.text .text.*) } :text
    . = ALIGN(4096);
    .rodata : { *(.rodata .rodata.*) } :rodata
    . = ALIGN(4096);
    .data   : { *(.data .data.*) } :data
    .bss    : { *(.bss .bss.* COMMON) } :data   /* guest RAM starts zeroed, so .bss needs no loading */
    /DISCARD/ : { *(.eh_frame*) *(.comment) }
}
