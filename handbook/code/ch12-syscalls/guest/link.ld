/* Guest physical memory map (identity-mapped: guest virtual = guest physical).
 * Must match the page-table regions built in src/main.rs. */
SECTIONS
{
    . = 0x80000000;  .sup   : { *(.text.sup) }     /* supervisor code + data   EL1 only        */
    . = 0x80010000;  .agent : { *(.text.agent) }   /* agent code + strings     EL0 read+exec   */
}
