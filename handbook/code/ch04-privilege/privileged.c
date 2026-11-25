/* privileged.c: try three things only the kernel may do, from user level.
 * Usage: ./privileged sysreg | irqoff | kmem
 * arm64 only. Each one should kill the program with a signal. */
#include <stdio.h>
#include <string.h>

#ifndef __aarch64__
#error "this demo is arm64 code; see the x86 notes in chapter 4"
#endif

int main(int argc, char **argv)
{
    const char *what = argc > 1 ? argv[1] : "sysreg";
    unsigned long v = 0;

    printf("trying: %s\n", what);
    fflush(stdout);              /* print before we die */

    if (strcmp(what, "sysreg") == 0) {
        /* Read the kernel's main control register (MMU on/off etc.). */
        asm volatile("mrs %0, sctlr_el1" : "=r"(v));
    } else if (strcmp(what, "irqoff") == 0) {
        /* Mask interrupts: set the I bit in DAIF. */
        asm volatile("msr daifset, #2");
    } else if (strcmp(what, "kmem") == 0) {
        /* Read an address in the kernel's half of the address space. */
        v = *(volatile unsigned long *)0xffff800080000000UL;
    }

    printf("still alive, v = %#lx\n", v);
    return 0;
}
