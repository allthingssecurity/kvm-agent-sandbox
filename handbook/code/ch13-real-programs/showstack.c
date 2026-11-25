/* Print what the loader (Linux's execve, or our VMM) left on the starting
 * stack: argc, argv, envp and the auxiliary vector. Built as a static PIE,
 * the same kind of file as Alpine's busybox. */
#include <stdio.h>
#include <sys/auxv.h>

int main(int argc, char **argv, char **envp)
{
    static const struct { unsigned long kind; const char *name; } aux[] = {
        { AT_PHDR, "AT_PHDR" },   { AT_PHENT, "AT_PHENT" },
        { AT_PHNUM, "AT_PHNUM" }, { AT_PAGESZ, "AT_PAGESZ" },
        { AT_ENTRY, "AT_ENTRY" }, { AT_UID, "AT_UID" },
        { AT_SECURE, "AT_SECURE" }, { AT_RANDOM, "AT_RANDOM" },
    };
    int nenv = 0;

    printf("argc      = %d\n", argc);
    for (int i = 0; i < argc; i++)
        printf("argv[%d]   = \"%s\"\n", i, argv[i]);
    while (envp[nenv])
        nenv++;
    printf("envp      = %d variables\n", nenv);
    for (unsigned i = 0; i < sizeof aux / sizeof aux[0]; i++)
        printf("%-9s = %#lx\n", aux[i].name, getauxval(aux[i].kind));
    printf("main      = %p\n", (void *)main);
    printf("stack     = %p\n", (void *)&argc);
    return 0;
}
