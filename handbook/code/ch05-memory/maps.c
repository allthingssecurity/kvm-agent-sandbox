/* maps.c: print where things live, then the process's own memory map. */
#include <stdio.h>
#include <stdlib.h>

int global = 42;

int main(void)
{
	int local = 7;
	int *heap = malloc(4096);

	printf("code  (main)   %p\n", (void *)main);
	printf("data  (global) %p\n", (void *)&global);
	printf("heap  (malloc) %p\n", (void *)heap);
	printf("stack (local)  %p\n", (void *)&local);
	fflush(stdout);

	/* The kernel describes our address space in this text file. */
	FILE *f = fopen("/proc/self/maps", "r");
	char line[256];
	while (f && fgets(line, sizeof line, f))
		fputs(line, stdout);
	free(heap);
	return 0;
}
