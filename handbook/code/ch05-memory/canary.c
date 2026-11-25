/* canary.c: a classic stack buffer overflow, caught by the canary. */
#include <stdio.h>
#include <string.h>

static void copy_name(const char *src)
{
	char buf[16];

	strcpy(buf, src);	/* the bug: no length check */
	printf("hello, %s\n", buf);
}

int main(int argc, char **argv)
{
	copy_name(argc > 1 ? argv[1] : "world");
	puts("back in main");
	return 0;
}
