/* overflow.c: a name field that is too small, next to a function pointer. */
#include <stdio.h>
#include <string.h>

struct greeter {
	char name[16];
	void (*greet)(void);	/* sits right after name in memory */
};

static void hello(void)
{
	puts("Hello, ordinary user.");
}

void secret(void)
{
	puts("secret(): you should never see this line.");
}

int main(int argc, char **argv)
{
	struct greeter g;

	g.greet = hello;
	if (argc > 1)
		strcpy(g.name, argv[1]);	/* the bug: no length check */
	printf("name is at %p, greet is at %p\n",
	       (void *)g.name, (void *)&g.greet);
	printf("greet points to %p\n", (void *)g.greet);
	fflush(stdout);			/* print before we maybe crash */
	g.greet();
	return 0;
}
