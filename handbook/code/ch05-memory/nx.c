/* nx.c: put machine code in a writable buffer and try to run it. */
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#if defined(__aarch64__)
/* mov w0, #42 ; ret */
static const unsigned char code[] = {
	0x40, 0x05, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6 };
#elif defined(__x86_64__)
/* mov eax, 42 ; ret */
static const unsigned char code[] = { 0xb8, 0x2a, 0, 0, 0, 0xc3 };
#endif

typedef int (*fn)(void);

int main(int argc, char **argv)
{
	long page = sysconf(_SC_PAGESIZE);

	if (argc > 1 && strcmp(argv[1], "mprotect") == 0) {
		/* Ask the kernel for a page, fill it, then make it R+X. */
		unsigned char *p = mmap(NULL, page, PROT_READ | PROT_WRITE,
					MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		memcpy(p, code, sizeof code);
		mprotect(p, page, PROT_READ | PROT_EXEC);
		__builtin___clear_cache((char *)p, (char *)p + sizeof code);
		printf("page %p is now r-x, calling it\n", (void *)p);
		printf("it returned %d\n", ((fn)p)());
		return 0;
	}

	unsigned char buf[64];		/* on the stack: read + write only */
	memcpy(buf, code, sizeof code);
	__builtin___clear_cache((char *)buf, (char *)buf + sizeof code);
	printf("stack buffer %p holds code, calling it\n", (void *)buf);
	fflush(stdout);
	printf("it returned %d\n", ((fn)buf)());
	return 0;
}
