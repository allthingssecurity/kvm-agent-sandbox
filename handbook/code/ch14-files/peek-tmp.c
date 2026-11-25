/* Write a file to /tmp, then try to read /tmp's memory directly.
 * In the sandbox, /tmp's data lives at 0x88000000, in pages that only
 * the supervisor (EL1) may touch. The program sees it only through
 * read(). */
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int main(void)
{
    char buf[32] = { 0 };
    int fd = open("/tmp/secret", O_CREAT | O_RDWR, 0600);

    write(fd, "hello from /tmp", 15);
    lseek(fd, 0, SEEK_SET);
    read(fd, buf, sizeof buf - 1);
    printf("through read(): \"%s\"\n", buf);
    fflush(stdout);

    volatile char *raw = (volatile char *)0x88000000;
    printf("directly: \"%c\"\n", raw[0]);
    return 0;
}
