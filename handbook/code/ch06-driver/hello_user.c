/* hello_user.c: talk to /dev/hello with write, read and ioctl. */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "hello_ioctl.h"

static void greet(int fd)
{
	char buf[128];
	ssize_t n = pread(fd, buf, sizeof(buf) - 1, 0);

	buf[n > 0 ? n : 0] = '\0';
	printf("read:  %s", buf);
}

int main(void)
{
	int fd = open("/dev/hello", O_RDWR);
	int count;

	if (fd < 0) {
		perror("open /dev/hello");
		return 1;
	}
	const char *msg = "hi from user space";
	write(fd, msg, strlen(msg));
	greet(fd);
	greet(fd);

	ioctl(fd, HELLO_GET_COUNT, &count);
	printf("ioctl: count = %d\n", count);
	ioctl(fd, HELLO_RESET);
	ioctl(fd, HELLO_GET_COUNT, &count);
	printf("ioctl: count after reset = %d\n", count);

	/* Hand the kernel bad pointers: it must refuse, not crash. */
	if (ioctl(fd, HELLO_GET_COUNT, (int *)16) < 0)
		printf("ioctl with pointer 16: %s\n", strerror(errno));
	if (write(fd, (char *)0xdead0000, 5) < 0)
		printf("write from 0xdead0000: %s\n", strerror(errno));
	if (ioctl(fd, 12345, 0) < 0)
		printf("ioctl 12345: %s\n", strerror(errno));
	close(fd);
	return 0;
}
