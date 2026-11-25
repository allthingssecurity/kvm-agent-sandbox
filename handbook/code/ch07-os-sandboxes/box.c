/* box.c: a tiny container. New namespaces, then a seccomp filter.
 * Usage: ./box command [args...]     (runs as a normal user) */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

int install_filter(void);		/* in filter.c */

static int sync_pipe[2];
static char child_stack[1 << 16];

static void die(const char *what)
{
	perror(what);
	exit(1);
}

static void write_file(const char *path, const char *text)
{
	int fd = open(path, O_WRONLY);

	if (fd < 0 || write(fd, text, strlen(text)) < 0)
		die(path);
	close(fd);
}

static void try_socket(const char *when)
{
	int fd = socket(AF_INET, SOCK_STREAM, 0);

	if (fd < 0)
		printf("box: socket() %s: %s\n", when, strerror(errno));
	else
		printf("box: socket() %s: fd %d\n", when, fd);
	if (fd >= 0)
		close(fd);
}

static int child(void *arg)
{
	char **argv = arg;
	char c;

	/* Wait until the parent has written our uid/gid maps. */
	close(sync_pipe[1]);
	if (read(sync_pipe[0], &c, 1) != 0)
		die("sync");

	if (sethostname("box", 3) < 0)
		die("sethostname");
	/* Keep our mounts to ourselves, then mount a /proc that
	 * shows only the processes in our new PID namespace. */
	if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0)
		die("mount private");
	if (mount("proc", "/proc", "proc", 0, NULL) < 0)
		die("mount proc");

	printf("box: pid %d, uid %d\n", getpid(), getuid());
	try_socket("before filter");
	if (install_filter() < 0)
		die("seccomp");
	try_socket("after filter");

	fflush(stdout);
	execvp(argv[0], argv);
	die("execvp");
	return 1;
}

int main(int argc, char **argv)
{
	int flags = CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID |
		    CLONE_NEWUTS | CLONE_NEWNET | SIGCHLD;
	char map[64];
	int status;

	if (argc < 2) {
		fprintf(stderr, "usage: %s command [args...]\n", argv[0]);
		return 2;
	}
	if (pipe(sync_pipe) < 0)
		die("pipe");

	pid_t pid = clone(child, child_stack + sizeof(child_stack),
			  flags, argv + 1);
	if (pid < 0)
		die("clone");

	/* Map root inside the box to our own user outside it. */
	snprintf(map, sizeof(map), "/proc/%d/uid_map", pid);
	char line[32];
	snprintf(line, sizeof(line), "0 %d 1\n", getuid());
	write_file(map, line);
	snprintf(map, sizeof(map), "/proc/%d/setgroups", pid);
	write_file(map, "deny");
	snprintf(map, sizeof(map), "/proc/%d/gid_map", pid);
	snprintf(line, sizeof(line), "0 %d 1\n", getgid());
	write_file(map, line);
	close(sync_pipe[1]);		/* tells the child to go on */

	if (waitpid(pid, &status, 0) < 0)
		die("waitpid");
	printf("box: child exited with %d\n", WEXITSTATUS(status));
	return 0;
}
