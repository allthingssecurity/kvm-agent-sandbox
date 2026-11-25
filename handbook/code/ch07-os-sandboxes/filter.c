/* filter.c: a classic-BPF seccomp filter that refuses socket(). */
#include <errno.h>
#include <stddef.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#if defined(__aarch64__)
#define MY_ARCH AUDIT_ARCH_AARCH64
#elif defined(__x86_64__)
#define MY_ARCH AUDIT_ARCH_X86_64
#endif

#define LOAD(field) BPF_STMT(BPF_LD | BPF_W | BPF_ABS, \
		offsetof(struct seccomp_data, field))
#define RET(val)    BPF_STMT(BPF_RET | BPF_K, (val))

int install_filter(void)
{
	struct sock_filter prog[] = {
		/* Wrong architecture? Kill: the numbers would mean
		 * different system calls. */
		LOAD(arch),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, MY_ARCH, 1, 0),
		RET(SECCOMP_RET_KILL_PROCESS),
		/* socket() fails with EPERM, everything else is allowed. */
		LOAD(nr),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_socket, 0, 1),
		RET(SECCOMP_RET_ERRNO | EPERM),
		RET(SECCOMP_RET_ALLOW),
	};
	struct sock_fprog fprog = {
		.len = sizeof(prog) / sizeof(prog[0]),
		.filter = prog,
	};

	/* Required for unprivileged filters: we can never gain
	 * privileges later (no setuid binaries) to escape it. */
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
		return -1;
	return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &fprog);
}
