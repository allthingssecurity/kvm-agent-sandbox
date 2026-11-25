// syscall-cost.c: how long does one plain system call take on this host?
// A yardstick for the VM exit cost that hello-kvm prints.
// Build and run: make
#include <stdio.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define N 1000000

int main(void)
{
    struct timespec a, b;
    clock_gettime(CLOCK_MONOTONIC, &a);
    for (int i = 0; i < N; i++)
        syscall(SYS_getppid); /* tiny call: the kernel just reads a field */
    clock_gettime(CLOCK_MONOTONIC, &b);
    double ns = (b.tv_sec - a.tv_sec) * 1e9 + (b.tv_nsec - a.tv_nsec);
    printf("%d getppid calls, %.0f ns per call\n", N, ns / N);
    return 0;
}
