// hello-kvm.c: the smallest complete KVM virtual machine, in C.
// A C port of ch01-hello-kvm/src/main.rs. Build: make. Run: make run.
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>
#include <linux/kvm.h>

#define RAM_BASE  0x80000000UL /* guest-physical address of guest RAM */
#define RAM_SIZE  0x10000UL    /* 64 KiB: a multiple of any page size */
#define UART_ADDR 0x09000000UL /* no RAM here, so stores trap to us */

// Register ids for KVM_SET_ONE_REG: arm64, 64 bits wide, "core" group,
// and the register's offset inside struct kvm_regs in 32-bit words.
#define CORE_REG(r) (KVM_REG_ARM64 | KVM_REG_SIZE_U64 | \
                     KVM_REG_ARM_CORE | KVM_REG_ARM_CORE_REG(regs.r))

static void die(const char *what)
{
    perror(what);
    exit(1);
}

// Every ioctl goes through here; #req turns the request name into text
// so an error says which step failed.
#define IOCTL(fd, req, arg) xioctl(fd, req, (unsigned long)(arg), #req)

static int xioctl(int fd, unsigned long req, unsigned long arg,
                  const char *name)
{
    int ret = ioctl(fd, req, arg);
    if (ret < 0)
        die(name);
    return ret;
}

static double now_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1e6 + ts.tv_nsec / 1e3;
}

static int open_kvm(void)
{
    int kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    if (kvm < 0)
        die("open /dev/kvm");
    int api = IOCTL(kvm, KVM_GET_API_VERSION, 0);
    if (api != KVM_API_VERSION) {
        fprintf(stderr, "KVM API version %d, need %d\n",
                api, KVM_API_VERSION);
        exit(1);
    }
    printf("[1] opened /dev/kvm, KVM API version %d\n", api);
    return kvm;
}

static int create_vm(int kvm)
{
    // The VM type on arm64 holds the guest-physical address size in bits.
    int ipa = IOCTL(kvm, KVM_CHECK_EXTENSION, KVM_CAP_ARM_VM_IPA_SIZE);
    int vm = IOCTL(kvm, KVM_CREATE_VM, KVM_VM_TYPE_ARM_IPA_SIZE(ipa));
    printf("[2] KVM_CREATE_VM -> fd %d (%d-bit guest physical addresses)\n",
           vm, ipa);
    return vm;
}

static void add_ram(int vm, const char *image)
{
    uint8_t *ram = mmap(NULL, RAM_SIZE, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (ram == MAP_FAILED)
        die("mmap guest RAM");

    FILE *f = fopen(image, "rb");
    if (f == NULL)
        die(image);
    size_t n = fread(ram, 1, RAM_SIZE, f);
    if (ferror(f))
        die(image);
    fclose(f);

    struct kvm_userspace_memory_region region = {
        .slot = 0,
        .guest_phys_addr = RAM_BASE,
        .memory_size = RAM_SIZE,
        .userspace_addr = (uint64_t)ram,
    };
    IOCTL(vm, KVM_SET_USER_MEMORY_REGION, &region);
    printf("[3] %lu KiB at host address %p is now guest RAM at %#lx\n",
           RAM_SIZE / 1024, (void *)ram, RAM_BASE);
    printf("    copied %zu bytes from %s to the start of it\n", n, image);
}

static void set_reg(int vcpu, uint64_t id, uint64_t value)
{
    struct kvm_one_reg reg = { .id = id, .addr = (uint64_t)&value };
    IOCTL(vcpu, KVM_SET_ONE_REG, &reg);
}

static void init_vcpu(int vm, int vcpu)
{
    struct kvm_vcpu_init init;
    memset(&init, 0, sizeof init);
    IOCTL(vm, KVM_ARM_PREFERRED_TARGET, &init);
    init.features[0] |= 1u << KVM_ARM_VCPU_PSCI_0_2; /* lets it power off */
    IOCTL(vcpu, KVM_ARM_VCPU_INIT, &init);

    // Start at kernel level (EL1) with all four interrupt kinds masked.
    // This is also what KVM_ARM_VCPU_INIT gives us; we say it out loud.
    set_reg(vcpu, CORE_REG(pstate),
            PSR_MODE_EL1h | PSR_D_BIT | PSR_A_BIT | PSR_I_BIT | PSR_F_BIT);
    set_reg(vcpu, CORE_REG(pc), RAM_BASE);
    printf("[5] vCPU initialised (target %u), PC = %#lx\n",
           init.target, RAM_BASE);
}

static void show_fds(void)
{
    char path[32], target[128];
    printf("    open file descriptors of this process:\n");
    for (int fd = 0; fd < 16; fd++) {
        snprintf(path, sizeof path, "/proc/self/fd/%d", fd);
        ssize_t n = readlink(path, target, sizeof target - 1);
        if (n < 0)
            continue;
        target[n] = '\0';
        printf("      fd %2d -> %s\n", fd, target);
    }
}

static long run_vcpu(int vcpu, struct kvm_run *run)
{
    for (long exits = 1;; exits++) {
        IOCTL(vcpu, KVM_RUN, 0);
        switch (run->exit_reason) {
        case KVM_EXIT_MMIO:
            if (run->mmio.is_write && run->mmio.phys_addr == UART_ADDR)
                fwrite(run->mmio.data, 1, run->mmio.len, stdout);
            else
                fprintf(stderr, "unexpected MMIO at %#llx\n",
                        (unsigned long long)run->mmio.phys_addr);
            break;
        case KVM_EXIT_SYSTEM_EVENT:
            fflush(stdout);
            printf("\n[7] guest requested %s via PSCI (system event %u)\n",
                   run->system_event.type == KVM_SYSTEM_EVENT_SHUTDOWN ?
                   "power off" : "other", run->system_event.type);
            return exits;
        default:
            fprintf(stderr, "unhandled exit reason %u\n", run->exit_reason);
            exit(1);
        }
    }
}

int main(int argc, char **argv)
{
    const char *image = argc > 1 ? argv[1] : "guest.bin";
    double t0 = now_us();

    int kvm = open_kvm();
    int vm = create_vm(kvm);
    add_ram(vm, image);

    int vcpu = IOCTL(vm, KVM_CREATE_VCPU, 0);
    int size = IOCTL(kvm, KVM_GET_VCPU_MMAP_SIZE, 0);
    struct kvm_run *run = mmap(NULL, size, PROT_READ | PROT_WRITE,
                               MAP_SHARED, vcpu, 0);
    if (run == MAP_FAILED)
        die("mmap kvm_run");
    printf("[4] KVM_CREATE_VCPU -> fd %d, shared kvm_run page of %d bytes\n",
           vcpu, size);

    init_vcpu(vm, vcpu);
    show_fds();

    printf("[6] running the guest:\n\n");
    double t1 = now_us();
    long exits = run_vcpu(vcpu, run);
    double t2 = now_us();
    printf("    %ld VM exits (%ld MMIO, 1 power off)\n", exits, exits - 1);
    printf("    setup %.0f us, guest run %.0f us (%.1f us per exit)\n",
           t1 - t0, t2 - t1, (t2 - t1) / exits);
    return 0; /* exiting closes the fds, and the kernel frees the VM */
}
