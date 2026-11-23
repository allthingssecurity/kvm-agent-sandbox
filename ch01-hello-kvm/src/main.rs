//! Chapter 1: the smallest complete KVM virtual machine.
//!
//! No crates except `libc`, no guest kernel. We talk to KVM with raw ioctls so every step is visible:
//!
//!   open("/dev/kvm")           the one real device file
//!   KVM_CREATE_VM              -> a file descriptor for a VM (an anonymous inode, not a file on disk)
//!   mmap + SET_USER_MEMORY     -> ordinary process memory becomes guest RAM
//!   KVM_CREATE_VCPU            -> a file descriptor for a virtual CPU
//!   KVM_RUN in a loop          -> this thread runs guest code until the guest needs us ("VM exit")
//!
//! The guest (guest/guest.S) prints a string by storing bytes to an address with no RAM behind it.
//! Each store becomes a KVM_EXIT_MMIO that we handle here, then the guest powers off through PSCI.

use std::fs::{self, File};
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::time::Instant;

// ---------------------------------------------------------------------------------------------
// ioctl request numbers, built the same way as the _IO/_IOR/_IOW macros in <linux/ioctl.h>:
// direction (2 bits) | argument size (14 bits) | type (8 bits, 0xAE for KVM) | number (8 bits)
// ---------------------------------------------------------------------------------------------
const KVMIO: u64 = 0xAE;
const fn io(nr: u64) -> u64 { (KVMIO << 8) | nr }
const fn iow(nr: u64, size: u64) -> u64 { (1 << 30) | (size << 16) | (KVMIO << 8) | nr }
const fn ior(nr: u64, size: u64) -> u64 { (2 << 30) | (size << 16) | (KVMIO << 8) | nr }

const KVM_GET_API_VERSION: u64 = io(0x00);
const KVM_CREATE_VM: u64 = io(0x01);
const KVM_CHECK_EXTENSION: u64 = io(0x03);
const KVM_GET_VCPU_MMAP_SIZE: u64 = io(0x04);
const KVM_CREATE_VCPU: u64 = io(0x41);
const KVM_SET_USER_MEMORY_REGION: u64 = iow(0x46, size_of::<KvmUserspaceMemoryRegion>() as u64);
const KVM_RUN: u64 = io(0x80);
const KVM_SET_ONE_REG: u64 = iow(0xac, size_of::<KvmOneReg>() as u64);
const KVM_ARM_VCPU_INIT: u64 = iow(0xae, size_of::<KvmVcpuInit>() as u64);
const KVM_ARM_PREFERRED_TARGET: u64 = ior(0xaf, size_of::<KvmVcpuInit>() as u64);

const KVM_CAP_ARM_VM_IPA_SIZE: u64 = 165; // how many bits of guest-physical address the host supports
const KVM_ARM_VCPU_PSCI_0_2: u32 = 2; // vCPU feature bit: let the guest call PSCI (power off, CPU on, ...)

// Why KVM_RUN returned (the subset this chapter handles).
const KVM_EXIT_MMIO: u32 = 6;
const KVM_EXIT_FAIL_ENTRY: u32 = 9;
const KVM_EXIT_INTERNAL_ERROR: u32 = 17;
const KVM_EXIT_SYSTEM_EVENT: u32 = 24;
const KVM_SYSTEM_EVENT_SHUTDOWN: u32 = 1;

// Register id for the program counter, for KVM_SET_ONE_REG:
// ARM64 | 64-bit register | "core" register group | offset of `pc` in struct kvm_regs, in 32-bit words.
// struct kvm_regs starts with x0..x30 then sp, then pc: (31 + 1) * 8 bytes = 256 bytes = word 64.
const KVM_REG_ARM64: u64 = 0x6000_0000_0000_0000;
const KVM_REG_SIZE_U64: u64 = 0x0030_0000_0000_0000;
const KVM_REG_ARM_CORE: u64 = 0x0010 << 16;
const REG_PC: u64 = KVM_REG_ARM64 | KVM_REG_SIZE_U64 | KVM_REG_ARM_CORE | (256 / 4);

// ---------------------------------------------------------------------------------------------
// The guest-physical memory map of our tiny machine.
// ---------------------------------------------------------------------------------------------
const RAM_BASE: u64 = 0x8000_0000; // guest RAM starts here (same as Firecracker's arm64 layout)
const RAM_SIZE: usize = 64 * 1024; // 64 KiB is plenty for 100 bytes of code
const UART_ADDR: u64 = 0x0900_0000; // nothing is mapped here, so guest stores trap to us

/// The guest program from guest/guest.S, assembled with `clang -target arm64-none-elf`.
/// Code first, then the string it prints (the `adr` at offset 0 points 0x28 bytes ahead).
const GUEST_CODE: [u32; 10] = [
    0x1000_0142, // adr   x2, msg
    0xd2a1_2000, // movz  x0, #0x0900, lsl #16     ; x0 = UART_ADDR
    0x3840_1441, // ldrb  w1, [x2], #1             ; next byte of the string
    0x3400_0061, // cbz   w1, done
    0x3900_0001, // strb  w1, [x0]                 ; MMIO store -> KVM_EXIT_MMIO
    0x17ff_fffd, // b     loop
    0x5280_0100, // movz  w0, #0x0008              ; done: w0 = 0x8400_0008, PSCI SYSTEM_OFF
    0x72b0_8000, // movk  w0, #0x8400, lsl #16
    0xd400_0002, // hvc   #0                       ; -> KVM_EXIT_SYSTEM_EVENT
    0x1400_0000, // b     .
];
const GUEST_MSG: &[u8] = b"Hello from the guest! Every character you see was a VM exit.\n\0";

// ---------------------------------------------------------------------------------------------
// The structs passed to ioctls, laid out exactly as in <linux/kvm.h>.
// ---------------------------------------------------------------------------------------------
#[repr(C)]
struct KvmUserspaceMemoryRegion {
    slot: u32,
    flags: u32,
    guest_phys_addr: u64,
    memory_size: u64,
    userspace_addr: u64, // where this memory lives in *our* process
}

#[repr(C)]
#[derive(Default)]
struct KvmVcpuInit {
    target: u32,
    features: [u32; 7],
}

#[repr(C)]
struct KvmOneReg {
    id: u64,
    addr: u64, // pointer to the value in our memory
}

/// The start of `struct kvm_run`, the page KVM shares with us for each vCPU. KVM writes the reason for
/// every exit here, and for MMIO the address, the data and its size.
#[repr(C)]
struct KvmRun {
    request_interrupt_window: u8,
    immediate_exit: u8,
    padding1: [u8; 6],
    exit_reason: u32,
    ready_for_interrupt_injection: u8,
    if_flag: u8,
    flags: u16,
    cr8: u64,
    apic_base: u64,
    exit: ExitUnion, // which member is valid depends on exit_reason
}

#[repr(C)]
union ExitUnion {
    mmio: MmioExit,
    system_event: SystemEventExit,
    padding: [u8; 256],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct MmioExit {
    phys_addr: u64,
    data: [u8; 8],
    len: u32,
    is_write: u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SystemEventExit {
    kind: u32,
    ndata: u32,
}

// ---------------------------------------------------------------------------------------------

/// One ioctl, with the kernel's error turned into a Rust error.
fn ioctl(fd: RawFd, request: u64, arg: u64) -> io::Result<i32> {
    // `as _` because the request type differs between libc implementations (musl: int, glibc: ulong).
    let ret = unsafe { libc::ioctl(fd, request as _, arg) };
    if ret < 0 { Err(io::Error::last_os_error()) } else { Ok(ret) }
}

/// ioctls that create a KVM object return a new file descriptor. Owning it means it is closed
/// (and the object freed by the kernel) when it goes out of scope.
fn ioctl_fd(fd: RawFd, request: u64, arg: u64) -> io::Result<OwnedFd> {
    let new_fd = ioctl(fd, request, arg)?;
    Ok(unsafe { OwnedFd::from_raw_fd(new_fd) })
}

/// Anonymous shared memory: plain process memory that we will lend to the guest.
fn mmap(len: usize, fd: RawFd, flags: i32) -> io::Result<*mut u8> {
    let p = unsafe { libc::mmap(std::ptr::null_mut(), len, libc::PROT_READ | libc::PROT_WRITE, flags, fd, 0) };
    if p == libc::MAP_FAILED { Err(io::Error::last_os_error()) } else { Ok(p.cast()) }
}

/// Print this process's open file descriptors, to show what the KVM objects really are.
fn show_fds() {
    println!("    open file descriptors of this process (/proc/self/fd):");
    let mut entries: Vec<_> = fs::read_dir("/proc/self/fd").unwrap().flatten().collect();
    entries.sort_by_key(|e| e.file_name().to_string_lossy().parse::<u32>().unwrap_or(0));
    for e in entries {
        if let Ok(target) = fs::read_link(e.path()) {
            println!("      fd {:>2} -> {}", e.file_name().to_string_lossy(), target.display());
        }
    }
}

fn main() -> io::Result<()> {
    let t0 = Instant::now();

    // 1. The one real device file. Everything else comes from ioctls on it.
    let kvm = File::options().read(true).write(true).open("/dev/kvm")?;
    let api = ioctl(kvm.as_raw_fd(), KVM_GET_API_VERSION, 0)?;
    println!("[1] opened /dev/kvm, KVM API version {api}");

    // 2. Create a VM. The argument is the guest-physical address size: use what this host supports.
    let ipa_bits = ioctl(kvm.as_raw_fd(), KVM_CHECK_EXTENSION, KVM_CAP_ARM_VM_IPA_SIZE)?;
    let vm = ioctl_fd(kvm.as_raw_fd(), KVM_CREATE_VM, ipa_bits as u64)?;
    println!("[2] KVM_CREATE_VM -> fd {} ({ipa_bits}-bit guest physical addresses)", vm.as_raw_fd());

    // 3. Guest RAM is ordinary memory in this process. Copy the program in, then tell KVM
    //    "guest-physical RAM_BASE .. RAM_BASE+RAM_SIZE is backed by this memory".
    let ram = mmap(RAM_SIZE, -1, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE)?;
    unsafe {
        let code: Vec<u8> = GUEST_CODE.iter().flat_map(|w| w.to_le_bytes()).collect();
        std::ptr::copy_nonoverlapping(code.as_ptr(), ram, code.len());
        std::ptr::copy_nonoverlapping(GUEST_MSG.as_ptr(), ram.add(code.len()), GUEST_MSG.len());
    }
    let region = KvmUserspaceMemoryRegion {
        slot: 0,
        flags: 0,
        guest_phys_addr: RAM_BASE,
        memory_size: RAM_SIZE as u64,
        userspace_addr: ram as u64,
    };
    ioctl(vm.as_raw_fd(), KVM_SET_USER_MEMORY_REGION, &region as *const _ as u64)?;
    println!("[3] {} KiB at host address {:p} is now guest RAM at {RAM_BASE:#x}", RAM_SIZE / 1024, ram);

    // 4. Create vCPU 0 and map its shared `kvm_run` page, where KVM reports each exit.
    let vcpu = ioctl_fd(vm.as_raw_fd(), KVM_CREATE_VCPU, 0)?;
    let run_size = ioctl(kvm.as_raw_fd(), KVM_GET_VCPU_MMAP_SIZE, 0)? as usize;
    let run = mmap(run_size, vcpu.as_raw_fd(), libc::MAP_SHARED)? as *mut KvmRun;
    println!("[4] KVM_CREATE_VCPU -> fd {}, shared kvm_run page of {run_size} bytes", vcpu.as_raw_fd());

    // 5. Initialise the vCPU as the host's preferred CPU model, with PSCI so the guest can power off.
    //    It starts in EL1 with the MMU off and interrupts masked. Then point its PC at our code.
    let mut init = KvmVcpuInit::default();
    ioctl(vm.as_raw_fd(), KVM_ARM_PREFERRED_TARGET, &mut init as *mut _ as u64)?;
    init.features[0] |= 1 << KVM_ARM_VCPU_PSCI_0_2;
    ioctl(vcpu.as_raw_fd(), KVM_ARM_VCPU_INIT, &init as *const _ as u64)?;
    let pc: u64 = RAM_BASE;
    let reg = KvmOneReg { id: REG_PC, addr: &pc as *const _ as u64 };
    ioctl(vcpu.as_raw_fd(), KVM_SET_ONE_REG, &reg as *const _ as u64)?;
    println!("[5] vCPU initialised (target {}), PC = {pc:#x}", init.target);
    show_fds();
    let setup = t0.elapsed();

    // 6. Run. Each KVM_RUN executes guest instructions on the real CPU, on this thread, until the
    //    guest does something KVM cannot finish on its own. Then we handle it and run again.
    println!("[6] running the guest:\n");
    let (mut exits, mut mmio_exits) = (0u64, 0u64);
    let t_run = Instant::now();
    let mut out = io::stdout().lock();
    loop {
        ioctl(vcpu.as_raw_fd(), KVM_RUN, 0)?;
        exits += 1;
        let run = unsafe { &*run };
        match run.exit_reason {
            KVM_EXIT_MMIO => {
                mmio_exits += 1;
                let mmio = unsafe { run.exit.mmio };
                if mmio.is_write == 1 && mmio.phys_addr == UART_ADDR {
                    out.write_all(&mmio.data[..mmio.len as usize])?; // our whole "UART device"
                } else {
                    eprintln!("unexpected MMIO at {:#x} (write={})", mmio.phys_addr, mmio.is_write);
                }
            }
            KVM_EXIT_SYSTEM_EVENT => {
                let ev = unsafe { run.exit.system_event };
                let what = if ev.kind == KVM_SYSTEM_EVENT_SHUTDOWN { "power off" } else { "other" };
                out.flush()?;
                println!("\n[7] guest requested {what} via PSCI (system event {})", ev.kind);
                break;
            }
            KVM_EXIT_FAIL_ENTRY | KVM_EXIT_INTERNAL_ERROR => {
                return Err(io::Error::other(format!("KVM could not run the guest (exit {})", run.exit_reason)));
            }
            other => return Err(io::Error::other(format!("unhandled exit reason {other}"))),
        }
    }
    let ran = t_run.elapsed();

    println!(
        "    {exits} VM exits ({mmio_exits} MMIO, 1 power off)\n    \
         setup {:.0} us, guest run {:.0} us ({:.1} us per exit), total {:.0} us",
        setup.as_secs_f64() * 1e6,
        ran.as_secs_f64() * 1e6,
        ran.as_secs_f64() * 1e6 / exits as f64,
        t0.elapsed().as_secs_f64() * 1e6
    );
    // Dropping `vcpu`, `vm` and `kvm` closes the fds: the kernel frees the VM. Nothing is left behind.
    Ok(())
}
