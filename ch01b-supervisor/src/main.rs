//! Chapter 1b: a Dune-style supervisor inside a KVM guest.
//!
//! Where everything runs:
//!
//!                    REAL mode (host)               GUEST mode
//!     level 0        KVM, inside host Linux         supervisor (guest/supervisor.S)
//!     level 3        this program (the VMM)         agent code (guest/agent.S)
//!
//! The VMM's jobs: create the VM as in chapter 1, load the guest, prepare the supervisor's page tables
//! (which memory is "level 0 only" and which the agent may use), answer the supervisor's doorbell
//! (the only way out of guest mode), and at the end read the supervisor's notebook (audit log)
//! straight out of guest memory.

use std::fs::File;
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::time::Instant;

// ------------------------------- KVM ioctls (same as chapter 1) -------------------------------
const KVMIO: u64 = 0xAE;
const fn io(nr: u64) -> u64 { (KVMIO << 8) | nr }
const fn iow(nr: u64, size: u64) -> u64 { (1 << 30) | (size << 16) | (KVMIO << 8) | nr }
const fn ior(nr: u64, size: u64) -> u64 { (2 << 30) | (size << 16) | (KVMIO << 8) | nr }

const KVM_CREATE_VM: u64 = io(0x01);
const KVM_CHECK_EXTENSION: u64 = io(0x03);
const KVM_GET_VCPU_MMAP_SIZE: u64 = io(0x04);
const KVM_CREATE_VCPU: u64 = io(0x41);
const KVM_SET_USER_MEMORY_REGION: u64 = iow(0x46, 32);
const KVM_RUN: u64 = io(0x80);
const KVM_SET_ONE_REG: u64 = iow(0xac, 16);
const KVM_ARM_VCPU_INIT: u64 = iow(0xae, 32);
const KVM_ARM_PREFERRED_TARGET: u64 = ior(0xaf, 32);
const KVM_CAP_ARM_VM_IPA_SIZE: u64 = 165;
const KVM_EXIT_MMIO: u32 = 6;
const KVM_EXIT_INTERNAL_ERROR: u32 = 17;
const REG_PC: u64 = 0x6030_0000_0010_0000 | (256 / 4);

// ------------------------------- Guest memory map ---------------------------------------------
// Must match guest/link.ld and the constants at the top of guest/supervisor.S.
const RAM_BASE: u64 = 0x8000_0000;
const RAM_SIZE: usize = 1 << 20; // 1 MiB
const HC_PAGE: u64 = 0x8004_0000; // doorbell request/result page
const PT_BASE: u64 = 0x8005_0000; // page tables (4 pages)
const LOG_BASE: u64 = 0x8007_0000; // supervisor's notebook
const DOORBELL: u64 = 0x0900_0000; // no memory here: a store exits to us

/// Who may use each region. The supervisor installs these tables; the CPU enforces them.
/// (offset from RAM_BASE, size, permissions, what it is)
const REGIONS: &[(u64, u64, u64, &str)] = &[
    (0x00000, 0x10000, EL1_ONLY_EXEC, "supervisor code + data"),
    (0x10000, 0x10000, ALL_READ_EXEC_EL0, "agent code + strings"),
    (0x20000, 0x10000, ALL_READ_WRITE, "agent data + stack"),
    (0x30000, 0x01000, ALL_READ_ONLY, "read-only page (attack 4)"),
    (0x40000, 0x01000, EL1_ONLY_DATA, "doorbell request page"),
    (0x50000, 0x04000, EL1_ONLY_DATA, "page tables"),
    (0x60000, 0x20000, EL1_ONLY_DATA, "supervisor stack + notebook"),
];

// ARMv8 page-table entry bits (4 KiB pages).
const TABLE: u64 = 0b11; // points to the next-level table
const PAGE: u64 = 0b11; // last level: a 4 KiB page
const BLOCK: u64 = 0b01; // a 2 MiB block
const NORMAL: u64 = 0 << 2; // memory attribute 0: normal memory
const DEVICE: u64 = 1 << 2; // memory attribute 1: device
const INNER_SHAREABLE: u64 = 3 << 8;
const ACCESSED: u64 = 1 << 10;
const EL0_ALLOWED: u64 = 1 << 6; // AP[1]: level 3 may access
const READ_ONLY: u64 = 1 << 7; // AP[2]
const NO_EXEC_EL1: u64 = 1 << 53; // PXN
const NO_EXEC_EL0: u64 = 1 << 54; // UXN
const EL1_ONLY_EXEC: u64 = NO_EXEC_EL0;
const EL1_ONLY_DATA: u64 = NO_EXEC_EL0 | NO_EXEC_EL1;
const ALL_READ_EXEC_EL0: u64 = EL0_ALLOWED | READ_ONLY | NO_EXEC_EL1;
const ALL_READ_WRITE: u64 = EL0_ALLOWED | NO_EXEC_EL0 | NO_EXEC_EL1;
const ALL_READ_ONLY: u64 = EL0_ALLOWED | READ_ONLY | NO_EXEC_EL0 | NO_EXEC_EL1;

const GUEST: &[u8] = include_bytes!("../guest/guest.bin");

// ------------------------------- ioctl structs ------------------------------------------------
#[repr(C)]
struct MemRegion { slot: u32, flags: u32, guest_phys_addr: u64, memory_size: u64, userspace_addr: u64 }
#[repr(C)]
#[derive(Default)]
struct VcpuInit { target: u32, features: [u32; 7] }
#[repr(C)]
struct OneReg { id: u64, addr: u64 }
#[repr(C)]
struct KvmRun { _hdr: [u8; 8], exit_reason: u32, _pad: [u8; 20], exit: [u8; 256] }
#[repr(C)]
#[derive(Clone, Copy)]
struct MmioExit { phys_addr: u64, data: [u8; 8], len: u32, is_write: u8 }

fn ioctl(fd: RawFd, req: u64, arg: u64) -> io::Result<i32> {
    let r = unsafe { libc::ioctl(fd, req as _, arg) };
    if r < 0 { Err(io::Error::last_os_error()) } else { Ok(r) }
}
fn ioctl_fd(fd: RawFd, req: u64, arg: u64) -> io::Result<OwnedFd> {
    Ok(unsafe { OwnedFd::from_raw_fd(ioctl(fd, req, arg)?) })
}
fn mmap(len: usize, fd: RawFd, flags: i32) -> io::Result<*mut u8> {
    let p = unsafe { libc::mmap(std::ptr::null_mut(), len, libc::PROT_READ | libc::PROT_WRITE, flags, fd, 0) };
    if p == libc::MAP_FAILED { Err(io::Error::last_os_error()) } else { Ok(p.cast()) }
}

/// Guest RAM, seen from the VMM. Every access is bounds-checked: the guest decides what addresses we
/// are asked to read, so they are untrusted input.
struct GuestRam { ptr: *mut u8 }
impl GuestRam {
    fn slice(&self, gpa: u64, len: u64) -> Option<&[u8]> {
        let off = gpa.checked_sub(RAM_BASE)?;
        if off.checked_add(len)? > RAM_SIZE as u64 { return None; }
        Some(unsafe { std::slice::from_raw_parts(self.ptr.add(off as usize), len as usize) })
    }
    fn read_u64(&self, gpa: u64) -> u64 {
        u64::from_le_bytes(self.slice(gpa, 8).expect("u64 inside RAM").try_into().unwrap())
    }
    fn write_u64(&self, gpa: u64, v: u64) {
        let off = (gpa - RAM_BASE) as usize;
        assert!(off + 8 <= RAM_SIZE);
        unsafe { std::ptr::copy_nonoverlapping(v.to_le_bytes().as_ptr(), self.ptr.add(off), 8) }
    }
    fn c_string(&self, gpa: u64) -> String {
        let bytes = (0..256).map_while(|i| self.slice(gpa + i, 1).map(|b| b[0])).take_while(|&b| b != 0);
        String::from_utf8_lossy(&bytes.collect::<Vec<_>>()).into_owned()
    }
}

/// Identity-mapped page tables (guest virtual = guest physical), three levels, 4 KiB pages:
/// L1 (1 GiB per entry) -> L2 (2 MiB per entry) -> L3 (4 KiB per entry).
fn build_page_tables(ram: &GuestRam) {
    let (l1, l2_low, l2_ram, l3) = (PT_BASE, PT_BASE + 0x1000, PT_BASE + 0x2000, PT_BASE + 0x3000);
    let entry = |table: u64, index: u64, value: u64| ram.write_u64(table + index * 8, value);

    entry(l1, 0, l2_low | TABLE); // 0 .. 1 GiB: the doorbell lives here
    entry(l1, RAM_BASE >> 30, l2_ram | TABLE); // 2 .. 3 GiB: our RAM
    entry(l2_low, DOORBELL >> 21, DOORBELL | BLOCK | DEVICE | ACCESSED | EL1_ONLY_DATA);
    entry(l2_ram, 0, l3 | TABLE);
    for &(off, size, perms, _) in REGIONS {
        for page in (off..off + size).step_by(4096) {
            entry(l3, page >> 12, (RAM_BASE + page) | PAGE | NORMAL | INNER_SHAREABLE | ACCESSED | perms);
        }
    }
    // Every page not listed in REGIONS stays 0: not mapped at all.
}

fn print_notebook(ram: &GuestRam) {
    let count = ram.read_u64(LOG_BASE).min(100);
    println!("\nThe supervisor's notebook (read by the VMM straight from guest memory):");
    for i in 0..count {
        let e = LOG_BASE + 64 + i * 48;
        let f: Vec<u64> = (0..6).map(|k| ram.read_u64(e + k * 8)).collect();
        let line = match f[0] {
            1 => format!("allowed  write(fd={}, {} bytes)          -> left the VM through the doorbell", f[2], f[4]),
            2 if f[1] == 56 => format!("refused  open(\"{}\")         -> stayed inside the VM", ram.c_string(f[3])),
            2 if f[1] == 64 => format!("refused  write(fd={}, address {:#x}) -> stayed inside the VM", f[2], f[3]),
            2 => format!("refused  system call #{}", f[1]),
            3 => {
                let (class, addr, pc) = (f[1] >> 26, f[2], f[3]);
                let what = match class {
                    0x24 => format!("write to protected memory at {addr:#x}"),
                    0x20 => format!("run code at protected address {addr:#x}"),
                    0x00 => "privileged instruction (needs level 0)".to_string(),
                    c => format!("exception class {c:#x}"),
                };
                format!("blocked  {what}, by instruction at {pc:#x}")
            }
            4 => format!("exit     code {}", f[1] as i64),
            k => format!("unknown entry kind {k}"),
        };
        println!("  {:>2}. {line}", i + 1);
    }
}

fn main() -> io::Result<()> {
    let t0 = Instant::now();

    // 1. The VM, its RAM and one vCPU: exactly as in chapter 1.
    let kvm = File::options().read(true).write(true).open("/dev/kvm")?;
    let ipa = ioctl(kvm.as_raw_fd(), KVM_CHECK_EXTENSION, KVM_CAP_ARM_VM_IPA_SIZE)?;
    let vm = ioctl_fd(kvm.as_raw_fd(), KVM_CREATE_VM, ipa as u64)?;
    let ram = GuestRam { ptr: mmap(RAM_SIZE, -1, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE)? };
    let region = MemRegion { slot: 0, flags: 0, guest_phys_addr: RAM_BASE, memory_size: RAM_SIZE as u64, userspace_addr: ram.ptr as u64 };
    ioctl(vm.as_raw_fd(), KVM_SET_USER_MEMORY_REGION, &region as *const _ as u64)?;

    // 2. Load the guest (supervisor + agent code) and the supervisor's page tables.
    unsafe { std::ptr::copy_nonoverlapping(GUEST.as_ptr(), ram.ptr, GUEST.len()) };
    build_page_tables(&ram);
    println!("Guest memory map (the supervisor turns these permissions on; the CPU enforces them):");
    for &(off, size, perms, name) in REGIONS {
        let who = if perms & EL0_ALLOWED == 0 { "level 0 only" } else if perms & READ_ONLY != 0 { "agent may read" } else { "agent may read+write" };
        println!("  {:#010x}..{:#010x}  {who:<21} {name}", RAM_BASE + off, RAM_BASE + off + size);
    }
    println!();

    // 3. vCPU starting at the supervisor's first instruction, at guest level 0.
    let vcpu = ioctl_fd(vm.as_raw_fd(), KVM_CREATE_VCPU, 0)?;
    let run_size = ioctl(kvm.as_raw_fd(), KVM_GET_VCPU_MMAP_SIZE, 0)? as usize;
    let run = mmap(run_size, vcpu.as_raw_fd(), libc::MAP_SHARED)? as *mut KvmRun;
    let mut init = VcpuInit::default();
    ioctl(vm.as_raw_fd(), KVM_ARM_PREFERRED_TARGET, &mut init as *mut _ as u64)?;
    ioctl(vcpu.as_raw_fd(), KVM_ARM_VCPU_INIT, &init as *const _ as u64)?;
    let pc = RAM_BASE;
    ioctl(vcpu.as_raw_fd(), KVM_SET_ONE_REG, &OneReg { id: REG_PC, addr: &pc as *const _ as u64 } as *const _ as u64)?;

    // 4. Run. The only exits we expect are doorbell rings from the supervisor.
    let (mut exits, mut writes) = (0u64, 0u64);
    let mut out = io::stdout().lock();
    let code = loop {
        ioctl(vcpu.as_raw_fd(), KVM_RUN, 0)?;
        exits += 1;
        let run = unsafe { &*run };
        if run.exit_reason == KVM_EXIT_INTERNAL_ERROR {
            return Err(io::Error::other("KVM internal error"));
        }
        if run.exit_reason != KVM_EXIT_MMIO {
            return Err(io::Error::other(format!("unexpected exit reason {}", run.exit_reason)));
        }
        let mmio: MmioExit = unsafe { std::ptr::read_unaligned(run.exit.as_ptr().cast()) };
        if mmio.phys_addr != DOORBELL || mmio.is_write != 1 {
            return Err(io::Error::other(format!("unexpected MMIO at {:#x}", mmio.phys_addr)));
        }
        // The doorbell rang: the request is in the shared page.
        let (op, a, b, c) = (ram.read_u64(HC_PAGE), ram.read_u64(HC_PAGE + 8), ram.read_u64(HC_PAGE + 16), ram.read_u64(HC_PAGE + 24));
        match op {
            1 => {
                writes += 1;
                // Even though the supervisor checked the pointer, the VMM checks again (defense in depth).
                let result = match ram.slice(a, b) {
                    Some(bytes) => { out.write_all(bytes)?; out.flush()?; b }
                    None => (-14i64) as u64,
                };
                ram.write_u64(HC_PAGE + 32, result);
            }
            2 => break a as i64,
            3 => return Err(io::Error::other(format!("supervisor fault: class {:#x} at pc {b:#x}, address {c:#x}", a >> 26))),
            _ => return Err(io::Error::other(format!("unknown doorbell request {op}"))),
        }
    };
    drop(out);

    print_notebook(&ram);
    println!(
        "\nExits to the VMM: {exits} ({writes} allowed writes + 1 exit). Refused calls and blocked faults: 0 exits.\n\
         Agent exit code {code}. Total time {:.0} us.",
        t0.elapsed().as_secs_f64() * 1e6
    );
    Ok(())
}
