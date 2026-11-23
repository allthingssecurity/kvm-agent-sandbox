//! Chapter 1c: answer it, refuse it, forward it.
//!
//!                    REAL mode (host)               GUEST mode
//!     level 0        KVM, inside host Linux         supervisor (guest/supervisor.S)
//!     level 3        this program (the VMM)         agent code (guest/agent.S)
//!
//! Every system call of the agent goes to the supervisor. The supervisor answers some itself,
//! refuses some, and forwards the rest through the doorbell, the only way out of guest mode.
//! For forwarded calls this VMM makes the real system call on the host: printing to the terminal,
//! and opening/reading files, confined to the ./workspace folder.

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
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
const REG_PC: u64 = 0x6030_0000_0010_0000 | (256 / 4);

// ------------------------------- Guest memory map ---------------------------------------------
const RAM_BASE: u64 = 0x8000_0000;
const RAM_SIZE: usize = 1 << 20;
const HC_PAGE: u64 = 0x8004_0000;
const PT_BASE: u64 = 0x8005_0000;
const LOG_BASE: u64 = 0x8007_0000;
const DOORBELL: u64 = 0x0900_0000;

const REGIONS: &[(u64, u64, u64, &str)] = &[
    (0x00000, 0x10000, EL1_ONLY_EXEC, "supervisor code + data"),
    (0x10000, 0x10000, ALL_READ_EXEC_EL0, "agent code + strings"),
    (0x20000, 0x10000, ALL_READ_WRITE, "agent data + stack"),
    (0x40000, 0x01000, EL1_ONLY_DATA, "doorbell request page"),
    (0x50000, 0x04000, EL1_ONLY_DATA, "page tables"),
    (0x60000, 0x20000, EL1_ONLY_DATA, "supervisor stack + notebook"),
];

const TABLE: u64 = 0b11;
const PAGE: u64 = 0b11;
const BLOCK: u64 = 0b01;
const NORMAL: u64 = 0 << 2;
const DEVICE: u64 = 1 << 2;
const INNER_SHAREABLE: u64 = 3 << 8;
const ACCESSED: u64 = 1 << 10;
const EL0_ALLOWED: u64 = 1 << 6;
const READ_ONLY: u64 = 1 << 7;
const NO_EXEC_EL1: u64 = 1 << 53;
const NO_EXEC_EL0: u64 = 1 << 54;
const EL1_ONLY_EXEC: u64 = NO_EXEC_EL0;
const EL1_ONLY_DATA: u64 = NO_EXEC_EL0 | NO_EXEC_EL1;
const ALL_READ_EXEC_EL0: u64 = EL0_ALLOWED | READ_ONLY | NO_EXEC_EL1;
const ALL_READ_WRITE: u64 = EL0_ALLOWED | NO_EXEC_EL0 | NO_EXEC_EL1;

const GUEST: &[u8] = include_bytes!("../guest/guest.bin");

// Doorbell requests (must match guest/supervisor.S)
const HC_WRITE: u64 = 1;
const HC_EXIT: u64 = 2;
const HC_PANIC: u64 = 3;
const HC_OPEN: u64 = 4;
const HC_READ: u64 = 5;
const HC_CLOSE: u64 = 6;

// Linux error numbers returned to the guest (as negative values)
const EBADF: i64 = 9;
const EACCES: i64 = 13;
const EFAULT: i64 = 14;
const ENOENT: i64 = 2;

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

/// Guest RAM, seen from the VMM. Addresses come from the guest, so every access is bounds-checked.
struct GuestRam { ptr: *mut u8 }
impl GuestRam {
    fn range(&self, gpa: u64, len: u64) -> Option<usize> {
        let off = gpa.checked_sub(RAM_BASE)?;
        if off.checked_add(len)? > RAM_SIZE as u64 { None } else { Some(off as usize) }
    }
    fn slice(&self, gpa: u64, len: u64) -> Option<&[u8]> {
        let off = self.range(gpa, len)?;
        Some(unsafe { std::slice::from_raw_parts(self.ptr.add(off), len as usize) })
    }
    #[allow(clippy::mut_from_ref)]
    fn slice_mut(&self, gpa: u64, len: u64) -> Option<&mut [u8]> {
        let off = self.range(gpa, len)?;
        Some(unsafe { std::slice::from_raw_parts_mut(self.ptr.add(off), len as usize) })
    }
    fn read_u64(&self, gpa: u64) -> u64 {
        u64::from_le_bytes(self.slice(gpa, 8).expect("inside RAM").try_into().unwrap())
    }
    fn write_u64(&self, gpa: u64, v: u64) {
        self.slice_mut(gpa, 8).expect("inside RAM").copy_from_slice(&v.to_le_bytes());
    }
    fn c_string(&self, gpa: u64) -> String {
        let bytes: Vec<u8> = (0..256).map_while(|i| self.slice(gpa + i, 1).map(|b| b[0])).take_while(|&b| b != 0).collect();
        String::from_utf8_lossy(&bytes).into_owned()
    }
}

fn build_page_tables(ram: &GuestRam) {
    let (l1, l2_low, l2_ram, l3) = (PT_BASE, PT_BASE + 0x1000, PT_BASE + 0x2000, PT_BASE + 0x3000);
    let entry = |table: u64, index: u64, value: u64| ram.write_u64(table + index * 8, value);
    entry(l1, 0, l2_low | TABLE);
    entry(l1, RAM_BASE >> 30, l2_ram | TABLE);
    entry(l2_low, DOORBELL >> 21, DOORBELL | BLOCK | DEVICE | ACCESSED | EL1_ONLY_DATA);
    entry(l2_ram, 0, l3 | TABLE);
    for &(off, size, perms, _) in REGIONS {
        for page in (off..off + size).step_by(4096) {
            entry(l3, page >> 12, (RAM_BASE + page) | PAGE | NORMAL | INNER_SHAREABLE | ACCESSED | perms);
        }
    }
}

/// The host side of forwarded file calls. The agent sees "/workspace/..."; on the host that is the
/// ./workspace folder and nothing outside it. The supervisor already checked the path; we check
/// again, because the VMM must not depend on the guest being correct.
struct Files { root: PathBuf, open: Vec<Option<File>> }
impl Files {
    fn open(&mut self, guest_path: &str) -> i64 {
        let Some(rest) = guest_path.strip_prefix("/workspace/") else { return -EACCES };
        if rest.split('/').any(|p| p == "..") || rest.starts_with('/') { return -EACCES; }
        let full = match self.root.join(rest).canonicalize() { Ok(p) => p, Err(_) => return -ENOENT };
        if !full.starts_with(&self.root) { return -EACCES; } // e.g. a symlink pointing outside
        match File::open(&full) {
            Ok(f) => { self.open.push(Some(f)); 2 + self.open.len() as i64 } // guest fds start at 3
            Err(_) => -ENOENT,
        }
    }
    fn get(&mut self, fd: u64) -> Option<&mut File> {
        fd.checked_sub(3).and_then(|i| self.open.get_mut(i as usize)).and_then(|f| f.as_mut())
    }
}

fn syscall_name(nr: u64) -> &'static str {
    match nr { 56 => "open", 57 => "close", 63 => "read", 64 => "write", 93 => "exit", 113 => "clock_gettime",
               142 => "reboot", 172 => "getpid", 222 => "mmap", _ => "?" }
}
fn errno_name(v: i64) -> String {
    match -v { 1 => "EPERM".into(), 9 => "EBADF".into(), 13 => "EACCES".into(), 14 => "EFAULT".into(),
               22 => "EINVAL".into(), _ => v.to_string() }
}

fn print_notebook(ram: &GuestRam) {
    let count = ram.read_u64(LOG_BASE).min(200);
    let (mut answered, mut refused, mut forwarded, mut prints, mut faults) = (0, 0, 0, 0, 0);
    println!("\nThe supervisor's notebook (the VMM reads it straight from guest memory):");
    for i in 0..count {
        let e = LOG_BASE + 64 + i * 48;
        let f: Vec<u64> = (0..6).map(|k| ram.read_u64(e + k * 8)).collect();
        let (kind, nr, a0, a1, a2, res) = (f[0], f[1], f[2], f[3], f[4], f[5] as i64);
        let line = match kind {
            5 => {
                answered += 1;
                let how = match nr {
                    172 => format!("= {res}            (made up by the supervisor)"),
                    113 => "= ok           (read the CPU clock itself)".into(),
                    222 => format!("= {res:#x}   (added a page to the agent's page table)"),
                    _ => format!("= {res}"),
                };
                format!("ANSWERED   {:<34} {how}", format!("{}()", syscall_name(nr)))
            }
            2 => {
                refused += 1;
                let call = match nr {
                    56 => format!("open(\"{}\")", ram.c_string(a1)),
                    64 => format!("write({a0}, {a1:#x}, {a2})"),
                    _ => format!("{}()", syscall_name(nr)),
                };
                format!("REFUSED    {call:<34} -> {}", errno_name(res))
            }
            1 if nr == 64 => { prints += 1; forwarded += 1; continue }
            1 => {
                forwarded += 1;
                let call = match nr {
                    56 => format!("open(\"{}\")", ram.c_string(a1)),
                    63 => format!("read(fd {a0}, {a2})"),
                    57 => format!("close(fd {a0})"),
                    _ => format!("{}()", syscall_name(nr)),
                };
                format!("FORWARDED  {call:<34} = {res}   (real host system call by the VMM)")
            }
            3 => { faults += 1; format!("BLOCKED    fault at {a1:#x}") }
            4 => format!("EXIT       code {}", nr as i64),
            _ => format!("unknown entry kind {kind}"),
        };
        println!("  {line}");
    }
    println!("  FORWARDED  write(1, ...) x {prints:<26} (the agent's printing)");
    println!("\n  bucket       calls   VM exits");
    println!("  answered     {answered:>5}   {:>8}", 0);
    println!("  refused      {refused:>5}   {:>8}", 0);
    println!("  forwarded    {forwarded:>5}   {forwarded:>8}   (one doorbell ring each)");
    if faults > 0 { println!("  blocked      {faults:>5}   {:>8}", 0); }
}

fn main() -> io::Result<()> {
    let t0 = Instant::now();
    let root = Path::new("workspace").canonicalize()
        .map_err(|e| io::Error::other(format!("need a ./workspace folder: {e}")))?;
    let mut files = Files { root, open: Vec::new() };

    let kvm = File::options().read(true).write(true).open("/dev/kvm")?;
    let ipa = ioctl(kvm.as_raw_fd(), KVM_CHECK_EXTENSION, KVM_CAP_ARM_VM_IPA_SIZE)?;
    let vm = ioctl_fd(kvm.as_raw_fd(), KVM_CREATE_VM, ipa as u64)?;
    let ram = GuestRam { ptr: mmap(RAM_SIZE, -1, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE)? };
    let region = MemRegion { slot: 0, flags: 0, guest_phys_addr: RAM_BASE, memory_size: RAM_SIZE as u64, userspace_addr: ram.ptr as u64 };
    ioctl(vm.as_raw_fd(), KVM_SET_USER_MEMORY_REGION, &region as *const _ as u64)?;
    unsafe { std::ptr::copy_nonoverlapping(GUEST.as_ptr(), ram.ptr, GUEST.len()) };
    build_page_tables(&ram);

    let vcpu = ioctl_fd(vm.as_raw_fd(), KVM_CREATE_VCPU, 0)?;
    let run_size = ioctl(kvm.as_raw_fd(), KVM_GET_VCPU_MMAP_SIZE, 0)? as usize;
    let run = mmap(run_size, vcpu.as_raw_fd(), libc::MAP_SHARED)? as *mut KvmRun;
    let mut init = VcpuInit::default();
    ioctl(vm.as_raw_fd(), KVM_ARM_PREFERRED_TARGET, &mut init as *mut _ as u64)?;
    ioctl(vcpu.as_raw_fd(), KVM_ARM_VCPU_INIT, &init as *const _ as u64)?;
    let pc = RAM_BASE;
    ioctl(vcpu.as_raw_fd(), KVM_SET_ONE_REG, &OneReg { id: REG_PC, addr: &pc as *const _ as u64 } as *const _ as u64)?;

    let mut exits = 0u64;
    let mut out = io::stdout().lock();
    loop {
        ioctl(vcpu.as_raw_fd(), KVM_RUN, 0)?;
        exits += 1;
        let run = unsafe { &*run };
        if run.exit_reason != KVM_EXIT_MMIO {
            return Err(io::Error::other(format!("unexpected exit reason {}", run.exit_reason)));
        }
        let mmio: MmioExit = unsafe { std::ptr::read_unaligned(run.exit.as_ptr().cast()) };
        if mmio.phys_addr != DOORBELL || mmio.is_write != 1 {
            return Err(io::Error::other(format!("unexpected MMIO at {:#x}", mmio.phys_addr)));
        }
        let req = |i: u64| ram.read_u64(HC_PAGE + 8 * i);
        let (op, a, b, c) = (req(0), req(1), req(2), req(3));
        let result: i64 = match op {
            HC_WRITE => match ram.slice(a, b) {
                Some(bytes) => { out.write_all(bytes)?; out.flush()?; b as i64 }
                None => -EFAULT,
            },
            HC_OPEN => files.open(&ram.c_string(a)),
            HC_READ => match (files.get(a), ram.slice_mut(b, c)) {
                (Some(f), Some(buf)) => f.read(buf).map(|n| n as i64).unwrap_or(-EBADF),
                (None, _) => -EBADF,
                (_, None) => -EFAULT,
            },
            HC_CLOSE => match a.checked_sub(3).and_then(|i| files.open.get_mut(i as usize)).and_then(Option::take) {
                Some(_) => 0,
                None => -EBADF,
            },
            HC_EXIT => break,
            HC_PANIC => return Err(io::Error::other(format!("supervisor fault: class {:#x} at pc {b:#x}, address {c:#x}", a >> 26))),
            _ => return Err(io::Error::other(format!("unknown doorbell request {op}"))),
        };
        ram.write_u64(HC_PAGE + 32, result as u64);
    }
    drop(out);

    print_notebook(&ram);
    println!("\n  total VM exits: {exits} (forwarded calls + 1 for exit). Total time {:.0} us.", t0.elapsed().as_secs_f64() * 1e6);
    Ok(())
}
