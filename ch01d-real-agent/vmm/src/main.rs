//! Chapter 1d VMM: run a REAL program (a static arm64 Linux ELF) under the supervisor,
//! with a policy file, resource limits, a watchdog, and a jail around the VMM itself.
//!
//!                    REAL mode (host)               GUEST mode
//!     level 0        KVM, inside host Linux         supervisor   (supervisor/, Rust, no_std)
//!     level 3        this program (the VMM)         the agent    (agent/, ordinary Rust + std)
//!
//! Usage:  vmm [--policy FILE] [--jail-selftest] [AGENT_ELF] [-- AGENT_ARGS...]
//!
//! Walls around the agent, from inside out:
//!   1. the supervisor: every system call is answered, refused or forwarded, by the policy
//!   2. this VMM: re-checks every forwarded request; enforces time, output and file limits
//!   3. the host kernel, on this VMM process: seccomp (only the system calls the VMM needs),
//!      Landlock (only ./workspace, read-only), rlimits (no new processes)

use std::collections::BTreeMap;
use std::ffi::CString;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

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

// ------------------------------- guest memory map (must match supervisor/src/main.rs) ---------
const RAM_BASE: u64 = 0x8000_0000;
const RAM_SIZE: usize = 128 << 20; // 128 MiB, allocated lazily by the host as it is touched
const BOOT_INFO: u64 = 0x8010_0000;
const HC_PAGE: u64 = 0x8011_0000;
const HC_TEXT: u64 = HC_PAGE + 64;
const POLICY_PAGE: u64 = 0x8012_0000;
const PT_BASE: u64 = 0x8020_0000;
const LOG_BASE: u64 = 0x8040_0000;
const SUP_LO: u64 = 0x8000_0000; // supervisor: code, boot info, doorbell page, policy, tables, notebook, stack
const SUP_HI: u64 = 0x8100_0000;
const ELF_LO: u64 = 0x8100_0000; // the agent's program pieces
const ELF_HI: u64 = 0x8200_0000;
const BRK_START: u64 = 0x8200_0000; // heap (brk)
const BRK_END: u64 = 0x8280_0000;
const MMAP_START: u64 = 0x8280_0000; // mmap area: its usable size is the policy's memory_mb
const MMAP_MAX_END: u64 = 0x87c0_0000;
const STACK_LO: u64 = 0x87c0_0000;
const STACK_HI: u64 = 0x8800_0000; // stack: 4 MiB below this
const DOORBELL: u64 = 0x0900_0000;

// Page-table entry bits (4 KiB pages).
const TABLE: u64 = 0b11;
const PAGE: u64 = 0b11;
const BLOCK: u64 = 0b01;
const DEVICE: u64 = 1 << 2;
const INNER_SHAREABLE: u64 = 3 << 8;
const ACCESSED: u64 = 1 << 10;
const EL0_ALLOWED: u64 = 1 << 6;
const READ_ONLY: u64 = 1 << 7;
const NO_EXEC_EL1: u64 = 1 << 53;
const NO_EXEC_EL0: u64 = 1 << 54;

const SUPERVISOR: &[u8] = include_bytes!("../../supervisor.bin");

// Doorbell requests (must match the supervisor).
const HC_WRITE: u64 = 1;
const HC_EXIT: u64 = 2;
const HC_PANIC: u64 = 3;
const HC_OPEN: u64 = 4;
const HC_READ: u64 = 5;
const HC_CLOSE: u64 = 6;
const HC_FSTAT: u64 = 7;
const HC_LSEEK: u64 = 8;
const HC_GETRANDOM: u64 = 9;
const HC_FAULT: u64 = 10;
const HC_LOG_FULL: u64 = 11;
const HC_SLEEP: u64 = 12;

/// Linux arm64 system call numbers, for policies and reports.
const SYSCALLS: &[(&str, u64)] = &[
    ("fcntl", 25), ("ioctl", 29), ("openat", 56), ("close", 57), ("pipe2", 59), ("lseek", 62), ("read", 63),
    ("write", 64), ("writev", 66), ("ppoll", 73), ("fstat", 80), ("exit", 93), ("exit_group", 94),
    ("set_tid_address", 96), ("futex", 98), ("nanosleep", 101), ("clock_gettime", 113), ("clock_nanosleep", 115), ("tkill", 130), ("sigaltstack", 132),
    ("rt_sigaction", 134), ("rt_sigprocmask", 135), ("getpid", 172), ("getuid", 174), ("geteuid", 175),
    ("getgid", 176), ("getegid", 177), ("gettid", 178), ("socket", 198), ("socketpair", 199), ("bind", 200),
    ("connect", 203), ("brk", 214), ("munmap", 215), ("mremap", 216), ("clone", 220), ("execve", 221),
    ("mmap", 222), ("mprotect", 226), ("madvise", 233), ("getrandom", 278), ("statx", 291), ("clone3", 435),
];
const ERRNOS: &[(&str, i64)] = &[
    ("EPERM", 1), ("ENOENT", 2), ("EBADF", 9), ("ENOMEM", 12), ("EACCES", 13), ("EFAULT", 14), ("EINVAL", 22),
    ("EMFILE", 24), ("ENOTTY", 25), ("ENAMETOOLONG", 36), ("ENOSYS", 38),
];
fn errno(name: &str) -> i64 { ERRNOS.iter().find(|e| e.0 == name).map(|e| e.1).unwrap() }

// ------------------------------- ioctl structs ------------------------------------------------
#[repr(C)]
struct MemRegion { slot: u32, flags: u32, guest_phys_addr: u64, memory_size: u64, userspace_addr: u64 }
#[repr(C)]
#[derive(Default)]
struct VcpuInit { target: u32, features: [u32; 7] }
#[repr(C)]
struct OneReg { id: u64, addr: u64 }
#[repr(C)]
struct KvmRun { _request_interrupt_window: u8, immediate_exit: u8, _pad1: [u8; 6], exit_reason: u32, _pad: [u8; 20], exit: [u8; 256] }
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
fn err(msg: impl Into<String>) -> io::Error { io::Error::other(msg.into()) }
fn host_random(buf: &mut [u8]) -> io::Result<()> {
    let n = unsafe { libc::getrandom(buf.as_mut_ptr().cast(), buf.len(), 0) };
    if n as usize == buf.len() { Ok(()) } else { Err(io::Error::last_os_error()) }
}

/// Guest RAM seen from the VMM. Addresses come from the guest, so every access is bounds-checked.
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
    fn read_u64(&self, gpa: u64) -> u64 { u64::from_le_bytes(self.slice(gpa, 8).expect("inside RAM").try_into().unwrap()) }
    fn write_u64(&self, gpa: u64, v: u64) { self.slice_mut(gpa, 8).expect("inside RAM").copy_from_slice(&v.to_le_bytes()) }
    fn write_bytes(&self, gpa: u64, b: &[u8]) { self.slice_mut(gpa, b.len() as u64).expect("inside RAM").copy_from_slice(b) }
    fn c_string(&self, gpa: u64) -> String {
        let bytes: Vec<u8> = (0..256).map_while(|i| self.slice(gpa + i, 1).map(|b| b[0])).take_while(|&b| b != 0).collect();
        String::from_utf8_lossy(&bytes).into_owned()
    }
}

// ------------------------------- the policy file ----------------------------------------------
struct Policy {
    time_limit: Duration,
    memory_mb: u64,
    max_output: u64,
    max_open_files: usize,
    workspace: PathBuf,
    read: Vec<String>,
    actions: [u8; 512], // per system call: 0 = not allowed, 1 = allowed, 2 = deny with errnos[nr]
    errnos: [u8; 512],
}

/// Parse a policy. Anything unknown is an error: a typo must never silently widen the policy.
fn parse_policy(path: &str) -> io::Result<Policy> {
    let text = std::fs::read_to_string(path).map_err(|e| err(format!("{path}: {e}")))?;
    let mut p = Policy {
        time_limit: Duration::from_millis(5000), memory_mb: 32, max_output: 64 << 10, max_open_files: 8,
        workspace: PathBuf::from("./workspace"), read: Vec::new(), actions: [0; 512], errnos: [0; 512],
    };
    let number = |name: &str| SYSCALLS.iter().find(|s| s.0 == name).map(|s| s.1 as usize);
    for (i, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap().trim();
        if line.is_empty() { continue; }
        let bad = |what: &str| err(format!("{path}:{}: {what}: {raw}", i + 1));
        let (key, value) = line.split_once('=').ok_or_else(|| bad("expected key = value"))?;
        let (key, value) = (key.trim(), value.trim());
        if let Some(names) = key.strip_prefix("deny ") {
            let code = ERRNOS.iter().find(|e| e.0 == value).ok_or_else(|| bad("unknown error name"))?.1;
            for name in names.split_whitespace() {
                let nr = number(name).ok_or_else(|| bad("unknown system call"))?;
                p.actions[nr] = 2;
                p.errnos[nr] = code as u8;
            }
            continue;
        }
        let num = || value.parse::<u64>().map_err(|_| bad("expected a number"));
        match key {
            "time_limit_ms" => p.time_limit = Duration::from_millis(num()?),
            "memory_mb" => p.memory_mb = num()?,
            "max_output_kb" => p.max_output = num()? << 10,
            "max_open_files" => p.max_open_files = num()? as usize,
            "workspace" => p.workspace = PathBuf::from(value),
            "read" => {
                if !value.starts_with("/workspace/") || value.contains("..") || value.len() > 126 {
                    return Err(bad("read prefixes must lie under /workspace/"));
                }
                if p.read.len() == 8 { return Err(bad("at most 8 read prefixes")); }
                p.read.push(value.to_string());
            }
            "allow" => {
                for name in value.split_whitespace() {
                    p.actions[number(name).ok_or_else(|| bad("unknown system call"))?] = 1;
                }
            }
            _ => return Err(bad("unknown key")),
        }
    }
    if p.memory_mb << 20 > MMAP_MAX_END - MMAP_START {
        return Err(err(format!("{path}: memory_mb is at most {}", (MMAP_MAX_END - MMAP_START) >> 20)));
    }
    Ok(p)
}

/// The policy as the supervisor reads it: a table in guest memory (see POLICY in the supervisor).
fn write_policy_page(ram: &GuestRam, p: &Policy) {
    ram.write_bytes(POLICY_PAGE, &p.actions);
    ram.write_bytes(POLICY_PAGE + 512, &p.errnos);
    ram.write_u64(POLICY_PAGE + 1024, p.read.len() as u64);
    for (i, prefix) in p.read.iter().enumerate() {
        let at = POLICY_PAGE + 1088 + i as u64 * 128;
        ram.write_bytes(at, prefix.as_bytes());
        ram.write_bytes(at + prefix.len() as u64, &[0]);
    }
}

// ------------------------------- loading the program (what execve does) -----------------------
struct Program { entry: u64, phdr: u64, phnum: u64, rw_lo: u64, rw_hi: u64 }

/// Load a static arm64 ELF executable's PT_LOAD pieces at their addresses and record per-page
/// permissions for the page tables.
fn load_elf(ram: &GuestRam, file: &[u8], perms: &mut [u64]) -> io::Result<Program> {
    let u16_at = |o: usize| u16::from_le_bytes(file[o..o + 2].try_into().unwrap()) as u64;
    let u32_at = |o: usize| u32::from_le_bytes(file[o..o + 4].try_into().unwrap()) as u64;
    let u64_at = |o: usize| u64::from_le_bytes(file[o..o + 8].try_into().unwrap());
    if file.len() < 64 || &file[0..4] != b"\x7fELF" || file[4] != 2 || file[5] != 1 {
        return Err(err("not a 64-bit little-endian ELF file"));
    }
    // ET_EXEC: linked for a fixed address. ET_DYN without an interpreter: a "static PIE", the usual
    // static build today (Alpine, most distributions). We place it at ELF_LO; it relocates itself.
    let base = match (u16_at(16), u16_at(18)) {
        (2, 183) => 0,
        (3, 183) => ELF_LO,
        _ => return Err(err("need a static arm64 executable (ET_EXEC or static PIE)")),
    };
    let (entry, phoff, phentsize, phnum) = (base + u64_at(24), u64_at(32) as usize, u16_at(54) as usize, u16_at(56));
    if phentsize < 56 || phoff.checked_add(phnum as usize * phentsize).is_none_or(|end| end > file.len()) {
        return Err(err("bad program headers"));
    }
    let (mut phdr, mut rw_lo, mut rw_hi) = (0, u64::MAX, 0);
    for i in 0..phnum as usize {
        let ph = phoff + i * phentsize;
        let (kind, flags, offset, vaddr) = (u32_at(ph), u32_at(ph + 4), u64_at(ph + 8) as usize, u64_at(ph + 16));
        let (filesz, memsz) = (u64_at(ph + 32) as usize, u64_at(ph + 40));
        let vaddr = vaddr.checked_add(base).ok_or_else(|| err("segment overflows"))?;
        match kind {
            3 => return Err(err("dynamically linked: the agent must be a static binary")),
            1 => {
                let end = vaddr.checked_add(memsz).ok_or_else(|| err("segment overflows"))?;
                if vaddr < ELF_LO || end > ELF_HI || filesz as u64 > memsz || offset.checked_add(filesz).is_none_or(|e| e > file.len()) {
                    return Err(err(format!("segment at {vaddr:#x} is outside the agent's program area")));
                }
                ram.write_bytes(vaddr, &file[offset..offset + filesz]); // the rest (bss) is already zero
                if offset <= phoff && phoff + phnum as usize * phentsize <= offset + filesz {
                    phdr = vaddr + (phoff - offset) as u64; // where the program headers are mapped (AT_PHDR)
                }
                let mut bits = EL0_ALLOWED | NO_EXEC_EL1; // the agent may read it; the supervisor never runs it
                if flags & 2 != 0 { rw_lo = rw_lo.min(vaddr); rw_hi = rw_hi.max(end); } else { bits |= READ_ONLY; }
                if flags & 1 == 0 { bits |= NO_EXEC_EL0; }
                for page in (vaddr & !0xfff..end).step_by(4096) {
                    let slot = &mut perms[((page - RAM_BASE) >> 12) as usize];
                    // Two pieces sharing a page get the union: writable and/or executable wins.
                    *slot = if *slot == 0 { bits } else { (*slot | bits) & !((READ_ONLY | NO_EXEC_EL0) & !(*slot & bits)) };
                }
            }
            _ => {}
        }
    }
    if phdr == 0 { return Err(err("program headers not inside a loaded segment")); }
    if rw_lo == u64::MAX { rw_lo = 0; }
    Ok(Program { entry, phdr, phnum, rw_lo, rw_hi })
}

/// The starting stack Linux gives every program: argc, argv, envp, then the auxiliary vector.
fn build_stack(ram: &GuestRam, prog: &Program, args: &[String]) -> io::Result<u64> {
    let mut top = STACK_HI;
    let mut push = |b: &[u8]| { top -= b.len() as u64; ram.write_bytes(top, b); top };
    let mut argv = Vec::new();
    for a in args.iter().rev() {
        argv.push(push(&[a.as_bytes(), b"\0"].concat()));
    }
    argv.reverse();
    let mut random = [0u8; 16];
    host_random(&mut random)?;
    let at_random = push(&random);
    const AT_PHDR: u64 = 3; const AT_PHENT: u64 = 4; const AT_PHNUM: u64 = 5; const AT_PAGESZ: u64 = 6;
    const AT_ENTRY: u64 = 9; const AT_UID: u64 = 11; const AT_EUID: u64 = 12; const AT_GID: u64 = 13;
    const AT_EGID: u64 = 14; const AT_SECURE: u64 = 23; const AT_RANDOM: u64 = 25;
    let mut words = vec![argv.len() as u64];
    words.extend(&argv);
    words.extend([0, 0]); // end of argv, empty environment
    words.extend([AT_PHDR, prog.phdr, AT_PHENT, 56, AT_PHNUM, prog.phnum, AT_PAGESZ, 4096, AT_ENTRY, prog.entry,
                  AT_UID, 1000, AT_EUID, 1000, AT_GID, 1000, AT_EGID, 1000, AT_SECURE, 0, AT_RANDOM, at_random, 0, 0]);
    let sp = (top - words.len() as u64 * 8) & !15;
    for (i, w) in words.iter().enumerate() { ram.write_u64(sp + i as u64 * 8, *w); }
    Ok(sp)
}

/// Identity-mapped page tables (guest virtual = guest physical), 4 KiB pages everywhere.
/// These are plain bytes in guest RAM; the CPU uses them once the supervisor turns the MMU on.
fn build_page_tables(ram: &GuestRam, perms: &[u64]) {
    let (l1, l2_low, l2_ram, l3_first) = (PT_BASE, PT_BASE + 0x1000, PT_BASE + 0x2000, PT_BASE + 0x3000);
    let entry = |table: u64, index: u64, value: u64| ram.write_u64(table + index * 8, value);
    entry(l1, 0, l2_low | TABLE);
    entry(l1, RAM_BASE >> 30, l2_ram | TABLE);
    entry(l2_low, DOORBELL >> 21, DOORBELL | BLOCK | DEVICE | ACCESSED | NO_EXEC_EL0 | NO_EXEC_EL1);
    for (i, &bits) in perms.iter().enumerate() {
        let (table, index) = (l3_first + (i as u64 / 512) * 0x1000, i as u64 % 512);
        if i % 512 == 0 { entry(l2_ram, i as u64 / 512, table | TABLE); }
        if bits != 0 {
            entry(table, index, (RAM_BASE + i as u64 * 4096) | PAGE | INNER_SHAREABLE | ACCESSED | bits);
        }
    }
}

// ------------------------------- the host side of forwarded calls -----------------------------
/// The agent sees "/workspace/..."; on the host that is the policy's workspace folder. The
/// supervisor checked the path already; we check again with the same policy and don't rely on it.
struct Files { root: PathBuf, read: Vec<String>, max_open: usize, open: Vec<Option<File>> }
impl Files {
    fn open(&mut self, guest_path: &str) -> i64 {
        if !self.read.iter().any(|p| guest_path.starts_with(p.as_str())) { return -errno("EACCES"); }
        let Some(rest) = guest_path.strip_prefix("/workspace/") else { return -errno("EACCES") };
        if rest.split('/').any(|p| p == "..") { return -errno("EACCES"); }
        if self.open.iter().flatten().count() >= self.max_open { return -errno("EMFILE"); }
        let Ok(full) = self.root.join(rest).canonicalize() else { return -errno("ENOENT") };
        if !full.starts_with(&self.root) { return -errno("EACCES"); }
        match File::open(&full) {
            Ok(f) => { self.open.push(Some(f)); 2 + self.open.len() as i64 }
            Err(_) => -errno("ENOENT"),
        }
    }
    fn get(&mut self, fd: u64) -> Option<&mut File> {
        fd.checked_sub(3).and_then(|i| self.open.get_mut(i as usize)).and_then(|f| f.as_mut())
    }
}

// ------------------------------- wall 3: jail this VMM process --------------------------------
/// Host system calls this VMM still needs once the agent runs. Everything else kills the VMM.
const VMM_SYSCALLS: &[u32] = &[
    17,                // getcwd
    56, 57, 62, 63,    // openat (limited by Landlock), close, lseek, read
    78, 79, 80, 291,   // readlinkat (canonicalize), newfstatat, fstat, statx
    93, 94,            // exit, exit_group
    98, 101, 113, 115, 124, // futex, nanosleep, clock_gettime, clock_nanosleep, sched_yield
    135, 139, 132,     // rt_sigprocmask, rt_sigreturn, sigaltstack
    172, 178,          // getpid, gettid
    214, 215, 216, 222, 226, 233, // brk, munmap, mremap, mmap, mprotect, madvise (our own memory)
    278,               // getrandom
];

fn install_seccomp() -> io::Result<usize> {
    #[repr(C)]
    struct SockFilter { code: u16, jt: u8, jf: u8, k: u32 }
    #[repr(C)]
    struct SockFprog { len: u16, filter: *const SockFilter }
    const LD_ABS: u16 = 0x20; // load a 32-bit word from the system call's data
    const JEQ: u16 = 0x15; // jump if equal
    const RET: u16 = 0x06;
    const ALLOW: u32 = 0x7fff_0000;
    const KILL: u32 = 0x8000_0000; // kill the whole process
    const AUDIT_ARCH_AARCH64: u32 = 0xc000_00b7;
    let (nr_off, arch_off, arg0_lo, arg1_lo) = (0, 4, 16, 24);
    let f = |code, k, jt, jf| SockFilter { code, jt, jf, k };

    let mut prog = vec![
        f(LD_ABS, arch_off, 0, 0),
        f(JEQ, AUDIT_ARCH_AARCH64, 1, 0), // the right architecture? (else system call numbers mean other things)
        f(RET, KILL, 0, 0),
        f(LD_ABS, nr_off, 0, 0),
    ];
    for &nr in VMM_SYSCALLS {
        prog.push(f(JEQ, nr, 0, 1)); // if nr matches: next instruction (allow), else skip it
        prog.push(f(RET, ALLOW, 0, 0));
    }
    // System calls allowed only with one specific argument value (the low 32 bits of it):
    //   ioctl:   only KVM_RUN                     (the kernel uses the low 32 bits of the command)
    //   write:   only to stdout (1) / stderr (2), and the same for writev
    //   fcntl:   only F_GETFD (1) / F_SETFD (2)   (musl's open() sets close-on-exec this way)
    //   tkill:   only SIGUSR1 (10)                (the watchdog stopping the vCPU thread)
    let restricted: [(u32, u32, &[u32]); 5] = [
        (29, arg1_lo, &[KVM_RUN as u32]), (64, arg0_lo, &[1, 2]), (66, arg0_lo, &[1, 2]),
        (25, arg1_lo, &[1, 2]), (130, arg1_lo, &[libc::SIGUSR1 as u32]),
    ];
    for (nr, arg, values) in restricted {
        let n = values.len() as u8;
        prog.push(f(LD_ABS, nr_off, 0, 0));
        prog.push(f(JEQ, nr, 0, n + 3)); // not this call: skip the whole block
        prog.push(f(LD_ABS, arg, 0, 0));
        for (i, &v) in values.iter().enumerate() {
            prog.push(f(JEQ, v, n - i as u8, 0)); // match: jump to ALLOW
        }
        prog.push(f(RET, KILL, 0, 0));
        prog.push(f(RET, ALLOW, 0, 0));
    }
    prog.push(f(RET, KILL, 0, 0)); // anything else

    let fprog = SockFprog { len: prog.len() as u16, filter: prog.as_ptr() };
    const SECCOMP_SET_MODE_FILTER: u64 = 1;
    const SECCOMP_FILTER_FLAG_TSYNC: u64 = 1; // apply to every thread (the watchdog too)
    let r = unsafe { libc::syscall(libc::SYS_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, &fprog) };
    if r != 0 { return Err(err(format!("seccomp: {}", io::Error::last_os_error()))); }
    Ok(VMM_SYSCALLS.len() + restricted.len())
}

/// Landlock: an unprivileged process limits its own file access. Afterwards this VMM can open
/// files only beneath the workspace folder, read-only. Files already open (KVM, stdout) keep working.
fn landlock_readonly(dir: &Path) -> Result<i64, String> {
    const CREATE_RULESET: i64 = 444;
    const ADD_RULE: i64 = 445;
    const RESTRICT_SELF: i64 = 446;
    let abi = unsafe { libc::syscall(CREATE_RULESET, std::ptr::null::<u8>(), 0usize, 1u32) }; // query version
    if abi < 1 { return Err(format!("not available on this kernel ({})", io::Error::last_os_error())); }
    // Every filesystem right this kernel's Landlock version knows is "handled" (denied unless granted).
    let handled: u64 = match abi { 1 => (1 << 13) - 1, 2 => (1 << 14) - 1, 3 | 4 => (1 << 15) - 1, _ => (1 << 16) - 1 };
    const READ_FILE: u64 = 1 << 2;
    const READ_DIR: u64 = 1 << 3;
    #[repr(C)]
    struct RulesetAttr { handled_access_fs: u64 }
    #[repr(C, packed)]
    struct PathBeneath { allowed_access: u64, parent_fd: i32 }
    let attr = RulesetAttr { handled_access_fs: handled };
    let ruleset = unsafe { libc::syscall(CREATE_RULESET, &attr, std::mem::size_of::<RulesetAttr>(), 0u32) };
    if ruleset < 0 { return Err(format!("create ruleset: {}", io::Error::last_os_error())); }
    let cpath = CString::new(dir.as_os_str().as_bytes()).map_err(|e| e.to_string())?;
    let dirfd = unsafe { libc::open(cpath.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if dirfd < 0 { return Err(format!("open workspace: {}", io::Error::last_os_error())); }
    let rule = PathBeneath { allowed_access: READ_FILE | READ_DIR, parent_fd: dirfd };
    let added = unsafe { libc::syscall(ADD_RULE, ruleset, 1u32, &rule, 0u32) };
    let restricted = if added == 0 { unsafe { libc::syscall(RESTRICT_SELF, ruleset, 0u32) } } else { -1 };
    let why = io::Error::last_os_error();
    unsafe { libc::close(dirfd); libc::close(ruleset as i32); }
    if restricted != 0 { return Err(format!("apply rules: {why}")); }
    Ok(abi)
}

fn jail(workspace: &Path) -> io::Result<String> {
    let limit = |res, n| unsafe { libc::setrlimit(res, &libc::rlimit { rlim_cur: n, rlim_max: n }) };
    limit(libc::RLIMIT_NPROC, 0); // no new processes (or threads) from here on
    limit(libc::RLIMIT_CORE, 0); // no core dumps (they would contain guest memory)
    limit(libc::RLIMIT_NOFILE, 64);
    // Required to use Landlock and seccomp without root; also blocks gaining privileges via setuid files.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 { return Err(io::Error::last_os_error()); }
    let landlock = match landlock_readonly(workspace) {
        Ok(abi) => format!("Landlock v{abi}: files limited to {} (read-only)", workspace.display()),
        Err(why) => format!("Landlock {why}: relying on seccomp + checks only"),
    };
    let n = install_seccomp()?;
    Ok(format!("seccomp: {n} host system calls allowed (ioctl = KVM_RUN only, write = stdout/stderr only)\n     {landlock}\n     rlimits: no new processes, no core dumps, 64 open files"))
}

/// Try two things a compromised VMM would do, to prove the jail holds.
fn jail_selftest() {
    println!("selftest: open(\"/etc/passwd\") from the VMM ...");
    match File::open("/etc/passwd") {
        Ok(_) => println!("selftest:   opened: Landlock is NOT protecting files!"),
        Err(e) => println!("selftest:   refused by the host kernel: {e}"),
    }
    println!("selftest: socket() from the VMM: seccomp should kill this process now (exit status 159 = SIGSYS) ...");
    let _ = io::stdout().flush();
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    println!("selftest:   socket() returned {fd}: seccomp is NOT working!");
}

// ------------------------------- watchdog -----------------------------------------------------
static TIMED_OUT: AtomicBool = AtomicBool::new(false);
extern "C" fn on_watchdog_signal(_: libc::c_int) {} // its only job: make KVM_RUN return

/// After `limit`, stop the vCPU: set kvm_run.immediate_exit (in case we are between runs) and
/// signal the vCPU thread (in case it is inside KVM_RUN, which then returns EINTR).
fn start_watchdog(limit: Duration, run: *mut KvmRun) {
    let act = libc::sigaction { sa_sigaction: on_watchdog_signal as *const () as usize, sa_mask: unsafe { std::mem::zeroed() }, sa_flags: 0, sa_restorer: None };
    unsafe { libc::sigaction(libc::SIGUSR1, &act, std::ptr::null_mut()) }; // no SA_RESTART: KVM_RUN must return
    let (vcpu_thread, run) = (unsafe { libc::pthread_self() } as usize, run as usize);
    std::thread::spawn(move || {
        std::thread::sleep(limit);
        TIMED_OUT.store(true, Ordering::SeqCst);
        unsafe {
            std::ptr::addr_of_mut!((*(run as *mut KvmRun)).immediate_exit).write_volatile(1);
            libc::pthread_kill(vcpu_thread as libc::pthread_t, libc::SIGUSR1);
        }
    });
}

// ------------------------------- report -------------------------------------------------------
fn syscall_name(nr: u64) -> String {
    SYSCALLS.iter().find(|s| s.1 == nr).map(|s| s.0.to_string()).unwrap_or_else(|| format!("#{nr}"))
}
fn errno_name(v: i64) -> String {
    ERRNOS.iter().find(|e| e.1 == -v).map(|e| e.0.to_string()).unwrap_or_else(|| v.to_string())
}

fn print_notebook(ram: &GuestRam, exits: u64) {
    let count = ram.read_u64(LOG_BASE).min(10_000);
    let mut table: BTreeMap<(u8, String), (u64, Vec<String>)> = BTreeMap::new();
    let mut totals = [0u64; 3];
    for i in 0..count {
        let e = LOG_BASE + 64 + i * 48;
        let f: Vec<u64> = (0..6).map(|k| ram.read_u64(e + k * 8)).collect();
        let (kind, nr, a1, res) = (f[0], f[1], f[3], f[5] as i64);
        let (bucket, detail) = match kind {
            5 => (0u8, None),
            2 => (1, Some(if nr == 56 { format!("\"{}\" -> {}", ram.c_string(a1), errno_name(res)) } else { errno_name(res) })),
            1 => (2, (nr == 56).then(|| format!("\"{}\" -> {}", ram.c_string(a1), if res < 0 { errno_name(res) } else { format!("fd {res}") }))),
            _ => continue,
        };
        totals[bucket as usize] += 1;
        let row = table.entry((bucket, syscall_name(nr))).or_default();
        row.0 += 1;
        if let Some(d) = detail { if !row.1.contains(&d) && row.1.len() < 4 { row.1.push(d); } }
    }
    println!("\n  {:<10} {:<16} {:>5} {:>6}   details", "bucket", "system call", "calls", "exits");
    let names = ["ANSWERED", "REFUSED", "FORWARDED"];
    for ((bucket, name), (calls, details)) in &table {
        let exits = if *bucket == 2 { calls.to_string() } else { "0".into() };
        println!("  {:<10} {:<16} {:>5} {:>6}   {}", names[*bucket as usize], name, calls, exits, details.join(", "));
    }
    println!("\n  {} system calls: {} answered, {} refused, {} forwarded. VM exits: {exits}.",
             totals.iter().sum::<u64>(), totals[0], totals[1], totals[2]);
}

fn stop(ram: &GuestRam, exits: u64, why: &str) -> ! {
    print_notebook(ram, exits);
    println!("\nVMM: agent STOPPED: {why}");
    std::process::exit(2);
}

// ------------------------------- main ---------------------------------------------------------
fn main() -> io::Result<()> {
    let t0 = Instant::now();
    let (mut policy_path, mut agent_path, mut agent_args, mut selftest) =
        ("policies/default.policy".to_string(), None, vec!["agent".to_string()], false);
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--policy" => policy_path = args.next().ok_or_else(|| err("--policy needs a file"))?,
            "--jail-selftest" => selftest = true,
            "--" => { agent_args.extend(args.by_ref()); }
            _ => agent_path = Some(a),
        }
    }
    let agent_path = agent_path.unwrap_or_else(|| "agent/target/aarch64-unknown-linux-musl/release/agent".into());
    agent_args[0] = Path::new(&agent_path).file_name().map_or("agent".into(), |n| n.to_string_lossy().into_owned()); // like a shell
    let policy = parse_policy(&policy_path)?;
    let elf = std::fs::read(&agent_path).map_err(|e| err(format!("{agent_path}: {e}")))?;
    let root = policy.workspace.canonicalize().map_err(|e| err(format!("workspace {}: {e}", policy.workspace.display())))?;
    let mut files = Files { root: root.clone(), read: policy.read.clone(), max_open: policy.max_open_files, open: Vec::new() };

    // 1. VM + guest RAM, as in chapter 1.
    let kvm = File::options().read(true).write(true).open("/dev/kvm")?;
    let ipa = ioctl(kvm.as_raw_fd(), KVM_CHECK_EXTENSION, KVM_CAP_ARM_VM_IPA_SIZE)?;
    let vm = ioctl_fd(kvm.as_raw_fd(), KVM_CREATE_VM, ipa as u64)?;
    let ram = GuestRam { ptr: mmap(RAM_SIZE, -1, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE)? };
    // 4 KiB pages, not 2 MiB "transparent huge pages": the guest touches a few scattered regions,
    // and with huge pages each one would cost 2 MiB. Measured: ~17 MiB per idle sandbox without this.
    unsafe { libc::madvise(ram.ptr.cast(), RAM_SIZE, libc::MADV_NOHUGEPAGE) };
    let region = MemRegion { slot: 0, flags: 0, guest_phys_addr: RAM_BASE, memory_size: RAM_SIZE as u64, userspace_addr: ram.ptr as u64 };
    ioctl(vm.as_raw_fd(), KVM_SET_USER_MEMORY_REGION, &region as *const _ as u64)?;

    // 2. Supervisor, policy, the agent's program (like execve), page tables, stack, boot record.
    ram.write_bytes(RAM_BASE, SUPERVISOR);
    write_policy_page(&ram, &policy);
    let mut perms = vec![0u64; RAM_SIZE / 4096];
    for page in (SUP_LO..SUP_HI).step_by(4096) { perms[((page - RAM_BASE) >> 12) as usize] = NO_EXEC_EL0; } // level 0 only
    let prog = load_elf(&ram, &elf, &mut perms)?;
    // Heap, the first memory_mb of the mmap area, and the stack: the agent's, never executable. The
    // rest of the mmap area stays unmapped, so the memory limit holds even against direct stores.
    let mmap_end = MMAP_START + (policy.memory_mb << 20);
    for page in (BRK_START..mmap_end).step_by(4096).chain((STACK_LO..STACK_HI).step_by(4096)) {
        perms[((page - RAM_BASE) >> 12) as usize] = EL0_ALLOWED | NO_EXEC_EL0 | NO_EXEC_EL1;
    }
    build_page_tables(&ram, &perms);
    let sp = build_stack(&ram, &prog, &agent_args)?;
    // Wall 3 doesn't trust the supervisor's pointer checks either: forwarded results only ever land
    // in, and output only ever comes from, the agent's own areas.
    let agent_mem = |gpa: u64, len: u64| gpa.checked_add(len).is_some_and(|end|
        (gpa >= ELF_LO && end <= mmap_end) || (gpa >= STACK_LO && end <= STACK_HI));
    for (i, v) in [prog.entry, sp, BRK_START, BRK_END, MMAP_START, mmap_end, prog.rw_lo, prog.rw_hi].into_iter().enumerate() {
        ram.write_u64(BOOT_INFO + i as u64 * 8, v);
    }

    // 3. One vCPU, starting in the supervisor at guest level 0.
    let vcpu = ioctl_fd(vm.as_raw_fd(), KVM_CREATE_VCPU, 0)?;
    let run_size = ioctl(kvm.as_raw_fd(), KVM_GET_VCPU_MMAP_SIZE, 0)? as usize;
    let run = mmap(run_size, vcpu.as_raw_fd(), libc::MAP_SHARED)? as *mut KvmRun;
    let mut init = VcpuInit::default();
    ioctl(vm.as_raw_fd(), KVM_ARM_PREFERRED_TARGET, &mut init as *mut _ as u64)?;
    ioctl(vcpu.as_raw_fd(), KVM_ARM_VCPU_INIT, &init as *const _ as u64)?;
    let pc = RAM_BASE;
    ioctl(vcpu.as_raw_fd(), KVM_SET_ONE_REG, &OneReg { id: REG_PC, addr: &pc as *const _ as u64 } as *const _ as u64)?;

    // 4. Watchdog, then lock this process down. From here on the VMM can't open sockets, start
    //    programs or read anything outside the workspace, even if the agent took it over.
    start_watchdog(policy.time_limit, run);
    let jail_status = jail(&root)?;
    println!("VMM: policy {policy_path}: time {} ms, memory {} MB, output {} KB, open files {}, read {:?}",
             policy.time_limit.as_millis(), policy.memory_mb, policy.max_output >> 10, policy.max_open_files, policy.read);
    println!("VMM: jail: {jail_status}");
    println!("VMM: agent {agent_path} {:?} ({} KB), entry {:#x}\n", &agent_args[1..], elf.len() / 1024, prog.entry);
    if selftest { jail_selftest(); return Ok(()); }

    // 5. Run. Every exit is a doorbell ring from the supervisor (or the watchdog).
    let (mut exits, mut printed) = (0u64, 0u64);
    let mut out = io::stdout().lock();
    let code = loop {
        if let Err(e) = ioctl(vcpu.as_raw_fd(), KVM_RUN, 0) {
            if e.raw_os_error() == Some(libc::EINTR) && TIMED_OUT.load(Ordering::SeqCst) {
                drop(out);
                stop(&ram, exits, &format!("time limit of {} ms reached (the watchdog interrupted the vCPU)", policy.time_limit.as_millis()));
            }
            if e.raw_os_error() == Some(libc::EINTR) { continue; }
            return Err(e);
        }
        exits += 1;
        let run = unsafe { &*run };
        if run.exit_reason != KVM_EXIT_MMIO { return Err(err(format!("unexpected exit reason {}", run.exit_reason))); }
        let mmio: MmioExit = unsafe { std::ptr::read_unaligned(run.exit.as_ptr().cast()) };
        if mmio.phys_addr != DOORBELL || mmio.is_write != 1 { return Err(err(format!("unexpected MMIO at {:#x}", mmio.phys_addr))); }
        let req = |i: u64| ram.read_u64(HC_PAGE + 8 * i);
        let (op, a, b, c) = (req(0), req(1), req(2), req(3));
        let result: i64 = match op {
            HC_WRITE => match ram.slice(a, b).filter(|_| agent_mem(a, b)) {
                Some(bytes) => {
                    let room = policy.max_output.saturating_sub(printed) as usize;
                    out.write_all(&bytes[..bytes.len().min(room)])?;
                    out.flush()?;
                    printed += b;
                    if printed > policy.max_output {
                        drop(out);
                        stop(&ram, exits, &format!("output limit of {} KB reached", policy.max_output >> 10));
                    }
                    b as i64
                }
                None => -errno("EFAULT"),
            },
            HC_OPEN => files.open(&ram.c_string(HC_TEXT)),
            HC_READ => match (files.get(a), ram.slice_mut(b, c).filter(|_| agent_mem(b, c))) {
                (Some(f), Some(buf)) => f.read(buf).map(|n| n as i64).unwrap_or(-errno("EBADF")),
                (None, _) => -errno("EBADF"),
                (_, None) => -errno("EFAULT"),
            },
            HC_CLOSE => match a.checked_sub(3).and_then(|i| files.open.get_mut(i as usize)).and_then(Option::take) {
                Some(_) => 0,
                None => -errno("EBADF"),
            },
            HC_FSTAT => match (files.get(a), ram.slice_mut(b, 128).filter(|_| agent_mem(b, 128))) {
                (Some(f), Some(buf)) => {
                    let mut st: libc::stat = unsafe { std::mem::zeroed() };
                    if unsafe { libc::fstat(f.as_raw_fd(), &mut st) } != 0 { -errno("EBADF") } else {
                        // Hide host details from the agent: keep only type, permissions and size.
                        let mut clean: libc::stat = unsafe { std::mem::zeroed() };
                        (clean.st_mode, clean.st_size, clean.st_blksize, clean.st_nlink) = (st.st_mode, st.st_size, 4096, 1);
                        let raw = unsafe { std::slice::from_raw_parts(&clean as *const _ as *const u8, std::mem::size_of::<libc::stat>().min(128)) };
                        buf[..raw.len()].copy_from_slice(raw);
                        0
                    }
                }
                (None, _) => -errno("EBADF"),
                (_, None) => -errno("EFAULT"),
            },
            HC_LSEEK => match files.get(a) {
                Some(f) => {
                    let pos = match c { 0 => Some(SeekFrom::Start(b)), 1 => Some(SeekFrom::Current(b as i64)), 2 => Some(SeekFrom::End(b as i64)), _ => None };
                    pos.and_then(|p| f.seek(p).ok()).map(|p| p as i64).unwrap_or(-errno("EINVAL"))
                }
                None => -errno("EBADF"),
            },
            HC_GETRANDOM => match ram.slice_mut(a, b).filter(|_| agent_mem(a, b)) {
                Some(buf) => { host_random(buf)?; b as i64 }
                None => -errno("EFAULT"),
            },
            HC_SLEEP => {
                // Sleep on the host, at most until the time limit; the watchdog's signal ends it early.
                let ts = libc::timespec { tv_sec: (a / 1_000_000_000) as i64, tv_nsec: (a % 1_000_000_000) as i64 };
                unsafe { libc::nanosleep(&ts, std::ptr::null_mut()) };
                if TIMED_OUT.load(Ordering::SeqCst) {
                    drop(out);
                    stop(&ram, exits, &format!("time limit of {} ms reached (while sleeping)", policy.time_limit.as_millis()));
                }
                0
            }
            HC_EXIT => break a as i64,
            HC_FAULT => {
                drop(out);
                let what = match a >> 26 {
                    0x00 => "illegal instruction (the program crashed itself)",
                    0x24 | 0x25 if b == 0 => "write to address 0 (the program crashed itself, e.g. abort() after an allocation failed)",
                    0x24 | 0x25 => "memory access it isn't allowed",
                    0x20 | 0x21 => "jump into memory it may not run",
                    _ => "CPU fault",
                };
                stop(&ram, exits, &format!("{what}: class {:#x}, address {b:#x}, instruction {c:#x}", a >> 26));
            }
            HC_LOG_FULL => { drop(out); stop(&ram, exits, "the audit log is full (no unlogged system calls allowed)"); }
            HC_PANIC => return Err(err(format!("supervisor fault: {} (esr {a:#x}, pc {b:#x}, address {c:#x})", ram.c_string(HC_TEXT)))),
            _ => return Err(err(format!("unknown doorbell request {op}"))),
        };
        ram.write_u64(HC_PAGE + 32, result as u64);
    };
    drop(out);

    print_notebook(&ram, exits);
    println!("\nVMM: agent exited with code {code}. Total time {:.1} ms (create VM + load + run).", t0.elapsed().as_secs_f64() * 1e3);
    Ok(())
}
