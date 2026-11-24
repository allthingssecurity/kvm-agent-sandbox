//! The supervisor: guest level 0 (EL1). A tiny "kernel" for one real program.
//!
//! The VMM loads the agent's ELF, builds the page tables and writes a BootInfo record. We then:
//!   1. point the CPU's "door" (VBAR_EL1) at our handlers,
//!   2. turn on the page tables and allow the agent to use the FP/SIMD unit,
//!   3. jump down to guest level 3 at the agent's entry point.
//! From then on every system call lands in `el0_sync`, and goes into one of three buckets:
//!   ANSWER IT  (memory, signals, clock, ids, the fd table, the current folder, and /tmp: a small
//!              file system in our own memory)  handled here, no VM exit
//!   REFUSE IT  (network, new processes, writes outside /tmp, paths outside the policy, anything unknown)
//!   FORWARD IT (printing, reading /workspace files and folders, randomness, sleeping)  checked
//!              here, then one doorbell exit each; the VMM makes the real host system call.
//! A fault (bad memory access, illegal instruction) kills the agent, as Linux would.

#![no_std]
#![no_main]

use core::arch::{asm, global_asm};
use core::fmt::Write;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};

// ------------------------------- memory map (must match vmm/src/main.rs) ----------------------
const BOOT_INFO: u64 = 0x8010_0000;
const HC_PAGE: u64 = 0x8011_0000; // doorbell request: [0] op [8] a [16] b [24] c [32] result
const POLICY: u64 = 0x8012_0000; // written by the VMM from the policy file:
                                 //   [0..512) action per system call (0 = not allowed, 1 = allowed, 2 = deny)
                                 //   [512..1024) errno for "deny", [1024] number of read prefixes,
                                 //   [1088 + i*128] read prefix i (NUL-terminated)
const HC_TEXT: u64 = HC_PAGE + 64; // 256-byte buffer: paths (copied, then checked) and panic text
const PT_L1: u64 = 0x8020_0000;
const LOG_BASE: u64 = 0x8040_0000; // notebook: [0] count, entries of 6 x u64 from +64
const LOG_MAX: u64 = 10_000;
const PATH_LOG: u64 = 0x8050_0000; // our permanent copy of every path the agent tries to open
const PATH_LOG_END: u64 = 0x8080_0000;
const STATE: u64 = 0x8080_0000; // our per-process state (fd table, current folder, /tmp's file table)
const SUP_STACK_TOP: u64 = 0x8100_0000;
const SUP_STACK_SIZE: u64 = 0x4_0000; // 256 KiB, with unmapped guard pages below
const AGENT_LO: u64 = 0x8100_0000; // everything the agent owns lives in [AGENT_LO, AGENT_HI)
const AGENT_HI: u64 = 0x8800_0000;
const DOORBELL: u64 = 0x0900_0000;

#[repr(C)]
struct BootInfo { entry: u64, sp: u64, brk_start: u64, brk_end: u64, mmap_start: u64, mmap_end: u64, rw_lo: u64, rw_hi: u64, tmp_lo: u64, tmp_hi: u64,
                  warm: u64, elf_lo: u64, elf_hi: u64, stack_hi: u64, wall_ns: u64, selftest: u64 }
fn boot() -> &'static BootInfo { unsafe { &*(BOOT_INFO as *const BootInfo) } }

// Doorbell requests, handled by the VMM.
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
const HC_STAT: u64 = 13;
const HC_READLINK: u64 = 14;
const HC_GETDENTS: u64 = 15;
const HC_READY: u64 = 16; // warm mode: "everything is set up; give me the request"

// Policy actions.
const ALLOW: u8 = 1;
const DENY: u8 = 2;

// Notebook entry kinds.
const FORWARDED: u64 = 1;
const REFUSED: u64 = 2;
const FAULT: u64 = 3;
const EXIT: u64 = 4;
const ANSWERED: u64 = 5;

// Linux error numbers.
const EPERM: i64 = 1; const ENOENT: i64 = 2; const ESRCH: i64 = 3; const EBADF: i64 = 9; const ENOMEM: i64 = 12;
const EACCES: i64 = 13; const EFAULT: i64 = 14; const EBUSY: i64 = 16; const EEXIST: i64 = 17; const ENOTDIR: i64 = 20;
const EISDIR: i64 = 21; const EINVAL: i64 = 22; const EMFILE: i64 = 24; const ENOTTY: i64 = 25; const EFBIG: i64 = 27;
const ENOSPC: i64 = 28; const ESPIPE: i64 = 29; const EROFS: i64 = 30; const ERANGE: i64 = 34;
const ENAMETOOLONG: i64 = 36; const ENOSYS: i64 = 38; const ENOTEMPTY: i64 = 39;

// Linux flags (arm64 values).
const AT_FDCWD: i32 = -100;
const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
const AT_REMOVEDIR: u64 = 0x200;
const AT_EMPTY_PATH: u64 = 0x1000;
const O_ACCMODE: u64 = 3;
const O_CREAT: u64 = 0o100;
const O_EXCL: u64 = 0o200;
const O_TRUNC: u64 = 0o1000;
const O_APPEND: u64 = 0o2000;
const O_DIRECTORY: u64 = 0o40000;
const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o040000;
const S_IFREG: u32 = 0o100000;
const S_IFCHR: u32 = 0o020000;

// ------------------------------- per-process state (in supervisor memory, starts zeroed) ------
const MAX_FDS: usize = 64;
const MAX_NODES: usize = 256;
const PATH_MAX: usize = 256;

// What an open file is.
const K_FREE: u8 = 0;
const K_STDIN: u8 = 1;
const K_STDOUT: u8 = 2;
const K_STDERR: u8 = 3;
const K_HOST: u8 = 4; // a /workspace file, opened by the VMM: `handle` is the VMM's number for it
const K_HOST_DIR: u8 = 5;
const K_TMP: u8 = 6; // a /tmp file: `handle` is its node
const K_TMP_DIR: u8 = 7;

/// An open file. Several fds can share one (dup): they share the offset, as on Linux.
#[repr(C)]
struct Ofd { kind: u8, mode: u8, append: u8, _pad: u8, refs: u32, handle: u64, offset: u64, path: [u8; PATH_MAX] }
/// A /tmp file or folder. `path` empty = unlinked but still open.
#[repr(C)]
struct Node { used: u8, dir: u8, _pad: [u8; 6], size: u64, data: u64, cap: u64, mtime: u64, path: [u8; PATH_MAX] }
#[repr(C)]
struct State {
    fds: [u16; MAX_FDS], // 0 = closed, else index + 1 into ofds
    ofds: [Ofd; MAX_FDS],
    nodes: [Node; MAX_NODES],
    cwd: [u8; PATH_MAX],
    path: [u8; PATH_MAX],  // the current call's path, cleaned up
    path2: [u8; PATH_MAX], // a second path (rename)
    tmp_next: u64,         // next free byte of /tmp memory
}
/// Only ever called once per trap: a single vCPU and no interrupts, so nothing else touches it.
fn state() -> &'static mut State { unsafe { &mut *(STATE as *mut State) } }
const STATE_SIZE: usize = 0x2_0000; // the VMM maps exactly this much (vmm/src/main.rs)
const _: () = assert!(core::mem::size_of::<State>() <= STATE_SIZE);

static BRK: AtomicU64 = AtomicU64::new(0);
static MMAP_NEXT: AtomicU64 = AtomicU64::new(0);
static PATH_NEXT: AtomicU64 = AtomicU64::new(PATH_LOG);
static LAST_PATH: AtomicU64 = AtomicU64::new(0);
static WALL_OFFSET_NS: AtomicU64 = AtomicU64::new(0); // real time minus our counter's time
static EXITED: AtomicBool = AtomicBool::new(false); // did this system call ring the doorbell?

// ------------------------------- entry, vectors, trap frame (assembly) -------------------------
global_asm!(
    r#"
    .section .text.entry, "ax"
    .global _start
_start:
    ldr   x0, ={stack_top}
    mov   sp, x0
    b     sup_main

    .text
    .macro ventry target
    .balign 0x80
    b     \target
    .endm

    .balign 0x800
    .global vectors
vectors:
    ventry el1_fault_entry          // exceptions in the supervisor itself (a bug)
    ventry el1_fault_entry
    ventry el1_fault_entry
    ventry el1_fault_entry
    ventry el1_fault_entry
    ventry el1_fault_entry
    ventry el1_fault_entry
    ventry el1_fault_entry
    ventry el0_sync_entry           // from the agent: system calls and faults
    ventry el1_fault_entry
    ventry el1_fault_entry
    ventry el1_fault_entry
    ventry el1_fault_entry
    ventry el1_fault_entry
    ventry el1_fault_entry
    ventry el1_fault_entry

el0_sync_entry:                     // save the agent's registers, call Rust, restore, return
    sub   sp, sp, #256
    stp   x0,  x1,  [sp, #0]
    stp   x2,  x3,  [sp, #16]
    stp   x4,  x5,  [sp, #32]
    stp   x6,  x7,  [sp, #48]
    stp   x8,  x9,  [sp, #64]
    stp   x10, x11, [sp, #80]
    stp   x12, x13, [sp, #96]
    stp   x14, x15, [sp, #112]
    stp   x16, x17, [sp, #128]
    stp   x18, x19, [sp, #144]
    stp   x20, x21, [sp, #160]
    stp   x22, x23, [sp, #176]
    stp   x24, x25, [sp, #192]
    stp   x26, x27, [sp, #208]
    stp   x28, x29, [sp, #224]
    str   x30,      [sp, #240]
    mov   x0, sp
    mrs   x1, esr_el1
    bl    el0_sync
    ldp   x0,  x1,  [sp, #0]
    ldp   x2,  x3,  [sp, #16]
    ldp   x4,  x5,  [sp, #32]
    ldp   x6,  x7,  [sp, #48]
    ldp   x8,  x9,  [sp, #64]
    ldp   x10, x11, [sp, #80]
    ldp   x12, x13, [sp, #96]
    ldp   x14, x15, [sp, #112]
    ldp   x16, x17, [sp, #128]
    ldp   x18, x19, [sp, #144]
    ldp   x20, x21, [sp, #160]
    ldp   x22, x23, [sp, #176]
    ldp   x24, x25, [sp, #192]
    ldp   x26, x27, [sp, #208]
    ldp   x28, x29, [sp, #224]
    ldr   x30,      [sp, #240]
    add   sp, sp, #256
    eret

el1_fault_entry:
    mrs   x0, esr_el1
    mrs   x1, elr_el1
    mrs   x2, far_el1
    bl    el1_fault
"#,
    stack_top = const SUP_STACK_TOP,
);

#[repr(C)]
pub struct TrapFrame { x: [u64; 32] } // x0..x30 + padding, laid out by el0_sync_entry

// ------------------------------- start-up -----------------------------------------------------
#[unsafe(no_mangle)]
extern "C" fn sup_main() -> ! {
    // MMU, caches, EL0 may use DC ZVA + CTR_EL0, and WXN: any writable page is never executable,
    // whatever its page-table entry says (a second lock behind the VMM's W^X page tables).
    const SCTLR_BITS: u64 = 1 | (1 << 2) | (1 << 12) | (1 << 14) | (1 << 15) | (1 << 19);
    unsafe {
        asm!("ldr {0}, =vectors", "msr vbar_el1, {0}", out(reg) _); // 1. the door
        asm!(
            "msr cpacr_el1, {fpen}",          // 2a. let the agent's compiled code use FP/SIMD
            "msr mair_el1, {mair}",           // 2b. memory types: 0 = normal, 1 = device
            "msr tcr_el1, {tcr}",             //     4 KiB pages, 39-bit addresses, 40-bit physical
            "msr ttbr0_el1, {ttbr}",          //     our page tables
            "isb",
            "tlbi vmalle1",
            "dsb nsh",
            "isb",
            "mrs {tmp}, sctlr_el1",
            "orr {tmp}, {tmp}, {bits}",
            "msr sctlr_el1, {tmp}",           //     MMU on
            "isb",
            fpen = in(reg) 3u64 << 20,
            mair = in(reg) 0x00ffu64,
            tcr = in(reg) 0x2_0080_3519u64,
            ttbr = in(reg) PT_L1,
            bits = in(reg) SCTLR_BITS,
            tmp = out(reg) _,
        );
    }
    let b = boot();
    BRK.store(b.brk_start, Relaxed);
    MMAP_NEXT.store(b.mmap_start, Relaxed);
    let s = state();
    for (fd, kind) in [K_STDIN, K_STDOUT, K_STDERR].into_iter().enumerate() {
        let o = new_ofd(s, kind, fd as u64, if fd == 0 { 0 } else { 1 }, b"").unwrap();
        install(s, o, fd as u64);
    }
    set_path(&mut s.cwd, if read_allowed(b"/workspace") { b"/workspace" } else { b"/" });
    if tmp_enabled() {
        s.tmp_next = b.tmp_lo;
        tmp_create_root(s);
    }
    if b.selftest != 0 { selftest(b.selftest); }
    if b.warm != 0 {
        // A warm sandbox: touch the pages the program is about to use, so KVM maps them now and not
        // one fault at a time during the call. Then wait (in the VMM) for the request, which writes
        // the program's arguments and stack pointer into the boot record.
        if b.warm == 1 { prefault(b); } // 2: warm without pre-mapping (for measuring)
        hypercall(HC_READY, 0, 0, 0);
    }
    let (entry, sp) = unsafe { (core::ptr::read_volatile(&b.entry), core::ptr::read_volatile(&b.sp)) };
    // The CPU counter starts near zero for each VM; the VMM wrote the real time just before we ran.
    let (secs, nanos) = now();
    let wall = unsafe { core::ptr::read_volatile(&b.wall_ns) };
    WALL_OFFSET_NS.store(wall.saturating_sub(secs * 1_000_000_000 + nanos), Relaxed);
    unsafe {
        asm!(
            "msr elr_el1, x9",                // 3. where eret goes: the agent's entry point
            "msr sp_el0, x10",                //    its stack (argc, argv, auxv: built by the VMM)
            "msr spsr_el1, x11",              //    level 3, interrupts masked
            "mov x0, xzr", "mov x1, xzr", "mov x2, xzr", "mov x3, xzr", "mov x4, xzr", "mov x5, xzr",
            "mov x6, xzr", "mov x7, xzr", "mov x8, xzr", "mov x9, xzr", "mov x10, xzr", "mov x11, xzr",
            "mov x29, xzr", "mov x30, xzr",
            "eret",
            in("x9") entry, in("x10") sp, in("x11") 0x3c0u64,
            options(noreturn),
        );
    }
}

/// `vmm --supervisor-selftest N`: the supervisor attacks its own memory, as an attacker who found a
/// bug in it would. Each attack must end in a fault (the VMM reports "supervisor fault").
fn selftest(n: u64) {
    let code = sup_main as *const () as u64;
    unsafe {
        match n {
            1 => (code as *mut u32).write_volatile(0xd503201f),               // patch our own code
            2 => (POLICY as *mut u8).write_volatile(1),                      // allow every system call
            3 => (PT_L1 as *mut u64).write_volatile(0),                      // edit the page tables
            4 => ((BOOT_INFO + 8) as *mut u64).write_volatile(0),            // change the boot record
            5 => { // write an instruction into our data, then jump to it
                let at = STATE as *mut u32;
                at.write_volatile(0xd65f03c0); // ret
                let f: extern "C" fn() = core::mem::transmute(at);
                f();
            }
            6 => ((SUP_STACK_TOP - SUP_STACK_SIZE - 8) as *mut u64).write_volatile(0), // just below our stack
            7 => { core::ptr::read_volatile(0x8090_0000 as *const u64); }  // a gap between our regions
            8 => { let at = "a constant string".as_ptr() as u64; (at as *mut u8).write_volatile(0); } // our constants
            _ => {}
        }
    }
    panic!("selftest {n} SURVIVED");
}

/// Map pages ahead of time: read the program's pages (they hold its code and data already) and
/// write a zero into the first pages of the heap, the mmap area and the stack (fresh memory).
fn prefault(b: &BootInfo) {
    let mapped = |page: u64| { let par: u64; unsafe { asm!("at s1e1r, {0}", "isb", "mrs {1}, par_el1", in(reg) page, out(reg) par) }; par & 1 == 0 };
    let mut page = b.elf_lo & !0xfff;
    while page < b.elf_hi {
        if mapped(page) { unsafe { core::ptr::read_volatile(page as *const u8); } }
        page += 4096;
    }
    let write = |lo: u64, hi: u64| { let mut p = lo; while p < hi { unsafe { (p as *mut u8).write_volatile(0) }; p += 4096; } };
    write(b.brk_start, (b.brk_start + (128 << 10)).min(b.brk_end));
    write(b.mmap_start, (b.mmap_start + (512 << 10)).min(b.mmap_end));
    write(b.stack_hi - (32 << 10), b.stack_hi);
    write(LOG_BASE + 4096, LOG_BASE + (16 << 10)); // our audit log and path copies, the first pages
    write(PATH_LOG, PATH_LOG + (8 << 10));
}

// ------------------------------- the door: everything the agent needs level 0 for -------------
#[unsafe(no_mangle)]
extern "C" fn el0_sync(tf: &mut TrapFrame, esr: u64) {
    if esr >> 26 != 0x15 {
        // Not a system call: the CPU blocked something (bad memory access, illegal instruction...).
        let (far, elr): (u64, u64);
        unsafe { asm!("mrs {0}, far_el1", "mrs {1}, elr_el1", out(reg) far, out(reg) elr) };
        log(FAULT, esr, far, elr, 0, 0);
        hypercall(HC_FAULT, esr, far, elr);
        loop {}
    }
    let (nr, a0, a1, a2) = (tf.x[8], tf.x[0], tf.x[1], tf.x[2]);
    if nr == 93 || nr == 94 {
        log(EXIT, a0, 0, 0, 0, 0); // exit, exit_group
        hypercall(HC_EXIT, a0, 0, 0);
        loop {}
    }
    // The policy (data from the VMM) decides first; only allowed calls reach our handlers.
    LAST_PATH.store(0, Relaxed);
    EXITED.store(false, Relaxed);
    let action = policy_action(nr);
    if action != ALLOW {
        if let Some(i) = path_arg(nr) { let _ = copy_path(tf.x[i]); } // keep a copy for the notebook
    }
    let result = match action {
        ALLOW => syscall(state(), nr, &tf.x),
        DENY => -(policy_errno(nr) as i64),
        _ => -ENOSYS,
    };
    // Which bucket: did it leave the VM? Otherwise, was it a refusal, or an answer?
    let bucket = if EXITED.load(Relaxed) { FORWARDED }
        else if action != ALLOW || matches!(-result, EACCES | EPERM | EFAULT | ENOSYS | ENAMETOOLONG) { REFUSED }
        else { ANSWERED };
    let path = LAST_PATH.load(Relaxed);
    let a1 = if path != 0 { path } else { a1 }; // path calls: log our copy of the path
    log(bucket, nr, a0, a1, a2, result as u64);
    tf.x[0] = result as u64; // the agent sees the result in x0
}

/// Which argument is a path, for the notebook (openat, newfstatat, ... take it second).
fn path_arg(nr: u64) -> Option<usize> {
    match nr { 49 => Some(0), 34 | 35 | 38 | 48 | 56 | 78 | 79 | 276 | 439 => Some(1), _ => None }
}

fn syscall(s: &mut State, nr: u64, x: &[u64; 32]) -> i64 {
    let a = |i: usize| x[i];
    match nr {
        // ---------------- who am I, limits, signals: answered here ----------------
        96 => 1,                                      // set_tid_address: "your thread id is 1"
        172 | 178 => 1,                               // getpid, gettid
        173 => 0,                                     // getppid: nobody started us
        174..=177 => 1000,                            // getuid, geteuid, getgid, getegid
        144 | 146 => if a(0) == 1000 { 0 } else { -EPERM }, // setgid, setuid: only to what we already are
        148 | 150 => put_ids(&[a(0), a(1), a(2)]),    // getresuid, getresgid
        155 | 157 => 1, 154 => 0,                     // getpgid, setsid, setpgid
        166 => 0o022,                                 // umask
        160 => uname(a(0)),
        261 => prlimit(a(0), a(1), a(2), a(3)),
        163 => prlimit(0, a(0), 0, a(1)),             // getrlimit
        129 => kill(a(0) as i32, a(1)),               // only ourselves: abort(), raise()
        130 => kill(if a(0) == 1 { 1 } else { -9 }, a(1)), // tkill(tid, sig)
        131 => kill(if a(1) == 1 { a(0) as i32 } else { -9 }, a(2)), // tgkill(pid, tid, sig)

        // ---------------- memory, signal setup, clock: answered here ----------------
        214 => brk(a(0)),
        222 => mmap(a(1), a(3), a(4) as i64),
        215 | 226 | 233 => 0,                         // munmap, mprotect, madvise: accepted
        134 => zero_out(a(2), 32),                    // rt_sigaction: no signals here; "old" = default
        135 => zero_out(a(2), 8),                     // rt_sigprocmask
        132 => sigaltstack(a(1)),
        113 => clock_gettime(a(0), a(1)),
        73 => ppoll(s, a(0), a(1)),
        124 => 0,                                     // sched_yield
        158 => 0,                                     // getgroups: no extra groups
        123 => affinity(a(1), a(2)),                  // sched_getaffinity: one CPU
        179 => sysinfo(a(0)),
        165 => zero_out(a(1), 144),                   // getrusage: nothing to report
        29 => -ENOTTY,                                // ioctl: "not a terminal"

        // ---------------- files: our fd table; /tmp lives here, /workspace is forwarded ----------
        56 => openat(s, a(0), a(1), a(2)),
        63 => read(s, a(0), a(1), a(2)),
        64 => write(s, a(0), a(1), a(2)),
        65 => vec_io(s, a(0), a(1), a(2), false),     // readv
        66 => vec_io(s, a(0), a(1), a(2), true),      // writev
        57 => close(s, a(0)),
        62 => lseek(s, a(0), a(1) as i64, a(2)),
        80 => fstat(s, a(0), a(1)),
        79 => fstatat(s, a(0), a(1), a(2), a(3)),     // newfstatat: stat, lstat
        48 | 439 => faccessat(s, a(0), a(1), a(2)),   // faccessat, faccessat2
        78 => readlinkat(s, a(0), a(1), a(2), a(3)),
        61 => getdents(s, a(0), a(1), a(2)),
        17 => getcwd(s, a(0), a(1)),
        49 => chdir(s, a(0)),
        50 => fchdir(s, a(0)),
        23 => match ofd_index(s, a(0)) { Some(o) => install(s, o, 0), None => -EBADF }, // dup
        24 => dup3(s, a(0), a(1)),
        25 => fcntl(s, a(0), a(1), a(2)),
        46 => ftruncate(s, a(0), a(1)),
        82 | 83 => if ofd_index(s, a(0)).is_some() { 0 } else { -EBADF }, // fsync, fdatasync
        34 => mkdirat(s, a(0), a(1)),
        35 => unlinkat(s, a(0), a(1), a(2)),
        38 => renameat(s, a(0), a(1), a(2), a(3), 0),
        276 => renameat(s, a(0), a(1), a(2), a(3), a(4)),

        // ---------------- forwarded: randomness, sleeping ----------------
        278 => getrandom(a(0), a(1)),
        101 => sleep(a(0)),                           // nanosleep(req, rem)
        115 if a(1) & 1 == 0 => sleep(a(2)),          // clock_nanosleep(clock, flags, req, rem), relative only

        // Anything the policy allows but we have no handler for is refused honestly.
        _ => -ENOSYS,
    }
}

// ------------------------------- the policy (data written by the VMM) -------------------------
fn policy_action(nr: u64) -> u8 {
    if nr < 512 { unsafe { ((POLICY + nr) as *const u8).read_volatile() } } else { 0 }
}
fn policy_errno(nr: u64) -> u8 {
    unsafe { ((POLICY + 512 + nr) as *const u8).read_volatile() } // only called when nr < 512
}
/// May the agent read this (clean, absolute) path? It must start with one of the policy's read
/// prefixes, or be the prefix's folder itself ("/workspace" for "/workspace/").
fn read_allowed(path: &[u8]) -> bool {
    let count = unsafe { ((POLICY + 1024) as *const u64).read_volatile() }.min(8);
    (0..count).any(|i| {
        let p = (POLICY + 1088 + i * 128) as *const u8;
        let len = (0..127).take_while(|&j| unsafe { p.add(j).read_volatile() } != 0).count();
        let prefix = unsafe { core::slice::from_raw_parts(p, len) };
        len > 0 && (path.starts_with(prefix) || (prefix.ends_with(b"/") && path == &prefix[..len - 1]))
    })
}

// ------------------------------- answered: identity, limits, signals -------------------------
fn put_ids(ptrs: &[u64]) -> i64 {
    for &p in ptrs {
        if !user_writable(p, 4) { return -EFAULT; }
        unsafe { (p as *mut u32).write_volatile(1000) }
    }
    0
}

fn uname(buf: u64) -> i64 {
    if !user_writable(buf, 390) { return -EFAULT; }
    let fields: [&[u8]; 6] = [b"Linux", b"sandbox", b"6.1.0-supervisor", b"#1", b"aarch64", b"(none)"];
    for (i, f) in fields.iter().enumerate() {
        let at = (buf + i as u64 * 65) as *mut u8;
        for j in 0..65 { unsafe { at.add(j).write_volatile(*f.get(j).unwrap_or(&0)) } }
    }
    0
}

fn prlimit(pid: u64, resource: u64, new: u64, old: u64) -> i64 {
    if pid != 0 && pid != 1 { return -ESRCH; }
    if new != 0 { return -EPERM; } // limits come from the policy, not from the agent
    if old != 0 {
        if !user_writable(old, 16) { return -EFAULT; }
        let v = match resource { 3 => 4 << 20, 7 => MAX_FDS as u64, _ => u64::MAX }; // stack, open files
        unsafe { (old as *mut u64).write_volatile(v); ((old + 8) as *mut u64).write_volatile(v) }
    }
    0
}

/// Signals: there is only us. A signal to ourselves ends the program the way Linux's default
/// action would (exit status 128 + signal); harmless ones are ignored.
fn kill(pid: i32, sig: u64) -> i64 {
    if pid != 0 && pid != 1 && pid != -1 { return -ESRCH; }
    if sig > 64 { return -EINVAL; }
    if sig == 0 || matches!(sig, 17 | 18 | 23 | 28) { return 0; } // probe, SIGCHLD, SIGCONT, SIGURG, SIGWINCH
    log(EXIT, 128 + sig, 0, 0, 0, 0);
    hypercall(HC_EXIT, 128 + sig, 0, 0);
    loop {}
}

// ------------------------------- answered: memory, signal setup, clock ------------------------
fn brk(request: u64) -> i64 {
    let b = boot();
    if request >= b.brk_start && request <= b.brk_end {
        BRK.store(request, Relaxed);
    }
    BRK.load(Relaxed) as i64 // like Linux: always return the current break
}

fn mmap(len: u64, flags: u64, fd: i64) -> i64 {
    const MAP_FIXED: u64 = 0x10;
    const MAP_ANONYMOUS: u64 = 0x20;
    if flags & MAP_ANONYMOUS == 0 || fd != -1 {
        return -EACCES; // mapping files: not offered
    }
    if flags & MAP_FIXED != 0 || len == 0 {
        return -EINVAL;
    }
    let Some(len) = len.checked_add(4095).map(|l| l & !4095) else { return -ENOMEM };
    let start = MMAP_NEXT.load(Relaxed);
    match start.checked_add(len) {
        Some(end) if end <= boot().mmap_end => {
            MMAP_NEXT.store(end, Relaxed); // fresh, never reused, so it is still all zeros
            start as i64
        }
        _ => -ENOMEM,
    }
}

fn zero_out(ptr: u64, len: u64) -> i64 {
    if ptr != 0 {
        if !user_writable(ptr, len) { return -EFAULT; }
        for i in 0..len { unsafe { ((ptr + i) as *mut u8).write_volatile(0) } }
    }
    0
}

fn sigaltstack(old: u64) -> i64 {
    if old != 0 {
        if !user_writable(old, 24) { return -EFAULT; }
        unsafe {
            (old as *mut u64).write_volatile(0); // ss_sp
            ((old + 8) as *mut u64).write_volatile(2); // ss_flags = SS_DISABLE
            ((old + 16) as *mut u64).write_volatile(0); // ss_size
        }
    }
    0
}

fn now() -> (u64, u64) {
    let (ticks, freq): (u64, u64);
    unsafe { asm!("mrs {0}, cntvct_el0", "mrs {1}, cntfrq_el0", out(reg) ticks, out(reg) freq) };
    (ticks / freq, (ticks % freq) * 1_000_000_000 / freq)
}

fn clock_gettime(clock: u64, ts: u64) -> i64 {
    if !user_writable(ts, 16) { return -EFAULT; }
    let (mut secs, mut nanos) = now();
    if matches!(clock, 0 | 5 | 11) { // CLOCK_REALTIME, _COARSE, CLOCK_TAI: wall time
        let t = secs * 1_000_000_000 + nanos + WALL_OFFSET_NS.load(Relaxed);
        (secs, nanos) = (t / 1_000_000_000, t % 1_000_000_000);
    }
    unsafe {
        (ts as *mut u64).write_volatile(secs);
        ((ts + 8) as *mut u64).write_volatile(nanos);
    }
    0
}

/// poll: every open fd is always ready (files, end-of-input stdin, the VMM's stdout), so it never
/// waits. A closed fd reports POLLNVAL, as on Linux.
fn ppoll(s: &State, fds: u64, nfds: u64) -> i64 {
    const POLLIN: u16 = 1; const POLLOUT: u16 = 4; const POLLNVAL: u16 = 0x20;
    if nfds > 64 || !user_writable(fds, nfds * 8) { return -EFAULT; }
    let mut ready = 0;
    for i in 0..nfds {
        let at = fds + i * 8;
        let (fd, events) = unsafe { ((at as *const i32).read_volatile(), ((at + 4) as *const u16).read_volatile()) };
        let revents = if fd < 0 { 0 } else if ofd_index(s, fd as u64).is_none() { POLLNVAL } else { events & (POLLIN | POLLOUT) };
        unsafe { ((at + 6) as *mut u16).write_volatile(revents) };
        if revents != 0 { ready += 1; }
    }
    ready
}

fn affinity(len: u64, mask: u64) -> i64 {
    if len < 8 { return -EINVAL; }
    if !user_writable(mask, 8) { return -EFAULT; }
    unsafe { (mask as *mut u64).write_volatile(1) };
    8
}

/// Linux's arm64 `struct sysinfo`: memory is what the policy gives this agent.
fn sysinfo(buf: u64) -> i64 {
    if !user_writable(buf, 112) { return -EFAULT; }
    let b = boot();
    unsafe {
        core::ptr::write_bytes(buf as *mut u8, 0, 112);
        let w = |off: u64, v: u64| ((buf + off) as *mut u64).write_volatile(v);
        w(0, now().0);
        w(32, b.mmap_end - b.mmap_start);
        w(40, b.mmap_end - MMAP_NEXT.load(Relaxed));
        ((buf + 80) as *mut u16).write_volatile(1);
        ((buf + 104) as *mut u32).write_volatile(1);
    }
    0
}

// ------------------------------- paths --------------------------------------------------------
/// Copy a path from the agent into OUR memory (a fresh slot, kept for the notebook).
/// Checks then run on the copy: the agent can't change it afterwards. Returns its length.
fn copy_path(path: u64) -> Result<u64, i64> {
    let slot = PATH_NEXT.load(Relaxed);
    if slot + 512 <= PATH_LOG_END { PATH_NEXT.store(slot + 256, Relaxed); }
    LAST_PATH.store(slot, Relaxed);
    let text = slot as *mut u8;
    unsafe { text.write_volatile(0) };
    let mut len = 0u64;
    loop {
        if len == 255 { unsafe { text.add(255).write_volatile(0) }; return Err(-ENAMETOOLONG); }
        if !user_readable(path + len, 1) { unsafe { text.add(len as usize).write_volatile(0) }; return Err(-EFAULT); }
        let c = unsafe { ((path + len) as *const u8).read_volatile() };
        unsafe { text.add(len as usize).write_volatile(c) };
        if c == 0 { return Ok(len); }
        len += 1;
    }
}

fn cstr(buf: &[u8; PATH_MAX]) -> &[u8] { &buf[..buf.iter().position(|&c| c == 0).unwrap_or(PATH_MAX)] }
fn set_path(buf: &mut [u8; PATH_MAX], v: &[u8]) { buf[..v.len()].copy_from_slice(v); buf[v.len()] = 0; }

/// Append the parts of `text` to the clean path in out[..n]. "" and "." vanish; ".." removes the
/// last part, by text. So the result never contains "..", and what the prefix check sees is
/// exactly what gets opened.
fn push_parts(out: &mut [u8; PATH_MAX], n: &mut usize, text: &[u8]) -> Result<(), i64> {
    for part in text.split(|&c| c == b'/') {
        match part {
            b"" | b"." => {}
            b".." => { while *n > 0 && out[*n - 1] != b'/' { *n -= 1; } if *n > 0 { *n -= 1; } }
            _ => {
                if *n + 1 + part.len() >= PATH_MAX { return Err(-ENAMETOOLONG); }
                out[*n] = b'/';
                out[*n + 1..*n + 1 + part.len()].copy_from_slice(part);
                *n += 1 + part.len();
            }
        }
    }
    Ok(())
}

/// (dirfd, path) from the agent -> a clean absolute path in s.path (which = 0) or s.path2 (1).
fn resolve(s: &mut State, dirfd: u64, ptr: u64, which: usize) -> Result<usize, i64> {
    let len = copy_path(ptr)? as usize;
    if len == 0 { return Err(-ENOENT); }
    let raw = unsafe { core::slice::from_raw_parts(LAST_PATH.load(Relaxed) as *const u8, len) };
    let (mut out, mut n) = ([0u8; PATH_MAX], 0usize);
    if raw[0] != b'/' {
        if dirfd as i32 == AT_FDCWD {
            let cwd = s.cwd;
            push_parts(&mut out, &mut n, cstr(&cwd))?;
        } else {
            let o = ofd_index(s, dirfd).ok_or(-EBADF)?;
            if s.ofds[o].kind != K_HOST_DIR && s.ofds[o].kind != K_TMP_DIR { return Err(-ENOTDIR); }
            let base = s.ofds[o].path;
            push_parts(&mut out, &mut n, cstr(&base))?;
        }
    }
    push_parts(&mut out, &mut n, raw)?;
    if n == 0 { out[0] = b'/'; n = 1; }
    set_path(if which == 0 { &mut s.path } else { &mut s.path2 }, &out[..n]);
    Ok(n)
}

/// A folder above what the agent may see ("/" for "/workspace/" and "/tmp"). `stat` on it gets a
/// made-up empty folder: tools like `ls -la` want one, and it reveals nothing.
fn is_ancestor(path: &[u8]) -> bool {
    let above = |dir: &[u8]| path == b"/" || (dir.starts_with(path) && dir.get(path.len()) == Some(&b'/'));
    let count = unsafe { ((POLICY + 1024) as *const u64).read_volatile() }.min(8);
    (tmp_enabled() && above(b"/tmp")) || (0..count).any(|i| {
        let p = (POLICY + 1088 + i * 128) as *const u8;
        let len = (0..127).take_while(|&j| unsafe { p.add(j).read_volatile() } != 0).count();
        let prefix = unsafe { core::slice::from_raw_parts(p, len) };
        above(prefix.strip_suffix(b"/").unwrap_or(prefix))
    })
}

fn tmp_enabled() -> bool { boot().tmp_hi > boot().tmp_lo }
fn under(path: &[u8], dir: &[u8]) -> bool { path == dir || (path.starts_with(dir) && path.get(dir.len()) == Some(&b'/')) }
fn in_tmp(path: &[u8]) -> bool { tmp_enabled() && under(path, b"/tmp") }
fn parent(path: &[u8]) -> &[u8] {
    match path.iter().rposition(|&c| c == b'/') { Some(0) | None => b"/", Some(i) => &path[..i] }
}

/// Forward a path request to the VMM: it gets our clean copy, never the agent's memory.
fn host_path_call(path: &[u8], op: u64, b: u64, c: u64) -> i64 {
    for (i, &ch) in path.iter().chain(&[0u8]).enumerate() {
        unsafe { (HC_TEXT as *mut u8).add(i).write_volatile(ch) }
    }
    hypercall(op, HC_TEXT, b, c)
}

// ------------------------------- the fd table ------------------------------------------------
fn ofd_index(s: &State, fd: u64) -> Option<usize> {
    let slot = *s.fds.get(fd as usize)?;
    if slot == 0 { None } else { Some(slot as usize - 1) }
}

fn new_ofd(s: &mut State, kind: u8, handle: u64, flags: u64, path: &[u8]) -> Option<usize> {
    let i = s.ofds.iter().position(|o| o.refs == 0)?;
    let o = &mut s.ofds[i];
    (o.kind, o.mode, o.append, o.handle, o.offset) = (kind, (flags & 3) as u8, (flags & O_APPEND != 0) as u8, handle, 0);
    set_path(&mut o.path, path);
    Some(i)
}

/// Give the open file `o` the lowest free fd >= min.
fn install(s: &mut State, o: usize, min: u64) -> i64 {
    match (min as usize..MAX_FDS).find(|&fd| s.fds[fd] == 0) {
        Some(fd) => { s.fds[fd] = o as u16 + 1; s.ofds[o].refs += 1; fd as i64 }
        None => { if s.ofds[o].refs == 0 { drop_ofd(s, o) } -EMFILE }
    }
}

fn drop_ofd(s: &mut State, o: usize) {
    let (kind, handle) = (s.ofds[o].kind, s.ofds[o].handle);
    (s.ofds[o].kind, s.ofds[o].refs) = (K_FREE, 0);
    match kind {
        K_HOST | K_HOST_DIR => { hypercall(HC_CLOSE, handle, 0, 0); }
        K_TMP | K_TMP_DIR => free_if_unused(s, handle as usize),
        _ => {}
    }
}

fn close(s: &mut State, fd: u64) -> i64 {
    let Some(o) = ofd_index(s, fd) else { return -EBADF };
    s.fds[fd as usize] = 0;
    s.ofds[o].refs -= 1;
    if s.ofds[o].refs == 0 { drop_ofd(s, o); }
    0
}

fn dup3(s: &mut State, old: u64, new: u64) -> i64 {
    let Some(o) = ofd_index(s, old) else { return -EBADF };
    if old == new { return -EINVAL; }
    if new as usize >= MAX_FDS { return -EBADF; }
    if s.fds[new as usize] != 0 { close(s, new); }
    s.fds[new as usize] = o as u16 + 1;
    s.ofds[o].refs += 1;
    new as i64
}

fn fcntl(s: &mut State, fd: u64, cmd: u64, arg: u64) -> i64 {
    let Some(o) = ofd_index(s, fd) else { return -EBADF };
    match cmd {
        0 | 1030 => if arg as usize >= MAX_FDS { -EINVAL } else { install(s, o, arg) }, // F_DUPFD(_CLOEXEC)
        1 | 2 => 0,                                                                      // F_GETFD, F_SETFD
        3 => s.ofds[o].mode as i64 | if s.ofds[o].append != 0 { O_APPEND as i64 } else { 0 }, // F_GETFL
        4 => { s.ofds[o].append = (arg & O_APPEND != 0) as u8; 0 }                       // F_SETFL
        _ => -EINVAL,
    }
}

// ------------------------------- file system calls -------------------------------------------
fn openat(s: &mut State, dirfd: u64, path: u64, flags: u64) -> i64 {
    let n = match resolve(s, dirfd, path, 0) { Ok(n) => n, Err(e) => return e };
    let buf = s.path;
    let p = &buf[..n];
    if in_tmp(p) { return tmp_open(s, p, flags); }
    if !read_allowed(p) { return -EACCES; }
    if flags & (O_ACCMODE | O_CREAT | O_TRUNC) != 0 { return -EACCES; } // the workspace is read-only
    let r = host_path_call(p, HC_OPEN, flags & O_DIRECTORY, 0);
    if r < 0 { return r; }
    let (handle, kind) = (r as u64 & 0xffff_ffff, if r >> 32 & 1 == 1 { K_HOST_DIR } else { K_HOST });
    match new_ofd(s, kind, handle, 0, p) {
        Some(o) => install(s, o, 0),
        None => { hypercall(HC_CLOSE, handle, 0, 0); -EMFILE }
    }
}

fn read(s: &mut State, fd: u64, buf: u64, len: u64) -> i64 {
    let Some(o) = ofd_index(s, fd) else { return -EBADF };
    if !user_writable(buf, len) { return -EFAULT; }
    let (kind, mode, handle) = (s.ofds[o].kind, s.ofds[o].mode, s.ofds[o].handle);
    match kind {
        K_STDIN => 0, // no input: end of file
        K_HOST => hypercall(HC_READ, handle, buf, len),
        K_TMP if mode != 1 => {
            let node = &s.nodes[handle as usize];
            let off = s.ofds[o].offset;
            let count = len.min(node.size.saturating_sub(off));
            unsafe { core::ptr::copy((node.data + off) as *const u8, buf as *mut u8, count as usize) };
            s.ofds[o].offset += count;
            count as i64
        }
        K_HOST_DIR | K_TMP_DIR => -EISDIR,
        _ => -EBADF,
    }
}

fn write(s: &mut State, fd: u64, buf: u64, len: u64) -> i64 {
    let Some(o) = ofd_index(s, fd) else { return -EBADF };
    if !user_readable(buf, len) { return -EFAULT; }
    match s.ofds[o].kind {
        K_STDOUT | K_STDERR => hypercall(HC_WRITE, buf, len, 0),
        K_TMP if s.ofds[o].mode != 0 => tmp_write(s, o, buf, len),
        _ => -EBADF,
    }
}

fn vec_io(s: &mut State, fd: u64, iov: u64, count: u64, writing: bool) -> i64 {
    if count > 64 || !user_readable(iov, count * 16) { return -EFAULT; }
    let mut total = 0i64;
    for i in 0..count {
        let (base, len) = unsafe { (((iov + i * 16) as *const u64).read_volatile(), ((iov + i * 16 + 8) as *const u64).read_volatile()) };
        if len == 0 { continue; }
        let r = if writing { write(s, fd, base, len) } else { read(s, fd, base, len) };
        if r < 0 { return if total > 0 { total } else { r }; }
        total += r;
        if (r as u64) < len { break; }
    }
    total
}

fn lseek(s: &mut State, fd: u64, off: i64, whence: u64) -> i64 {
    let Some(o) = ofd_index(s, fd) else { return -EBADF };
    let (kind, handle) = (s.ofds[o].kind, s.ofds[o].handle);
    match kind {
        K_HOST | K_HOST_DIR => hypercall(HC_LSEEK, handle, off as u64, whence),
        K_TMP | K_TMP_DIR => {
            let base = match whence { 0 => 0, 1 => s.ofds[o].offset as i64, 2 if kind == K_TMP => s.nodes[handle as usize].size as i64, _ => return -EINVAL };
            match base.checked_add(off) {
                Some(pos) if pos >= 0 => { s.ofds[o].offset = pos as u64; pos }
                _ => -EINVAL,
            }
        }
        _ => -ESPIPE,
    }
}

/// Linux's arm64 `struct stat`, 128 bytes.
fn put_stat(buf: u64, dev: u64, ino: u64, mode: u32, size: u64, mtime: u64) {
    unsafe {
        core::ptr::write_bytes(buf as *mut u8, 0, 128);
        let w64 = |off: u64, v: u64| ((buf + off) as *mut u64).write_volatile(v);
        let w32 = |off: u64, v: u32| ((buf + off) as *mut u32).write_volatile(v);
        w64(0, dev); w64(8, ino); w32(16, mode); w32(20, if mode & S_IFMT == S_IFDIR { 2 } else { 1 });
        w32(24, 1000); w32(28, 1000); w64(48, size); w32(56, 4096); w64(64, size.div_ceil(512));
        w64(72, mtime); w64(88, mtime); w64(104, mtime);
    }
}

fn node_stat(s: &State, n: usize, buf: u64) {
    let node = &s.nodes[n];
    let mode = if node.dir != 0 { S_IFDIR | 0o755 } else { S_IFREG | 0o644 };
    put_stat(buf, 2, n as u64 + 1, mode, node.size, node.mtime);
}

fn fstat(s: &mut State, fd: u64, buf: u64) -> i64 {
    let Some(o) = ofd_index(s, fd) else { return -EBADF };
    if !user_writable(buf, 128) { return -EFAULT; }
    let (kind, handle) = (s.ofds[o].kind, s.ofds[o].handle);
    match kind {
        K_HOST | K_HOST_DIR => hypercall(HC_FSTAT, handle, buf, 0),
        K_TMP | K_TMP_DIR => { node_stat(s, handle as usize, buf); 0 }
        _ => { put_stat(buf, 3, fd, S_IFCHR | 0o620, 0, 0); 0 } // stdin, stdout, stderr: a terminal-like device
    }
}

fn fstatat(s: &mut State, dirfd: u64, path: u64, buf: u64, flags: u64) -> i64 {
    if !user_writable(buf, 128) { return -EFAULT; }
    if flags & AT_EMPTY_PATH != 0 && user_readable(path, 1) && unsafe { (path as *const u8).read_volatile() } == 0 {
        return fstat(s, dirfd, buf);
    }
    let n = match resolve(s, dirfd, path, 0) { Ok(n) => n, Err(e) => return e };
    let pbuf = s.path;
    let p = &pbuf[..n];
    if in_tmp(p) {
        return match find_node(s, p) { Some(i) => { node_stat(s, i, buf); 0 } None => -ENOENT };
    }
    if is_ancestor(p) { put_stat(buf, 4, 2, S_IFDIR | 0o755, 0, 0); return 0; } // "/", for `ls -la /workspace`: an empty folder
    if !read_allowed(p) { return -EACCES; }
    let r = host_path_call(p, HC_STAT, buf, (flags & AT_SYMLINK_NOFOLLOW != 0) as u64);
    if r < 0 { r } else { 0 }
}

fn faccessat(s: &mut State, dirfd: u64, path: u64, mode: u64) -> i64 {
    let n = match resolve(s, dirfd, path, 0) { Ok(n) => n, Err(e) => return e };
    let pbuf = s.path;
    let p = &pbuf[..n];
    if in_tmp(p) { return if find_node(s, p).is_some() { 0 } else { -ENOENT }; }
    if !read_allowed(p) { return -EACCES; }
    let m = host_path_call(p, HC_STAT, 0, 0);
    if m < 0 { return m; }
    if mode & 2 != 0 { return -EROFS; }                       // W_OK: the workspace is read-only
    if mode & 1 != 0 && m & 0o111 == 0 { return -EACCES; }   // X_OK
    0
}

fn readlinkat(s: &mut State, dirfd: u64, path: u64, buf: u64, len: u64) -> i64 {
    if !user_writable(buf, len) { return -EFAULT; }
    let n = match resolve(s, dirfd, path, 0) { Ok(n) => n, Err(e) => return e };
    let pbuf = s.path;
    let p = &pbuf[..n];
    if in_tmp(p) { return -EINVAL; } // no symbolic links in /tmp
    if !read_allowed(p) { return -EACCES; }
    host_path_call(p, HC_READLINK, buf, len)
}

fn getdents(s: &mut State, fd: u64, buf: u64, len: u64) -> i64 {
    let Some(o) = ofd_index(s, fd) else { return -EBADF };
    if !user_writable(buf, len) { return -EFAULT; }
    match s.ofds[o].kind {
        K_HOST_DIR => hypercall(HC_GETDENTS, s.ofds[o].handle, buf, len),
        K_TMP_DIR => tmp_getdents(s, o, buf, len),
        _ => -ENOTDIR,
    }
}

fn getcwd(s: &mut State, buf: u64, size: u64) -> i64 {
    let cwd = s.cwd;
    let c = cstr(&cwd);
    let need = c.len() as u64 + 1;
    if size < need { return -ERANGE; }
    if !user_writable(buf, need) { return -EFAULT; }
    for (i, &ch) in c.iter().chain(&[0u8]).enumerate() { unsafe { (buf as *mut u8).add(i).write_volatile(ch) } }
    need as i64
}

fn chdir(s: &mut State, path: u64) -> i64 {
    let n = match resolve(s, AT_FDCWD as u64, path, 0) { Ok(n) => n, Err(e) => return e };
    let pbuf = s.path;
    let p = &pbuf[..n];
    if in_tmp(p) {
        match find_node(s, p) { Some(i) if s.nodes[i].dir != 0 => {} Some(_) => return -ENOTDIR, None => return -ENOENT }
    } else if read_allowed(p) {
        let m = host_path_call(p, HC_STAT, 0, 0);
        if m < 0 { return m; }
        if m as u32 & S_IFMT != S_IFDIR { return -ENOTDIR; }
    } else {
        return -EACCES;
    }
    set_path(&mut s.cwd, p);
    0
}

fn fchdir(s: &mut State, fd: u64) -> i64 {
    let Some(o) = ofd_index(s, fd) else { return -EBADF };
    if s.ofds[o].kind != K_HOST_DIR && s.ofds[o].kind != K_TMP_DIR { return -ENOTDIR; }
    s.cwd = s.ofds[o].path;
    0
}

fn ftruncate(s: &mut State, fd: u64, len: u64) -> i64 {
    let Some(o) = ofd_index(s, fd) else { return -EBADF };
    if s.ofds[o].kind != K_TMP || s.ofds[o].mode == 0 { return -EINVAL; }
    match tmp_set_size(s, s.ofds[o].handle as usize, len) { Ok(()) => 0, Err(e) => e }
}

fn mkdirat(s: &mut State, dirfd: u64, path: u64) -> i64 {
    let n = match resolve(s, dirfd, path, 0) { Ok(n) => n, Err(e) => return e };
    let pbuf = s.path;
    let p = &pbuf[..n];
    if in_tmp(p) {
        if find_node(s, p).is_some() { return -EEXIST; }
        return match tmp_create(s, p, true) { Ok(_) => 0, Err(e) => e };
    }
    // `mkdir -p /tmp/a` starts with "/": folders that exist must say so, not "permission denied".
    if is_ancestor(p) || (read_allowed(p) && host_path_call(p, HC_STAT, 0, 0) >= 0) { return -EEXIST; }
    if read_allowed(p) { -EROFS } else { -EACCES } // the workspace is read-only, everything else doesn't exist for the agent
}

fn unlinkat(s: &mut State, dirfd: u64, path: u64, flags: u64) -> i64 {
    let n = match resolve(s, dirfd, path, 0) { Ok(n) => n, Err(e) => return e };
    let pbuf = s.path;
    let p = &pbuf[..n];
    if !in_tmp(p) { return -EACCES; }
    let Some(i) = find_node(s, p) else { return -ENOENT };
    if i == 0 { return -EBUSY; } // /tmp itself
    if flags & AT_REMOVEDIR != 0 {
        if s.nodes[i].dir == 0 { return -ENOTDIR; }
        if has_children(s, p) { return -ENOTEMPTY; }
    } else if s.nodes[i].dir != 0 {
        return -EISDIR;
    }
    remove_node(s, i);
    0
}

fn renameat(s: &mut State, olddir: u64, old: u64, newdir: u64, new: u64, flags: u64) -> i64 {
    const RENAME_NOREPLACE: u64 = 1;
    if flags & !RENAME_NOREPLACE != 0 { return -EINVAL; }
    let n1 = match resolve(s, olddir, old, 0) { Ok(n) => n, Err(e) => return e };
    let n2 = match resolve(s, newdir, new, 1) { Ok(n) => n, Err(e) => return e };
    let (b1, b2) = (s.path, s.path2);
    let (from, to) = (&b1[..n1], &b2[..n2]);
    if !in_tmp(from) || !in_tmp(to) { return -EACCES; } // only inside /tmp: nothing leaves, nothing comes in
    let Some(src) = find_node(s, from) else { return -ENOENT };
    if src == 0 || to == b"/tmp" { return -EBUSY; }
    if from == to { return 0; }
    if under(to, from) { return -EINVAL; } // a folder into itself
    match find_node(s, parent(to)) { Some(d) if s.nodes[d].dir != 0 => {} Some(_) => return -ENOTDIR, None => return -ENOENT }
    if let Some(dst) = find_node(s, to) {
        if flags & RENAME_NOREPLACE != 0 { return -EEXIST; }
        match (s.nodes[src].dir != 0, s.nodes[dst].dir != 0) {
            (true, false) => return -ENOTDIR,
            (false, true) => return -EISDIR,
            (true, true) if has_children(s, to) => return -ENOTEMPTY,
            _ => {}
        }
        remove_node(s, dst);
    }
    // Every node at or below `from` moves; check all new names fit before changing anything.
    let moved = |p: &[u8]| under(p, from);
    if s.nodes.iter().any(|nd| nd.used != 0 && moved(cstr(&nd.path)) && cstr(&nd.path).len() - from.len() + to.len() >= PATH_MAX) {
        return -ENAMETOOLONG;
    }
    for nd in s.nodes.iter_mut().filter(|nd| nd.used != 0) {
        let old_path = nd.path;
        let p = cstr(&old_path);
        if moved(p) {
            let mut fresh = [0u8; PATH_MAX];
            fresh[..to.len()].copy_from_slice(to);
            fresh[to.len()..p.len() - from.len() + to.len()].copy_from_slice(&p[from.len()..]);
            nd.path = fresh;
        }
    }
    s.nodes[src].mtime = now().0;
    0
}

// ------------------------------- /tmp: a small file system in supervisor memory --------------
// Files and folders live in memory only the supervisor can touch (mapped for level 0 only, sized
// by the policy's tmp_kb). Writing never leaves the VM and never touches the host's disk.
fn find_node(s: &State, path: &[u8]) -> Option<usize> {
    s.nodes.iter().position(|nd| nd.used != 0 && nd.path[0] != 0 && cstr(&nd.path) == path)
}

fn has_children(s: &State, dir: &[u8]) -> bool {
    s.nodes.iter().any(|nd| nd.used != 0 && nd.path[0] != 0 && parent(cstr(&nd.path)) == dir && cstr(&nd.path) != dir)
}

fn tmp_create_root(s: &mut State) {
    let nd = &mut s.nodes[0];
    (nd.used, nd.dir, nd.mtime) = (1, 1, now().0);
    set_path(&mut nd.path, b"/tmp");
}

fn tmp_create(s: &mut State, path: &[u8], dir: bool) -> Result<usize, i64> {
    match find_node(s, parent(path)) { Some(d) if s.nodes[d].dir != 0 => {} Some(_) => return Err(-ENOTDIR), None => return Err(-ENOENT) }
    let i = s.nodes.iter().position(|nd| nd.used == 0).ok_or(-ENOSPC)?;
    let nd = &mut s.nodes[i];
    (nd.used, nd.dir, nd.size, nd.data, nd.cap, nd.mtime) = (1, dir as u8, 0, 0, 0, now().0);
    set_path(&mut nd.path, path);
    Ok(i)
}

/// Unlink: the name goes now; the data goes when no open file uses it any more (like Linux).
fn remove_node(s: &mut State, i: usize) {
    s.nodes[i].path[0] = 0;
    free_if_unused(s, i);
}

fn free_if_unused(s: &mut State, i: usize) {
    let open = s.ofds.iter().any(|o| o.refs > 0 && (o.kind == K_TMP || o.kind == K_TMP_DIR) && o.handle as usize == i);
    if s.nodes[i].path[0] == 0 && !open { s.nodes[i].used = 0; }
}

/// Make room for `need` bytes. Memory is handed out once and never reused (simple and safe:
/// fresh memory is always zero), and the policy's tmp_kb caps the total.
fn tmp_reserve(s: &mut State, n: usize, need: u64) -> Result<(), i64> {
    let (cap, data, size) = (s.nodes[n].cap, s.nodes[n].data, s.nodes[n].size);
    if need <= cap { return Ok(()); }
    let room = boot().tmp_hi - s.tmp_next;
    let want = need.max(cap.saturating_mul(2)).max(256).checked_add(15).ok_or(-ENOSPC)? & !15;
    let new_cap = if want <= room { want } else if need <= room { need } else { return Err(-ENOSPC) };
    let at = s.tmp_next;
    s.tmp_next += new_cap;
    if size > 0 { unsafe { core::ptr::copy_nonoverlapping(data as *const u8, at as *mut u8, size as usize) } }
    (s.nodes[n].data, s.nodes[n].cap) = (at, new_cap);
    Ok(())
}

fn tmp_set_size(s: &mut State, n: usize, len: u64) -> Result<(), i64> {
    tmp_reserve(s, n, len)?;
    let nd = &mut s.nodes[n];
    if len > nd.size { unsafe { core::ptr::write_bytes((nd.data + nd.size) as *mut u8, 0, (len - nd.size) as usize) } }
    (nd.size, nd.mtime) = (len, now().0);
    Ok(())
}

fn tmp_open(s: &mut State, path: &[u8], flags: u64) -> i64 {
    let writing = flags & O_ACCMODE != 0;
    let node = match find_node(s, path) {
        Some(_) if flags & O_CREAT != 0 && flags & O_EXCL != 0 => return -EEXIST,
        Some(i) if s.nodes[i].dir != 0 => { if writing { return -EISDIR; } i }
        Some(i) => {
            if flags & O_DIRECTORY != 0 { return -ENOTDIR; }
            if writing && flags & O_TRUNC != 0 { if let Err(e) = tmp_set_size(s, i, 0) { return e; } }
            i
        }
        None if flags & O_CREAT != 0 && flags & O_DIRECTORY == 0 => match tmp_create(s, path, false) { Ok(i) => i, Err(e) => return e },
        None => return -ENOENT,
    };
    let kind = if s.nodes[node].dir != 0 { K_TMP_DIR } else { K_TMP };
    match new_ofd(s, kind, node as u64, flags, path) { Some(o) => install(s, o, 0), None => -EMFILE }
}

fn tmp_write(s: &mut State, o: usize, buf: u64, len: u64) -> i64 {
    let n = s.ofds[o].handle as usize;
    let start = if s.ofds[o].append != 0 { s.nodes[n].size } else { s.ofds[o].offset };
    let Some(end) = start.checked_add(len) else { return -EFBIG };
    if start > s.nodes[n].size { if let Err(e) = tmp_set_size(s, n, start) { return e; } } // a gap reads as zeros
    if let Err(e) = tmp_reserve(s, n, end) { return e; }
    let nd = &mut s.nodes[n];
    unsafe { core::ptr::copy(buf as *const u8, (nd.data + start) as *mut u8, len as usize) };
    (nd.size, nd.mtime) = (nd.size.max(end), now().0);
    s.ofds[o].offset = end;
    len as i64
}

/// Directory entries (Linux's `struct linux_dirent64`): ".", "..", then the folder's children.
/// The position is 0 = ".", 1 = "..", k + 2 = node k.
fn tmp_getdents(s: &mut State, o: usize, buf: u64, len: u64) -> i64 {
    let dir_node = s.ofds[o].handle as usize;
    let dir_buf = s.nodes[dir_node].path;
    let dir = cstr(&dir_buf);
    let (mut pos, mut written) = (s.ofds[o].offset, 0u64);
    loop {
        let (name, ino, kind): (&[u8], u64, u8) = match pos {
            0 => (b".", dir_node as u64 + 1, 4),
            1 => (b"..", 1, 4),
            _ => {
                let next = (pos as usize - 2..MAX_NODES).find(|&k| {
                    let nd = &s.nodes[k];
                    nd.used != 0 && nd.path[0] != 0 && k != dir_node && parent(cstr(&nd.path)) == dir
                });
                let Some(k) = next else { break };
                pos = k as u64 + 2;
                let p = cstr(&s.nodes[k].path);
                (&p[parent(p).len() + 1..], k as u64 + 1, if s.nodes[k].dir != 0 { 4 } else { 8 })
            }
        };
        let reclen = (19 + name.len() as u64 + 1 + 7) & !7;
        if written + reclen > len { if written == 0 { return -EINVAL; } break; }
        let at = buf + written;
        unsafe {
            core::ptr::write_bytes(at as *mut u8, 0, reclen as usize);
            (at as *mut u64).write_volatile(ino);
            ((at + 8) as *mut u64).write_volatile(pos + 1);
            ((at + 16) as *mut u16).write_volatile(reclen as u16);
            ((at + 18) as *mut u8).write_volatile(kind);
            core::ptr::copy_nonoverlapping(name.as_ptr(), (at + 19) as *mut u8, name.len());
        }
        written += reclen;
        pos += 1;
    }
    s.ofds[o].offset = pos;
    written as i64
}

// ------------------------------- forwarded: randomness, sleeping -------------------------------
fn getrandom(buf: u64, len: u64) -> i64 {
    let len = len.min(256);
    if !user_writable(buf, len) { return -EFAULT; }
    hypercall(HC_GETRANDOM, buf, len, 0)
}

/// Sleeping: we have no timer of our own, so the VMM sleeps on the host. An idle agent then costs
/// no CPU at all: its vCPU thread is simply blocked on the host.
fn sleep(req: u64) -> i64 {
    if !user_readable(req, 16) { return -EFAULT; }
    let (secs, nanos) = unsafe { ((req as *const u64).read_volatile(), ((req + 8) as *const u64).read_volatile()) };
    if nanos >= 1_000_000_000 { return -EINVAL; }
    let total = secs.saturating_mul(1_000_000_000).saturating_add(nanos);
    hypercall(HC_SLEEP, total, 0, 0)
}

// ------------------------------- helpers ------------------------------------------------------
/// Pointers from the agent are never trusted. The rule: the supervisor touches memory for the agent
/// only if the agent could touch it itself. We don't compare against an address range (it has holes:
/// unmapped gaps, read-only code, memory beyond the limit); we ask the MMU, with the agent's own page
/// tables, page by page: AT S1E0R / S1E0W = "translate this as a level-3 read / write".
fn el0_can(ptr: u64, len: u64, write: bool) -> bool {
    let Some(end) = ptr.checked_add(len) else { return false };
    if ptr < AGENT_LO || end > AGENT_HI { return false; } // cheap first check, also bounds the loop
    let mut page = ptr & !0xfff;
    while page < end {
        let par: u64;
        unsafe {
            if write { asm!("at s1e0w, {0}", "isb", "mrs {1}, par_el1", in(reg) page, out(reg) par) }
            else { asm!("at s1e0r, {0}", "isb", "mrs {1}, par_el1", in(reg) page, out(reg) par) }
        }
        if par & 1 != 0 { return false; } // PAR_EL1.F: the translation would fault
        page += 4096;
    }
    true
}
fn user_readable(ptr: u64, len: u64) -> bool { el0_can(ptr, len, false) }
fn user_writable(ptr: u64, len: u64) -> bool { el0_can(ptr, len, true) }

fn hypercall(op: u64, a: u64, b: u64, c: u64) -> i64 {
    EXITED.store(true, Relaxed);
    unsafe {
        let p = HC_PAGE as *mut u64;
        p.write_volatile(op);
        p.add(1).write_volatile(a);
        p.add(2).write_volatile(b);
        p.add(3).write_volatile(c);
        asm!("dsb sy", "str xzr, [{0}]", in(reg) DOORBELL, options(nostack));
        p.add(4).read_volatile() as i64
    }
}

fn log(kind: u64, a: u64, b: u64, c: u64, d: u64, e: u64) {
    unsafe {
        let count = (LOG_BASE as *mut u64).read_volatile();
        if count >= LOG_MAX {
            // A gap in the audit trail is not acceptable: stop the agent instead.
            hypercall(HC_LOG_FULL, 0, 0, 0);
            loop {}
        }
        let entry = (LOG_BASE + 64 + count * 48) as *mut u64;
        for (i, v) in [kind, a, b, c, d, e].into_iter().enumerate() { entry.add(i).write_volatile(v) }
        (LOG_BASE as *mut u64).write_volatile(count + 1);
    }
}

#[unsafe(no_mangle)]
extern "C" fn el1_fault(esr: u64, elr: u64, far: u64) -> ! {
    hypercall(HC_PANIC, esr, elr, far);
    loop {}
}

struct TextBuf(usize);
impl Write for TextBuf {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        for b in s.bytes() {
            if self.0 < 255 { unsafe { (HC_TEXT as *mut u8).add(self.0).write_volatile(b) }; self.0 += 1; }
        }
        Ok(())
    }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    let mut t = TextBuf(0);
    let _ = write!(t, "{}", info.message());
    unsafe { (HC_TEXT as *mut u8).add(t.0).write_volatile(0) };
    hypercall(HC_PANIC, 0, 0, 0);
    loop {}
}
