//! The supervisor: guest level 0 (EL1). A tiny "kernel" for one real program.
//!
//! The VMM loads the agent's ELF, builds the page tables and writes a BootInfo record. We then:
//!   1. point the CPU's "door" (VBAR_EL1) at our handlers,
//!   2. turn on the page tables and allow the agent to use the FP/SIMD unit,
//!   3. jump down to guest level 3 at the agent's entry point.
//! From then on every system call lands in `el0_sync`, and goes into one of three buckets:
//!   ANSWER IT  (memory, signals, clock, ids)  handled here, no VM exit
//!   REFUSE IT  (network, new processes, writes, paths outside /workspace, anything unknown)
//!   FORWARD IT (printing, reading /workspace files, randomness)  checked here, then one doorbell
//!              exit each; the VMM makes the real host system call.
//! A fault (bad memory access, illegal instruction) kills the agent, as Linux would.

#![no_std]
#![no_main]

use core::arch::{asm, global_asm};
use core::fmt::Write;
use core::sync::atomic::{AtomicU64, Ordering::Relaxed};

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
const PATH_LOG_END: u64 = 0x80e0_0000;
const SUP_STACK_TOP: u64 = 0x8100_0000;
const AGENT_LO: u64 = 0x8100_0000; // everything the agent owns lives in [AGENT_LO, AGENT_HI)
const AGENT_HI: u64 = 0x8800_0000;
const DOORBELL: u64 = 0x0900_0000;

#[repr(C)]
struct BootInfo { entry: u64, sp: u64, brk_start: u64, brk_end: u64, mmap_start: u64, mmap_end: u64, rw_lo: u64, rw_hi: u64 }
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
const EPERM: i64 = 1;
const EBADF: i64 = 9;
const ENOMEM: i64 = 12;
const EACCES: i64 = 13;
const EFAULT: i64 = 14;
const EINVAL: i64 = 22;
const ENAMETOOLONG: i64 = 36;
const ENOSYS: i64 = 38;

static BRK: AtomicU64 = AtomicU64::new(0);
static MMAP_NEXT: AtomicU64 = AtomicU64::new(0);
static PATH_NEXT: AtomicU64 = AtomicU64::new(PATH_LOG);
static LAST_PATH: AtomicU64 = AtomicU64::new(0);

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
    const SCTLR_BITS: u64 = 1 | (1 << 2) | (1 << 12) | (1 << 14) | (1 << 15); // MMU, caches, EL0 may use DC ZVA + CTR_EL0
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
    unsafe {
        asm!(
            "msr elr_el1, x9",                // 3. where eret goes: the agent's entry point
            "msr sp_el0, x10",                //    its stack (argc, argv, auxv: built by the VMM)
            "msr spsr_el1, x11",              //    level 3, interrupts masked
            "mov x0, xzr", "mov x1, xzr", "mov x2, xzr", "mov x3, xzr", "mov x4, xzr", "mov x5, xzr",
            "mov x6, xzr", "mov x7, xzr", "mov x8, xzr", "mov x9, xzr", "mov x10, xzr", "mov x11, xzr",
            "mov x29, xzr", "mov x30, xzr",
            "eret",
            in("x9") b.entry, in("x10") b.sp, in("x11") 0x3c0u64,
            options(noreturn),
        );
    }
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
    if nr == 56 && policy_action(nr) != ALLOW {
        let _ = copy_path(a1); // keep a copy for the notebook even though the call is refused
    }
    let (bucket, result) = match policy_action(nr) {
        ALLOW => syscall(nr, &tf.x),
        DENY => (REFUSED, -(policy_errno(nr) as i64)),
        _ => (REFUSED, -ENOSYS),
    };
    let a1 = if nr == 56 { LAST_PATH.load(Relaxed) } else { a1 }; // openat: log our copy of the path
    log(bucket, nr, a0, a1, a2, result as u64);
    tf.x[0] = result as u64; // the agent sees the result in x0
}

fn syscall(nr: u64, x: &[u64; 32]) -> (u64, i64) {
    let a = |i: usize| x[i];
    match nr {
        // ---------------- ANSWER IT: no exit ----------------
        96 => (ANSWERED, 1),                          // set_tid_address: "your thread id is 1"
        172 | 178 => (ANSWERED, 1),                   // getpid, gettid
        174..=177 => (ANSWERED, 1000),                // getuid, geteuid, getgid, getegid
        214 => (ANSWERED, brk(a(0))),                 // brk: grow the heap
        222 => mmap(a(1), a(3), a(4) as i64),         // mmap: anonymous memory only
        215 | 226 | 233 => (ANSWERED, 0),             // munmap, mprotect, madvise: accepted
        134 => zero_out(a(2), 32),                    // rt_sigaction: no signals here; "old" = default
        135 => zero_out(a(2), 8),                     // rt_sigprocmask
        132 => sigaltstack(a(1)),
        113 => clock_gettime(a(1)),                   // read the CPU's own clock
        73 => ppoll(a(0), a(1)),                      // "are fds 0-2 open?" yes
        29 => (ANSWERED, -25),                        // ioctl: ENOTTY, "not a terminal"

        // ---------------- FORWARD IT: checks, then the doorbell ----------------
        64 => write(a(0), a(1), a(2)),
        66 => writev(a(0), a(1), a(2)),
        56 => openat(a(1), a(2)),
        63 => read(a(0), a(1), a(2)),
        57 => fd_call(HC_CLOSE, a(0), 0, 0),
        80 => fstat(a(0), a(1)),
        62 => fd_call(HC_LSEEK, a(0), a(1), a(2)),
        278 => getrandom(a(0), a(1)),
        101 => sleep(a(0)),                           // nanosleep(req, rem)
        115 if a(1) & 1 == 0 => sleep(a(2)),          // clock_nanosleep(clock, flags, req, rem), relative only

        // ---------------- REFUSE IT ----------------
        // Network, new processes, etc. are refused by the policy before we get here. Anything the
        // policy allows but we have no handler for is refused honestly as "not implemented".
        _ => (REFUSED, -ENOSYS),
    }
}

// ------------------------------- the policy (data written by the VMM) -------------------------
fn policy_action(nr: u64) -> u8 {
    if nr < 512 { unsafe { ((POLICY + nr) as *const u8).read_volatile() } } else { 0 }
}
fn policy_errno(nr: u64) -> u8 {
    unsafe { ((POLICY + 512 + nr) as *const u8).read_volatile() } // only called when nr < 512
}
/// Does the path start with one of the policy's read prefixes?
fn read_allowed(path: &[u8]) -> bool {
    let count = unsafe { ((POLICY + 1024) as *const u64).read_volatile() }.min(8);
    (0..count).any(|i| {
        let p = (POLICY + 1088 + i * 128) as *const u8;
        let len = (0..127).take_while(|&j| unsafe { p.add(j).read_volatile() } != 0).count();
        len > 0 && path.starts_with(unsafe { core::slice::from_raw_parts(p, len) })
    })
}

// ------------------------------- ANSWER IT ----------------------------------------------------
fn brk(request: u64) -> i64 {
    let b = boot();
    if request >= b.brk_start && request <= b.brk_end {
        BRK.store(request, Relaxed);
    }
    BRK.load(Relaxed) as i64 // like Linux: always return the current break
}

fn mmap(len: u64, flags: u64, fd: i64) -> (u64, i64) {
    const MAP_FIXED: u64 = 0x10;
    const MAP_ANONYMOUS: u64 = 0x20;
    if flags & MAP_ANONYMOUS == 0 || fd != -1 {
        return (REFUSED, -EACCES); // mapping files: not offered
    }
    if flags & MAP_FIXED != 0 || len == 0 {
        return (REFUSED, -EINVAL);
    }
    let len = (len + 4095) & !4095;
    let start = MMAP_NEXT.load(Relaxed);
    match start.checked_add(len) {
        Some(end) if end <= boot().mmap_end => {
            MMAP_NEXT.store(end, Relaxed); // fresh, never reused, so it is still all zeros
            (ANSWERED, start as i64)
        }
        _ => (REFUSED, -ENOMEM),
    }
}

fn zero_out(ptr: u64, len: u64) -> (u64, i64) {
    if ptr != 0 {
        if !user_writable(ptr, len) { return (REFUSED, -EFAULT); }
        for i in 0..len { unsafe { ((ptr + i) as *mut u8).write_volatile(0) } }
    }
    (ANSWERED, 0)
}

fn sigaltstack(old: u64) -> (u64, i64) {
    if old != 0 {
        if !user_writable(old, 24) { return (REFUSED, -EFAULT); }
        unsafe {
            (old as *mut u64).write_volatile(0); // ss_sp
            ((old + 8) as *mut u64).write_volatile(2); // ss_flags = SS_DISABLE
            ((old + 16) as *mut u64).write_volatile(0); // ss_size
        }
    }
    (ANSWERED, 0)
}

fn clock_gettime(ts: u64) -> (u64, i64) {
    if !user_writable(ts, 16) { return (REFUSED, -EFAULT); }
    let (ticks, freq): (u64, u64);
    unsafe { asm!("mrs {0}, cntvct_el0", "mrs {1}, cntfrq_el0", out(reg) ticks, out(reg) freq) };
    let secs = ticks / freq;
    let nanos = (ticks % freq) * 1_000_000_000 / freq;
    unsafe {
        (ts as *mut u64).write_volatile(secs);
        ((ts + 8) as *mut u64).write_volatile(nanos);
    }
    (ANSWERED, 0)
}

fn ppoll(fds: u64, nfds: u64) -> (u64, i64) {
    if nfds > 64 || !user_writable(fds, nfds * 8) { return (REFUSED, -EFAULT); }
    for i in 0..nfds {
        unsafe { ((fds + i * 8 + 6) as *mut u16).write_volatile(0) } // revents = 0: nothing wrong
    }
    (ANSWERED, 0)
}

// ------------------------------- FORWARD IT ---------------------------------------------------
fn write(fd: u64, buf: u64, len: u64) -> (u64, i64) {
    if fd != 1 && fd != 2 { return (REFUSED, -EBADF); }
    if !user_readable(buf, len) { return (REFUSED, -EFAULT); }
    (FORWARDED, hypercall(HC_WRITE, buf, len, 0))
}

fn writev(fd: u64, iov: u64, count: u64) -> (u64, i64) {
    if fd != 1 && fd != 2 { return (REFUSED, -EBADF); }
    if count > 64 || !user_readable(iov, count * 16) { return (REFUSED, -EFAULT); }
    let mut total = 0i64;
    for i in 0..count {
        let (base, len) = unsafe { (((iov + i * 16) as *const u64).read_volatile(), ((iov + i * 16 + 8) as *const u64).read_volatile()) };
        if len == 0 { continue; }
        if !user_readable(base, len) { return (REFUSED, -EFAULT); }
        let r = hypercall(HC_WRITE, base, len, 0);
        if r < 0 { return (FORWARDED, r); }
        total += r;
    }
    (FORWARDED, total)
}

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

fn openat(path: u64, flags: u64) -> (u64, i64) {
    let len = match copy_path(path) { Ok(len) => len, Err(e) => return (REFUSED, e) };
    let text = LAST_PATH.load(Relaxed) as *mut u8;
    let p = unsafe { core::slice::from_raw_parts(text, len as usize) };
    if !read_allowed(p) || p.windows(2).any(|w| w == b"..") {
        return (REFUSED, -EACCES); // only under the policy's read prefixes, no climbing out
    }
    if flags & 3 != 0 {
        return (REFUSED, -EACCES); // read-only workspace: no writing
    }
    for i in 0..=len as usize { // hand the VMM the checked copy, not the agent's memory
        unsafe { (HC_TEXT as *mut u8).add(i).write_volatile(text.add(i).read_volatile()) }
    }
    (FORWARDED, hypercall(HC_OPEN, HC_TEXT, 0, 0))
}

fn read(fd: u64, buf: u64, len: u64) -> (u64, i64) {
    if fd < 3 { return (REFUSED, -EBADF); } // only files the VMM opened (no stdin)
    if !user_writable(buf, len) { return (REFUSED, -EFAULT); }
    (FORWARDED, hypercall(HC_READ, fd, buf, len))
}

fn fstat(fd: u64, st: u64) -> (u64, i64) {
    if fd < 3 { return (REFUSED, -EBADF); }
    if !user_writable(st, 128) { return (REFUSED, -EFAULT); }
    (FORWARDED, hypercall(HC_FSTAT, fd, st, 0))
}

fn fd_call(op: u64, fd: u64, b: u64, c: u64) -> (u64, i64) {
    if fd < 3 { return (REFUSED, -EBADF); }
    (FORWARDED, hypercall(op, fd, b, c))
}

fn getrandom(buf: u64, len: u64) -> (u64, i64) {
    let len = len.min(256);
    if !user_writable(buf, len) { return (REFUSED, -EFAULT); }
    (FORWARDED, hypercall(HC_GETRANDOM, buf, len, 0))
}

/// Sleeping: we have no timer of our own, so the VMM sleeps on the host. An idle agent then costs
/// no CPU at all: its vCPU thread is simply blocked on the host.
fn sleep(req: u64) -> (u64, i64) {
    if !user_readable(req, 16) { return (REFUSED, -EFAULT); }
    let (secs, nanos) = unsafe { ((req as *const u64).read_volatile(), ((req + 8) as *const u64).read_volatile()) };
    if nanos >= 1_000_000_000 { return (REFUSED, -EINVAL); }
    let total = secs.saturating_mul(1_000_000_000).saturating_add(nanos);
    (FORWARDED, hypercall(HC_SLEEP, total, 0, 0))
}

// ------------------------------- helpers ------------------------------------------------------
/// Pointers from the agent are never trusted: they must lie inside the agent's own memory.
fn user_readable(ptr: u64, len: u64) -> bool {
    ptr >= AGENT_LO && ptr.checked_add(len).is_some_and(|end| end <= AGENT_HI)
}
/// For memory we (or the VMM) write into: heap/mmap/stack, or the program's writable data.
fn user_writable(ptr: u64, len: u64) -> bool {
    let b = boot();
    let Some(end) = ptr.checked_add(len) else { return false };
    (ptr >= b.brk_start && end <= AGENT_HI) || (ptr >= b.rw_lo && end <= b.rw_hi)
}

/// Ring the doorbell: the only way out of guest mode. The VMM does the work and writes the result.
fn hypercall(op: u64, a: u64, b: u64, c: u64) -> i64 {
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
