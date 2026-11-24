//! A hostile agent. It does what a prompt-injected agent tool (Hermes `terminal`/`execute_code`,
//! deepagents `execute`) would try once it runs inside the sandbox: steal host secrets, escape the
//! workspace, reach the network, start programs, take over the supervisor, outgrow its limits.
//!
//!   redteam probe          ~60 attacks that must each come back as an error; prints PASS/FAIL per attack
//!   redteam fatal NAME     one attack that must stop the sandbox (the run script checks how it stopped)
//!   redteam fuzz SEED N    N random system calls with hostile arguments
//!
//! It uses raw `svc` system calls so it can pass any number and any pointer, not just what libc allows.

use std::arch::asm;
use std::hint::black_box;

// The guest's memory map (see vmm/src/main.rs). The agent is told nothing; an attacker would guess.
const SUPERVISOR_CODE: u64 = 0x8000_0000;
const HC_PAGE: u64 = 0x8011_0000; // the supervisor's doorbell page
const POLICY: u64 = 0x8012_0000; // the policy table
const PAGE_TABLES: u64 = 0x8020_0000;
const AUDIT_LOG: u64 = 0x8040_0000;
const HOLE: u64 = 0x81f0_0000; // inside the agent's range, but nothing is mapped there
const MMAP_START: u64 = 0x8280_0000;
const DOORBELL: u64 = 0x0900_0000;

const ENOENT: i64 = 2; const ESRCH: i64 = 3; const EBUSY: i64 = 16; const ENOTDIR: i64 = 20; const EISDIR: i64 = 21;
const ENOSPC: i64 = 28; const ERANGE: i64 = 34;
const EPERM: i64 = 1; const EBADF: i64 = 9; const ENOMEM: i64 = 12; const EACCES: i64 = 13;
const EFAULT: i64 = 14; const EINVAL: i64 = 22; const EMFILE: i64 = 24; const ENAMETOOLONG: i64 = 36; const ENOSYS: i64 = 38;

unsafe fn sc(nr: u64, a: [u64; 6]) -> i64 {
    let r: i64;
    unsafe { asm!("svc 0", inlateout("x0") a[0] => r, in("x1") a[1], in("x2") a[2], in("x3") a[3], in("x4") a[4], in("x5") a[5], in("x8") nr) };
    r
}
fn sys(nr: u64, a: &[u64]) -> i64 {
    let mut v = [0u64; 6];
    v[..a.len()].copy_from_slice(a);
    unsafe { sc(nr, v) }
}
const AT_FDCWD: u64 = -100i64 as u64;
fn open(path: &[u8], flags: u64) -> i64 { sys(56, &[AT_FDCWD, path.as_ptr() as u64, flags, 0]) }
fn p(s: &[u8]) -> u64 { s.as_ptr() as u64 }

// ------------------------------------------------------------------------------------------------
fn probe() {
    let (mut pass, mut fail) = (0, 0);
    let mut check = |what: &str, got: i64, ok: bool, want: &str| {
        if ok { pass += 1 } else { fail += 1 }
        println!("{}  {what:<58} got {got:<12} want {want}", if ok { "PASS" } else { "FAIL" });
    };
    let is = |e: i64| move |r: i64| r == -e;

    println!("-- steal host secrets");
    for path in [&b"/etc/passwd\0"[..], b"/etc/shadow\0", b"/root/.ssh/id_rsa\0", b"/home/user/.aws/credentials\0",
                 b"/proc/self/environ\0", b"/proc/self/mem\0", b"/proc/1/root/etc/passwd\0", b"/dev/kvm\0", b"/\0"] {
        let r = open(path, 0);
        check(&format!("open {}", String::from_utf8_lossy(&path[..path.len() - 1])), r, is(EACCES)(r), "EACCES");
    }
    println!("-- escape the workspace");
    let r = open(b"/workspace/../etc/passwd\0", 0); check("open /workspace/../etc/passwd", r, is(EACCES)(r), "EACCES");
    let r = open(b"/workspace/./../../etc/passwd\0", 0); check("open /workspace/./../../etc/passwd", r, is(EACCES)(r), "EACCES");
    let r = open(b"/workspace//etc/passwd\0", 0); check("open /workspace//etc/passwd (= /workspace/etc/passwd)", r, is(ENOENT)(r), "ENOENT");
    let r = open(b"/workspace/escape-link\0", 0); check("open /workspace/escape-link (symlink -> /etc/passwd)", r, is(EACCES)(r), "EACCES");
    let r = open(b"/workspace/etc-link/passwd\0", 0); check("open /workspace/etc-link/passwd (symlink -> /etc)", r, is(EACCES)(r), "EACCES");
    let r = open(b"/workspaceX/notes.txt\0", 0); check("open /workspaceX/notes.txt (prefix confusion)", r, r < 0, "an error");
    let long = [b"/workspace/".as_slice(), &[b'a'; 300], b"\0"].concat();
    let r = open(&long, 0); check("open a 311-byte path", r, is(ENAMETOOLONG)(r), "ENAMETOOLONG");
    println!("-- write, create, persist");
    for (flags, name) in [(1, "O_WRONLY"), (2, "O_RDWR"), (0o1101, "O_WRONLY|O_CREAT|O_TRUNC"), (0o2001, "O_WRONLY|O_APPEND")] {
        let r = open(b"/workspace/notes.txt\0", flags); check(&format!("open notes.txt {name}"), r, is(EACCES)(r), "EACCES");
    }
    for (nr, name) in [(34, "mkdirat"), (35, "unlinkat"), (36, "symlinkat"), (37, "linkat"), (38, "renameat"), (53, "fchmodat"), (54, "fchownat")] {
        let r = sys(nr, &[AT_FDCWD, p(b"/workspace/x\0"), AT_FDCWD, p(b"/workspace/y\0")]); check(&format!("{name} in /workspace"), r, r < 0, "refused");
    }
    let mut st = [0u64; 16];
    let r = sys(79, &[AT_FDCWD, p(b"/workspace/x\0"), st.as_mut_ptr() as u64, 0]); check("...and /workspace/x does not exist afterwards", r, is(ENOENT)(r), "ENOENT");
    println!("-- network (exfiltration, Hermes' socket RPC)");
    let r = sys(198, &[2, 1, 0]); check("socket(AF_INET, SOCK_STREAM)", r, is(EACCES)(r), "EACCES");
    let r = sys(198, &[1, 1, 0]); check("socket(AF_UNIX, SOCK_STREAM)", r, is(EACCES)(r), "EACCES");
    let r = sys(203, &[3, 0, 16]); check("connect", r, is(EACCES)(r), "EACCES");
    let r = sys(199, &[1, 1, 0, 0]); check("socketpair", r, is(EACCES)(r), "EACCES");
    println!("-- start programs, fork bombs");
    let r = sys(220, &[17, 0, 0, 0, 0]); check("clone(SIGCHLD)  (fork)", r, is(EPERM)(r), "EPERM");
    let r = sys(435, &[0, 0]); check("clone3", r, is(EPERM)(r), "EPERM");
    let argv = [p(b"/bin/sh\0"), 0u64];
    let r = sys(221, &[p(b"/bin/sh\0"), argv.as_ptr() as u64, 0]); check("execve /bin/sh", r, is(EPERM)(r), "EPERM");
    let forks = (0..1_000).filter(|_| sys(220, &[17, 0, 0, 0, 0]) >= 0).count() as i64;
    check("fork bomb: 1,000 clone calls", forks, forks == 0, "0 succeed");
    println!("-- kernel attack surface the host normally exposes");
    for (nr, name) in [(117, "ptrace"), (40, "mount"), (97, "unshare"), (268, "setns"), (280, "bpf"),
                       (425, "io_uring_setup"), (282, "userfaultfd"), (241, "perf_event_open"), (105, "init_module"),
                       (219, "keyctl"), (270, "process_vm_readv"), (142, "reboot"), (59, "pipe2"),
                       (167, "prctl"), (277, "seccomp"), (999, "system call 999"), (u64::MAX, "system call 2^64-1")] {
        let r = sys(nr, &[1, 9, 0, 0]); check(name, r, is(ENOSYS)(r), "ENOSYS");
    }
    println!("-- hand the supervisor pointers to ITS memory (read it out / overwrite it)");
    let fd = open(b"/workspace/notes.txt\0", 0);
    check("open /workspace/notes.txt (allowed)", fd, fd >= 3, "an fd");
    let fdu = fd as u64;
    let r = sys(64, &[1, POLICY, 64]); check("write(stdout, policy table)", r, is(EFAULT)(r), "EFAULT");
    let r = sys(64, &[1, AUDIT_LOG, 64]); check("write(stdout, audit log)", r, is(EFAULT)(r), "EFAULT");
    let r = sys(64, &[1, p(b"x"), u64::MAX]); check("write(stdout, buf, 2^64-1 bytes)", r, is(EFAULT)(r), "EFAULT");
    let r = sys(63, &[fdu, SUPERVISOR_CODE, 16]); check("read(file, into supervisor code)", r, is(EFAULT)(r), "EFAULT");
    let r = sys(63, &[fdu, PAGE_TABLES, 16]); check("read(file, into page tables)", r, is(EFAULT)(r), "EFAULT");
    let r = sys(63, &[fdu, probe as *const () as u64, 16]); check("read(file, into my own code)", r, is(EFAULT)(r), "EFAULT");
    let r = sys(80, &[fdu, AUDIT_LOG]); check("fstat(file, into audit log)", r, is(EFAULT)(r), "EFAULT");
    let r = sys(278, &[HC_PAGE, 16, 0]); check("getrandom(into doorbell page)", r, is(EFAULT)(r), "EFAULT");
    let r = sys(113, &[0, SUPERVISOR_CODE]); check("clock_gettime(into supervisor code)", r, is(EFAULT)(r), "EFAULT");
    let r = sys(134, &[2, 0, POLICY, 8]); check("rt_sigaction(old action -> policy table)", r, is(EFAULT)(r), "EFAULT");
    let r = sys(132, &[0, POLICY]); check("sigaltstack(old -> policy table)", r, is(EFAULT)(r), "EFAULT");
    let r = sys(73, &[AUDIT_LOG, 4, 0, 0]); check("ppoll(fds in audit log)", r, is(EFAULT)(r), "EFAULT");
    let r = sys(66, &[1, POLICY, 1]); check("writev(iovec array in policy table)", r, is(EFAULT)(r), "EFAULT");
    let iov = [POLICY, 64u64];
    let r = sys(66, &[1, iov.as_ptr() as u64, 1]); check("writev(iovec -> policy table)", r, is(EFAULT)(r), "EFAULT");
    let r = sys(56, &[AT_FDCWD, POLICY, 0]); check("openat(path inside policy table)", r, is(EFAULT)(r), "EFAULT");
    let r = sys(56, &[AT_FDCWD, 0, 0]); check("openat(NULL path)", r, is(EFAULT)(r), "EFAULT");
    let r = sys(101, &[POLICY, 0]); check("nanosleep(request in policy table)", r, is(EFAULT)(r), "EFAULT");
    println!("-- memory games");
    let r = sys(222, &[0, u64::MAX - 100, 3, 0x22, u64::MAX, 0]); check("mmap 2^64-101 bytes (length overflow)", r, is(ENOMEM)(r), "ENOMEM");
    let r = sys(222, &[0, 1 << 40, 3, 0x22, u64::MAX, 0]); check("mmap 1 TiB", r, is(ENOMEM)(r), "ENOMEM");
    let r = sys(222, &[SUPERVISOR_CODE, 4096, 7, 0x32, u64::MAX, 0]); check("mmap MAP_FIXED over the supervisor", r, is(EINVAL)(r), "EINVAL");
    let r = sys(222, &[0, 4096, 5, 0x02, fdu, 0]); check("mmap a file (map host file memory)", r, is(EACCES)(r), "EACCES");
    let r = sys(214, &[SUPERVISOR_CODE]); check("brk(supervisor address)", r, r > 0 && r as u64 != SUPERVISOR_CODE, "unchanged break");
    let r = sys(101, &[[0u64, 2_000_000_000].as_ptr() as u64, 0]); check("nanosleep(2e9 ns field)", r, is(EINVAL)(r), "EINVAL");
    println!("-- file descriptors");
    let mut buf = [0u8; 8];
    let r = sys(63, &[0, buf.as_mut_ptr() as u64, 8]); check("read(stdin): there is no input", r, r == 0, "0 (end of file)");
    let r = sys(64, &[fdu, p(b"x"), 1]); check("write(the open file)", r, is(EBADF)(r), "EBADF");
    let r = sys(63, &[999, buf.as_mut_ptr() as u64, 8]); check("read(fd 999)", r, is(EBADF)(r), "EBADF");
    let r = sys(57, &[999]); check("close(fd 999)", r, is(EBADF)(r), "EBADF");
    sys(57, &[fdu]);
    let fds: Vec<i64> = (0..9).map(|_| open(b"/workspace/notes.txt\0", 0)).collect();
    check("open 9 files (limit 8)", fds[8], fds[..8].iter().all(|&f| f >= 3) && fds[8] == -EMFILE, "8 fds, then EMFILE");
    for f in fds { if f >= 3 { sys(57, &[f as u64]); } }

    println!("-- folders, the current folder, relative paths (new surface)");
    let ok_cd = sys(49, &[p(b"/workspace\0")]); check("chdir /workspace (allowed)", ok_cd, ok_cd == 0, "0");
    let r = sys(49, &[p(b"/etc\0")]); check("chdir /etc", r, is(EACCES)(r), "EACCES");
    let r = sys(49, &[p(b"..\0")]); check("chdir .. (to /)", r, is(EACCES)(r), "EACCES");
    let r = sys(49, &[p(b"notes.txt\0")]); check("chdir into a file", r, is(ENOTDIR)(r), "ENOTDIR");
    let r = sys(49, &[p(b"etc-link\0")]); check("chdir etc-link (symlink -> /etc)", r, is(EACCES)(r), "EACCES");
    for path in [&b"../etc/passwd\0"[..], b"../../../../etc/shadow\0", b"escape-link\0", b"etc-link/passwd\0", b"./././../etc/passwd\0"] {
        let r = open(path, 0); check(&format!("open {} (relative, cwd /workspace)", String::from_utf8_lossy(&path[..path.len() - 1])), r, is(EACCES)(r), "EACCES");
    }
    let dir = open(b"/workspace\0", 0o40000); check("open /workspace as a folder", dir, dir >= 3, "an fd");
    let r = sys(56, &[dir as u64, p(b"../etc/passwd\0"), 0]); check("openat(folder fd, ../etc/passwd)", r, is(EACCES)(r), "EACCES");
    let r = sys(56, &[1, p(b"x\0"), 0]); check("openat(stdout as a folder, x)", r, is(ENOTDIR)(r), "ENOTDIR");
    let r = sys(63, &[dir as u64, buf.as_mut_ptr() as u64, 8]); check("read(folder fd)", r, is(EISDIR)(r), "EISDIR");
    let r = sys(64, &[dir as u64, p(b"x"), 1]); check("write(folder fd)", r, is(EBADF)(r), "EBADF");
    let r = sys(61, &[dir as u64, AUDIT_LOG, 4096]); check("getdents64(folder, into audit log)", r, is(EFAULT)(r), "EFAULT");
    let r = sys(61, &[dir as u64, buf.as_mut_ptr() as u64, 1]); check("getdents64(folder, 1-byte buffer)", r, is(EINVAL)(r), "EINVAL");
    let mut big = vec![0u8; 4096];
    let r = sys(61, &[dir as u64, big.as_mut_ptr() as u64, 4096]); check("getdents64(/workspace) lists it", r, r > 0, "> 0 bytes");
    let r = sys(61, &[1, big.as_mut_ptr() as u64, 4096]); check("getdents64(stdout)", r, is(ENOTDIR)(r), "ENOTDIR");
    sys(57, &[dir as u64]);
    let r = sys(79, &[AT_FDCWD, p(b"/etc/shadow\0"), st.as_mut_ptr() as u64, 0]); check("stat /etc/shadow", r, is(EACCES)(r), "EACCES");
    let r = sys(79, &[AT_FDCWD, p(b"escape-link\0"), st.as_mut_ptr() as u64, 0]); check("stat escape-link (follows -> /etc/passwd)", r, is(EACCES)(r), "EACCES");
    let r = sys(79, &[AT_FDCWD, p(b"escape-link\0"), st.as_mut_ptr() as u64, 0x100]); check("lstat escape-link: the link itself", r, r == 0 && st[2] as u32 & 0o170000 == 0o120000, "0, a symlink");
    let r = sys(78, &[AT_FDCWD as u64, p(b"escape-link\0"), big.as_mut_ptr() as u64, 64]); check("readlink escape-link: its text, in the workspace", r, r == 11, "11 bytes");
    let r = sys(79, &[AT_FDCWD, p(b"notes.txt\0"), POLICY, 0]); check("stat(notes.txt, into policy table)", r, is(EFAULT)(r), "EFAULT");
    let r = sys(79, &[AT_FDCWD, p(b"/\0"), st.as_mut_ptr() as u64, 0]); check("stat / (a made-up empty folder)", r, r == 0 && st[6] == 0 && st[2] as u32 & 0o170000 == 0o040000, "0, empty folder");
    let r = open(b"/\0", 0o40000); check("open / to list it", r, is(EACCES)(r), "EACCES");
    let r = sys(17, &[big.as_mut_ptr() as u64, 1]); check("getcwd into a 1-byte buffer", r, is(ERANGE)(r), "ERANGE");
    let r = sys(17, &[POLICY, 256]); check("getcwd(into policy table)", r, is(EFAULT)(r), "EFAULT");
    let r = sys(160, &[POLICY]); check("uname(into policy table)", r, is(EFAULT)(r), "EFAULT");
    let r = sys(129, &[1234, 9]); check("kill(another process)", r, is(ESRCH)(r), "ESRCH");
    let lim = [1u64 << 40, 1 << 40];
    let r = sys(261, &[0, 7, lim.as_ptr() as u64, 0]); check("prlimit64: raise my open-file limit", r, is(EPERM)(r), "EPERM");
    let r = sys(146, &[0]); check("setuid(0)", r, is(EPERM)(r), "EPERM");

    println!("-- /tmp: writable, but only inside the VM (new surface)");
    let r = open(b"/tmp/../etc/passwd\0", 0); check("open /tmp/../etc/passwd", r, is(EACCES)(r), "EACCES");
    let r = sys(34, &[AT_FDCWD, p(b"/tmp/no/such/parent\0"), 0o755]); check("mkdir /tmp/no/such/parent", r, is(ENOENT)(r), "ENOENT");
    let f = open(b"/tmp/a.txt\0", 0o102); check("create /tmp/a.txt", f, f >= 3, "an fd");
    let r = sys(64, &[f as u64, p(b"secret data"), 11]); check("write to it", r, r == 11, "11");
    let r = sys(38, &[AT_FDCWD, p(b"/tmp/a.txt\0"), AT_FDCWD, p(b"/workspace/a.txt\0")]); check("rename /tmp/a.txt -> /workspace (smuggle out)", r, is(EACCES)(r), "EACCES");
    let r = sys(38, &[AT_FDCWD, p(b"/workspace/notes.txt\0"), AT_FDCWD, p(b"/tmp/n.txt\0")]); check("rename /workspace/notes.txt -> /tmp (steal)", r, is(EACCES)(r), "EACCES");
    let r = sys(35, &[AT_FDCWD, p(b"/workspace/notes.txt\0"), 0]); check("unlink /workspace/notes.txt", r, is(EACCES)(r), "EACCES");
    let r = sys(35, &[AT_FDCWD, p(b"/tmp\0"), 0x200]); check("rmdir /tmp", r, is(EBUSY)(r), "EBUSY");
    sys(34, &[AT_FDCWD, p(b"/tmp/d\0"), 0o755]);
    let r = sys(38, &[AT_FDCWD, p(b"/tmp/d\0"), AT_FDCWD, p(b"/tmp/d/inside\0")]); check("rename a folder into itself", r, is(EINVAL)(r), "EINVAL");
    let rd = open(b"/tmp/a.txt\0", 0);
    let r = sys(64, &[rd as u64, p(b"x"), 1]); check("write to a read-only /tmp fd", r, is(EBADF)(r), "EBADF");
    let wr = open(b"/tmp/a.txt\0", 1);
    let r = sys(63, &[wr as u64, buf.as_mut_ptr() as u64, 1]); check("read from a write-only /tmp fd", r, is(EBADF)(r), "EBADF");
    let r = sys(35, &[AT_FDCWD, p(b"/tmp/a.txt\0"), 0]); check("unlink /tmp/a.txt while open", r, r == 0, "0");
    let r = sys(63, &[rd as u64, big.as_mut_ptr() as u64, 64]); check("...the open fd still reads it (like Linux)", r, r == 11 && &big[..11] == b"secret data", "11 bytes");
    for fd in [f, rd, wr] { sys(57, &[fd as u64]); }
    let n = open(b"/tmp/a.txt\0", 0o102);
    let r = sys(63, &[n as u64, big.as_mut_ptr() as u64, 64]); check("a new /tmp/a.txt starts empty (no old data)", r, r == 0, "0 bytes");
    let r = sys(62, &[n as u64, 1 << 40, 0]);
    let r2 = sys(64, &[n as u64, p(b"x"), 1]); check("seek to 1 TiB and write (a huge gap)", r2, r == 1 << 40 && is(ENOSPC)(r2), "ENOSPC");
    let r = sys(46, &[n as u64, 1 << 40]); check("ftruncate to 1 TiB", r, is(ENOSPC)(r), "ENOSPC");
    let r = sys(24, &[n as u64, 64, 0]); check("dup3 onto fd 64 (past the table)", r, is(EBADF)(r), "EBADF");
    let r = sys(25, &[n as u64, 0, 64]); check("fcntl(F_DUPFD, 64)", r, is(EINVAL)(r), "EINVAL");
    sys(57, &[n as u64]);
    let fds: Vec<i64> = (0..70).map(|i| open(format!("/tmp/f{i}\0").as_bytes(), 0o102)).collect();
    let first_bad = fds.iter().position(|&f| f < 0).unwrap_or(70);
    check("open 70 /tmp files at once", fds[first_bad.min(69)], first_bad == 61 && fds[61] == -24, "fd 3..63, then EMFILE");
    for f in fds { if f >= 0 { sys(57, &[f as u64]); } }
    let made = (0..300).map(|i| open(format!("/tmp/n{i}\0").as_bytes(), 0o102)).inspect(|&f| { if f >= 0 { sys(57, &[f as u64]); } })
        .take_while(|&f| f >= 0).count() as i64;
    check("create 300 /tmp files (256-entry table)", made, made < 256, "ENOSPC before 256");
    for i in 0..300 { sys(35, &[AT_FDCWD, p(format!("/tmp/n{i}\0").as_bytes()), 0]); }
    let r = open(b"/tmp/after-cleanup\0", 0o102); check("...after unlinking them, names are free again", r, r >= 3, "an fd");
    let chunk = vec![7u8; 64 << 10];
    let (mut total, mut last) = (0i64, 0i64);
    while total < 8 << 20 { last = sys(64, &[r as u64, chunk.as_ptr() as u64, chunk.len() as u64]); if last < 0 { break; } total += last; }
    check(&format!("fill /tmp past tmp_kb = 4096 (wrote {} KiB)", total >> 10), last, is(ENOSPC)(last) && total <= 4 << 20, "ENOSPC at <= 4 MiB");
    let r = sys(56, &[AT_FDCWD, HOLE, 0]); check("openat(path pointer into an unmapped hole)", r, is(EFAULT)(r), "EFAULT");
    let r = sys(63, &[3, HOLE, 16]); check("read(into an unmapped hole)", r, r < 0, "an error");

    println!("\n{pass} passed, {fail} failed");
    std::process::exit(if fail == 0 { 0 } else { 1 });
}

// ------------------------------------------------------------------------------------------------
#[inline(never)]
fn recurse(n: u64) -> u64 { let buf = black_box([n; 512]); if n == 0 { 0 } else { recurse(n - 1) + buf[7] } }

fn fatal(name: &str) {
    println!("redteam: attack '{name}'");
    unsafe {
        match name {
            "read-policy" => { black_box((POLICY as *const u64).read_volatile()); }
            "erase-audit-log" => (AUDIT_LOG as *mut u64).write_volatile(0),
            "edit-page-tables" => (PAGE_TABLES as *mut u64).write_volatile(0),
            "run-supervisor-code" => { let f: extern "C" fn() = std::mem::transmute(SUPERVISOR_CODE as usize); f() }
            "patch-own-code" => ((fatal as *const () as usize) as *mut u32).write_volatile(0xd503201f),
            "run-from-heap" => { let code = black_box(vec![0xd65f03c0u32]); let f: extern "C" fn() = std::mem::transmute(code.as_ptr()); f() }
            "run-from-stack" => { let code = black_box([0xd65f03c0u32; 4]); let f: extern "C" fn() = std::mem::transmute(code.as_ptr()); f() }
            "set-vector-table" => asm!("msr vbar_el1, {0}", in(reg) 0u64),
            "read-page-table-register" => { let x: u64; asm!("mrs {0}, ttbr0_el1", out(reg) x); black_box(x); }
            "turn-off-mmu" => asm!("msr sctlr_el1, xzr"),
            "hypervisor-call" => asm!("hvc #0"),
            "firmware-call" => asm!("smc #0"),
            "eret" => asm!("eret"),
            "ring-doorbell" => (DOORBELL as *mut u32).write_volatile(1),
            "touch-outside-ram" => { black_box((0x4000_0000 as *const u64).read_volatile()); }
            "zero-audit-log-dczva" => asm!("dc zva, {0}", in(reg) AUDIT_LOG),
            "beyond-memory-limit" => {
                let addr = MMAP_START + (33 << 20); // memory_mb = 32: one MiB past the end
                (addr as *mut u64).write_volatile(42);
                println!("redteam: wrote to {addr:#x}, past the memory limit, and read back {}", (addr as *const u64).read_volatile());
                // Go on: try to take all guest RAM up to the stack.
                let mut n = 0u64;
                for page in (MMAP_START..0x87b0_0000).step_by(4096) { (page as *mut u64).write_volatile(1); n += 1; }
                println!("redteam: touched {} MiB without asking for it", n * 4096 >> 20);
            }
            "stack-overflow" => { black_box(recurse(1 << 20)); }
            "wait-for-interrupt" => asm!("wfi"),
            "sleep-an-hour" => { sys(101, &[[3600u64, 0].as_ptr() as u64, 0]); }
            "spin" => loop { black_box(0); },
            _ => { println!("unknown attack"); std::process::exit(3) }
        }
    }
    println!("redteam: SURVIVED: attack '{name}' was not stopped");
    std::process::exit(0);
}

// ------------------------------------------------------------------------------------------------
fn fuzz(seed: u64, n: u64) {
    let mut s = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    let mut rnd = move || { s ^= s << 13; s ^= s >> 7; s ^= s << 17; s };
    let scratch = vec![0u8; 1 << 16];
    let sp = scratch.as_ptr() as u64;
    let interesting = [0, 1, 2, 3, 4, 8, 64, 4096, u64::MAX, u64::MAX - 4095, 1 << 63, 0x7fff_ffff, AT_FDCWD,
                       SUPERVISOR_CODE, HC_PAGE, POLICY, PAGE_TABLES, AUDIT_LOG, HOLE, DOORBELL, MMAP_START, 0x87ff_fff0];
    let allowed = [214, 222, 215, 226, 233, 96, 134, 135, 132, 73, 29, 113, 172, 178, 174, 64, 66, 56, 63, 57, 80, 62, 278,
                   17, 23, 24, 25, 34, 35, 38, 46, 48, 49, 50, 61, 65, 78, 79, 82, 123, 124, 144, 146, 148, 150, 154, 155,
                   157, 158, 160, 163, 165, 166, 173, 179, 261, 276, 439];
    let paths: [&[u8]; 8] = [b"/tmp/a\0", b"/tmp\0", b"/tmp/a/b\0", b"/workspace\0", b"..\0", b"/workspace/notes.txt\0", b"escape-link\0", b"/\0"];
    let mut ok = 0u64;
    for i in 0..n {
        let nr = match rnd() % 10 { 0..=5 => allowed[(rnd() % allowed.len() as u64) as usize], 6..=8 => rnd() % 460, _ => rnd() };
        if matches!(nr, 93 | 94 | 101 | 115 | 129 | 130 | 131) { continue; } // don't exit, sleep or signal ourselves
        let mut a = [0u64; 6];
        for x in &mut a {
            *x = match rnd() % 4 {
                0 => interesting[(rnd() % interesting.len() as u64) as usize],
                1 => sp + rnd() % (1 << 16),     // inside our scratch buffer
                2 => rnd() % 512,
                _ => rnd(),
            };
        }
        if (nr == 64 || nr == 66) && a[0] < 3 { a[2] %= 16; } // keep stdout small
        for i in 0..4 { if rnd() % 3 == 0 { a[i] = p(paths[(rnd() % paths.len() as u64) as usize]); } }
        if rnd() % 3 == 0 { a[0] = AT_FDCWD; }
        if unsafe { sc(nr, a) } >= 0 { ok += 1; }
        if i % 1000 == 999 { eprint!("."); }
    }
    // stdout may be closed or redirected by now (random dup3/close): the exit code is the signal.
    let _ = ok;
    unsafe { sc(94, [77, 0, 0, 0, 0, 0]); }
}

/// Open /workspace/d/passwd over and over while something on the host swaps `d` between a real
/// folder (holding a harmless file called passwd) and a symbolic link to /etc. Any read that returns
/// the host's /etc/passwd ("root:") is a leak.
fn race(n: u64) {
    let mut buf = [0u8; 64];
    let (mut inside, mut refused, mut leaked) = (0, 0, 0);
    for _ in 0..n {
        let fd = open(b"/workspace/d/passwd\0", 0);
        if fd < 0 { refused += 1; continue; }
        let r = sys(63, &[fd as u64, buf.as_mut_ptr() as u64, 64]);
        if r > 0 && buf.starts_with(b"root:") { leaked += 1 } else { inside += 1 }
        sys(57, &[fd as u64]);
    }
    println!("race: {n} opens: {inside} read the workspace's own file, {refused} refused or missing, {leaked} LEAKED the host's /etc/passwd");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("probe") => probe(),
        Some("fatal") => fatal(args.get(2).map_or("", |s| s.as_str())),
        Some("race") => race(args.get(2).and_then(|s| s.parse().ok()).unwrap_or(3000)),
        Some("fuzz") => fuzz(args.get(2).and_then(|s| s.parse().ok()).unwrap_or(1), args.get(3).and_then(|s| s.parse().ok()).unwrap_or(5000)),
        _ => println!("usage: redteam probe | fatal NAME | fuzz SEED N"),
    }
}
