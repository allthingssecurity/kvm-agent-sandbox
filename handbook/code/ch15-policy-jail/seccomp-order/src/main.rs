//! A seccomp argument check that never fired (chapter 15, war story).
//!   seccomp-order wrong   a plain "allow openat" comes before the check
//!   seccomp-order right   only the argument check mentions openat
//! Then it opens /dev/null for reading (fine) and for writing (must die).

use std::fs::File;

#[repr(C)]
struct SockFilter { code: u16, jt: u8, jf: u8, k: u32 }
#[repr(C)]
struct SockFprog { len: u16, filter: *const SockFilter }

const LD_ABS: u16 = 0x20; // load a 32-bit word of the call's data
const JEQ: u16 = 0x15; // jump if equal
const JSET: u16 = 0x45; // jump if (A & k) != 0
const RET: u16 = 0x06;
const ALLOW: u32 = 0x7fff_0000;
const KILL: u32 = 0x8000_0000; // kill the whole process
const ARCH: u32 = 0xc000_00b7; // AUDIT_ARCH_AARCH64
const NR: u32 = 0; // offsets into struct seccomp_data
const ARCH_OFF: u32 = 4;
const ARG2: u32 = 32; // low 32 bits of the third argument

fn f(code: u16, k: u32, jt: u8, jf: u8) -> SockFilter {
    SockFilter { code, jt, jf, k }
}

fn main() {
    let wrong = std::env::args().nth(1).as_deref() == Some("wrong");
    let openat = libc::SYS_openat as u32;
    let writes = (libc::O_WRONLY | libc::O_RDWR | libc::O_CREAT
        | libc::O_TRUNC | libc::O_APPEND) as u32;
    let mut prog = vec![
        f(LD_ABS, ARCH_OFF, 0, 0),
        f(JEQ, ARCH, 1, 0),
        f(RET, KILL, 0, 0),
        f(LD_ABS, NR, 0, 0),
    ];
    if wrong {
        // the old list of plain allows still had openat in it
        prog.push(f(JEQ, openat, 0, 1));
        prog.push(f(RET, ALLOW, 0, 0));
    }
    prog.push(f(JEQ, openat, 0, 3)); // not openat: skip to the last ALLOW
    prog.push(f(LD_ABS, ARG2, 0, 0)); // openat's flags
    prog.push(f(JSET, writes, 0, 1)); // a write flag: kill, else allow
    prog.push(f(RET, KILL, 0, 0));
    prog.push(f(RET, ALLOW, 0, 0)); // this demo leaves other calls alone

    let fprog = SockFprog { len: prog.len() as u16, filter: prog.as_ptr() };
    unsafe {
        assert_eq!(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), 0);
        let r = libc::syscall(libc::SYS_seccomp, 1, 0, &fprog); // set filter
        assert_eq!(r, 0, "seccomp");
    }
    println!("filter: {} instructions ({} order)", prog.len(),
             if wrong { "wrong" } else { "right" });
    println!("open /dev/null for reading: {:?}",
             File::open("/dev/null").map(|_| "ok"));
    let w = File::options().write(true).open("/dev/null");
    println!("open /dev/null for writing: {:?} (the check never fired)",
             w.map(|_| "ok"));
}
