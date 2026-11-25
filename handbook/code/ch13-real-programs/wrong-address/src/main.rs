//! Print what the loader (Linux's execve, or our VMM) left on the starting
//! stack. musl saves the auxiliary vector at start-up; getauxval reads it.

unsafe extern "C" {
    fn getauxval(kind: u64) -> u64;
}

fn main() {
    for (i, arg) in std::env::args().enumerate() {
        println!("argv[{i}]     = {arg:?}");
    }
    println!("envp       = {} variables", std::env::vars().count());
    let wanted = [
        (3, "AT_PHDR"), (4, "AT_PHENT"), (5, "AT_PHNUM"),
        (6, "AT_PAGESZ"), (9, "AT_ENTRY"), (11, "AT_UID"),
        (23, "AT_SECURE"), (25, "AT_RANDOM"),
    ];
    for (kind, name) in wanted {
        println!("{name:<10} = {:#x}", unsafe { getauxval(kind) });
    }
    // 16 random bytes the loader put on the stack (musl seeds its
    // stack canary from them).
    let random = unsafe { getauxval(25) } as *const [u8; 16];
    if !random.is_null() {
        let bytes = unsafe { *random };
        println!("random     = {:02x?}", &bytes[..4]);
    }
    println!("main       = {:#x}", main as *const () as usize);
}
