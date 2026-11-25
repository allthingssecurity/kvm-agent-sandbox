// hello.S: print a line and exit, with no C library at all.
// Build: gcc -nostdlib -static -o hello hello.S
// Linux arm64 system calls: number in x8, arguments in x0..x5,
// "svc #0" to ask, result comes back in x0.

        .global _start
        .text
_start:
        mov     x0, #1                  // fd 1: standard output
        adr     x1, msg                 // address of the bytes
        mov     x2, #len                // how many bytes
        mov     x8, #64                 // 64 = write
        svc     #0                      // ask the kernel

        mov     x0, #0                  // exit status 0
        mov     x8, #93                 // 93 = exit
        svc     #0                      // never returns

msg:    .ascii  "hello from svc\n"
        len = . - msg
