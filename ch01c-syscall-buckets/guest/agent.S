// Chapter 1c agent code (guest level 3). Ordinary Linux-style system calls, in three groups.
// It doesn't know which bucket each one lands in: only the supervisor decides.

    .equ SYS_OPENAT, 56
    .equ SYS_CLOSE,  57
    .equ SYS_READ,   63
    .equ SYS_WRITE,  64
    .equ SYS_EXIT,   93
    .equ SYS_CLOCK_GETTIME, 113
    .equ SYS_REBOOT, 142
    .equ SYS_GETPID, 172
    .equ SYS_MMAP,   222
    .equ AT_FDCWD,   -100
    .equ TS_BUF,     0x80028000      // agent data memory (read/write for the agent)
    .equ READ_BUF,   0x80029000

    .macro say msg
    adr   x1, \msg
    mov   x2, #(\msg\()_end - \msg)
    bl    print
    .endm

    .macro open path
    mov   x0, #AT_FDCWD
    adr   x1, \path
    mov   x2, #0
    mov   x8, #SYS_OPENAT
    svc   #0
    .endm

    .section .text.agent, "ax"
    .global agent_start
agent_start:
    // ---------------- calls the supervisor can answer itself ----------------
    say   h_answer
    say   m_getpid
    mov   x8, #SYS_GETPID
    svc   #0
    bl    print_dec
    say   m_nl

    say   m_clock
    mov   x0, #1                     // CLOCK_MONOTONIC
    ldr   x1, =TS_BUF
    mov   x8, #SYS_CLOCK_GETTIME
    svc   #0
    ldr   x1, =TS_BUF
    ldr   x0, [x1]
    bl    print_dec
    say   m_sec
    ldr   x1, =TS_BUF
    ldr   x0, [x1, #8]
    bl    print_dec
    say   m_ns

    say   m_mmap
    mov   x0, #0
    mov   x1, #4096
    mov   x2, #3                     // read + write
    mov   x3, #0x22                  // private, anonymous
    mov   x4, #-1
    mov   x5, #0
    mov   x8, #SYS_MMAP
    svc   #0
    mov   x19, x0                    // the address we were given
    bl    print_hex
    say   m_nl
    mov   w4, #'Z'
    strb  w4, [x19]                  // use the new memory
    ldrb  w5, [x19]
    cmp   w5, #'Z'
    b.ne  1f
    say   m_mmap_ok
1:
    // ---------------- calls the supervisor refuses ----------------
    say   h_refuse
    say   m_ssh
    open  p_ssh
    bl    report
    say   m_dotdot
    open  p_dotdot
    bl    report
    say   m_reboot
    mov   x0, #0
    mov   x8, #SYS_REBOOT
    svc   #0
    bl    report
    say   m_leak
    mov   x0, #1
    ldr   x1, =0x80000000            // the supervisor's memory, not ours
    mov   x2, #64
    mov   x8, #SYS_WRITE
    svc   #0
    bl    report

    // ---------------- calls the supervisor forwards to the host ----------------
    say   h_forward
    say   m_open
    open  p_notes
    mov   x20, x0                    // file descriptor
    bl    print_dec
    say   m_nl
    say   m_read
    mov   x0, x20
    ldr   x1, =READ_BUF
    mov   x2, #512
    mov   x8, #SYS_READ
    svc   #0
    mov   x21, x0                    // bytes read
    bl    print_dec
    say   m_bytes
    mov   x0, #1                     // print what we read
    ldr   x1, =READ_BUF
    mov   x2, x21
    mov   x8, #SYS_WRITE
    svc   #0
    say   m_close
    mov   x0, x20
    mov   x8, #SYS_CLOSE
    svc   #0
    bl    report

    say   m_bye
    mov   x0, #0
    mov   x8, #SYS_EXIT
    svc   #0

// ---------------- little helpers (no C library down here) ----------------
print:                               // x1 = text, x2 = length
    mov   x0, #1
    mov   x8, #SYS_WRITE
    svc   #0
    ret

report:                              // explain a system call's result in x0
    cmn   x0, #1
    b.eq  1f
    cmn   x0, #13
    b.eq  2f
    cmn   x0, #14
    b.eq  3f
    adr   x1, r_ok
    mov   x2, #(r_ok_end - r_ok)
    b     print
1:  adr   x1, r_eperm
    mov   x2, #(r_eperm_end - r_eperm)
    b     print
2:  adr   x1, r_eacces
    mov   x2, #(r_eacces_end - r_eacces)
    b     print
3:  adr   x1, r_efault
    mov   x2, #(r_efault_end - r_efault)
    b     print

print_dec:                           // print x0 as a decimal number
    stp   x29, x30, [sp, #-48]!
    add   x9, sp, #47
    mov   x10, #10
    mov   x11, x9
1:  udiv  x12, x0, x10
    msub  x13, x12, x10, x0
    add   w13, w13, #'0'
    sub   x11, x11, #1
    strb  w13, [x11]
    mov   x0, x12
    cbnz  x0, 1b
    mov   x1, x11
    sub   x2, x9, x11
    bl    print
    ldp   x29, x30, [sp], #48
    ret

print_hex:                           // print x0 as 0x followed by 16 hex digits
    stp   x29, x30, [sp, #-48]!
    mov   x9, x0
    add   x11, sp, #16
    mov   w12, #'0'
    strb  w12, [x11]
    mov   w12, #'x'
    strb  w12, [x11, #1]
    add   x13, x11, #2
    mov   x14, #60
2:  lsr   x15, x9, x14
    and   x15, x15, #0xf
    cmp   x15, #10
    b.lo  3f
    add   x15, x15, #('a' - 10 - '0')
3:  add   x15, x15, #'0'
    strb  w15, [x13], #1
    subs  x14, x14, #4
    b.ge  2b
    mov   x1, x11
    mov   x2, #18
    bl    print
    ldp   x29, x30, [sp], #48
    ret

h_answer:   .ascii "\n== 1. ANSWER IT: the supervisor answers by itself ==\n"
h_answer_end:
m_getpid:   .ascii "agent: getpid()                         = "
m_getpid_end:
m_clock:    .ascii "agent: clock_gettime()                  = "
m_clock_end:
m_sec:      .ascii " s + "
m_sec_end:
m_ns:       .ascii " ns\n"
m_ns_end:
m_mmap:     .ascii "agent: mmap(4 KiB)                      = "
m_mmap_end:
m_mmap_ok:  .ascii "agent: wrote 'Z' into the new memory and read it back: it works\n"
m_mmap_ok_end:
h_refuse:   .ascii "\n== 2. REFUSE IT: the supervisor says no ==\n"
h_refuse_end:
m_ssh:      .ascii "agent: open(\"~/.ssh/id_rsa\")"
m_ssh_end:
m_dotdot:   .ascii "agent: open(\"/workspace/../etc/passwd\")"
m_dotdot_end:
m_reboot:   .ascii "agent: reboot()"
m_reboot_end:
m_leak:     .ascii "agent: write(1, <supervisor memory>)"
m_leak_end:
h_forward:  .ascii "\n== 3. FORWARD IT: the supervisor approves, the VMM does it on the host ==\n"
h_forward_end:
m_open:     .ascii "agent: open(\"/workspace/notes.txt\")     = fd "
m_open_end:
m_read:     .ascii "agent: read(fd, 512)                    = "
m_read_end:
m_bytes:    .ascii " bytes:\n"
m_bytes_end:
m_close:    .ascii "agent: close(fd)"
m_close_end:
m_bye:      .ascii "\nagent: done\n"
m_bye_end:
m_nl:       .ascii "\n"
m_nl_end:
r_ok:       .ascii "  -> ok\n"
r_ok_end:
r_eperm:    .ascii "  -> refused: EPERM (not on the allow-list)\n"
r_eperm_end:
r_eacces:   .ascii "  -> refused: EACCES (path not allowed)\n"
r_eacces_end:
r_efault:   .ascii "  -> refused: EFAULT (that memory isn't yours)\n"
r_efault_end:
p_ssh:      .asciz "~/.ssh/id_rsa"
p_dotdot:   .asciz "/workspace/../etc/passwd"
p_notes:    .asciz "/workspace/notes.txt"

    .ltorg
