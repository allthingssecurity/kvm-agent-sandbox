// Chapter 1b agent code: untrusted, runs at guest level 3 (EL0) under the supervisor.
// It makes ordinary Linux-style system calls (x8 = call number, x0..x2 = arguments, `svc #0`)
// and tries six things, three of them attacks. It has no idea a supervisor is watching.

    .equ SYS_OPENAT, 56
    .equ SYS_WRITE,  64
    .equ SYS_EXIT,   93
    .equ AT_FDCWD,   -100

    .macro say msg                   // print a string from this file
    adr   x1, \msg
    mov   x2, #(\msg\()_end - \msg)
    bl    print
    .endm

    .section .text.agent, "ax"
    .global agent_start
agent_start:
    // 1. A normal, allowed system call.
    say   m_hello

    // 2. Try to open the user's SSH key.
    say   m_try_ssh
    mov   x0, #AT_FDCWD
    adr   x1, p_ssh
    mov   x2, #0
    mov   x8, #SYS_OPENAT
    svc   #0
    bl    report

    // 3. Try to trick the supervisor into printing ITS memory (a pointer that isn't ours).
    say   m_try_leak
    mov   x0, #1
    ldr   x1, =0x80000000
    mov   x2, #64
    mov   x8, #SYS_WRITE
    svc   #0
    bl    report

    // 4. Write to a page the supervisor made read-only.
    say   m_try_ro
    ldr   x3, =0x80030000
    mov   w4, #'X'
    strb  w4, [x3]
    say   m_blocked

    // 5. Overwrite the supervisor's own code.
    say   m_try_sup
    ldr   x3, =0x80000000
    strb  w4, [x3]
    say   m_blocked

    // 6. Take over the door: point "system calls go here" at our own code.
    say   m_try_door
    adr   x0, agent_start
    msr   vbar_el1, x0
    say   m_blocked

    // Done.
    say   m_bye
    mov   x0, #0
    mov   x8, #SYS_EXIT
    svc   #0

print:                               // x1 = text, x2 = length
    mov   x0, #1
    mov   x8, #SYS_WRITE
    svc   #0
    ret

report:                              // print what a system call returned (x0)
    cmn   x0, #13
    b.eq  1f
    cmn   x0, #14
    b.eq  2f
    adr   x1, m_ok
    mov   x2, #(m_ok_end - m_ok)
    b     print
1:  adr   x1, m_eacces
    mov   x2, #(m_eacces_end - m_eacces)
    b     print
2:  adr   x1, m_efault
    mov   x2, #(m_efault_end - m_efault)
    b     print

m_hello:     .ascii "agent: 1. hello, printing through a normal system call\n"
m_hello_end:
m_try_ssh:   .ascii "agent: 2. open(\"~/.ssh/id_rsa\")\n"
m_try_ssh_end:
m_try_leak:  .ascii "agent: 3. print 64 bytes of the supervisor's memory\n"
m_try_leak_end:
m_try_ro:    .ascii "agent: 4. write to the read-only page\n"
m_try_ro_end:
m_try_sup:   .ascii "agent: 5. overwrite the supervisor's code\n"
m_try_sup_end:
m_try_door:  .ascii "agent: 6. take over the system-call door\n"
m_try_door_end:
m_bye:       .ascii "agent: done, exiting\n"
m_bye_end:
m_ok:        .ascii "          -> allowed\n"
m_ok_end:
m_eacces:    .ascii "          -> refused by the supervisor (not on the allow-list)\n"
m_eacces_end:
m_efault:    .ascii "          -> refused by the supervisor (that memory isn't yours)\n"
m_efault_end:
m_blocked:   .ascii "          -> blocked by the CPU; the supervisor noted it, agent continues\n"
m_blocked_end:
p_ssh:       .asciz "~/.ssh/id_rsa"

    .ltorg
