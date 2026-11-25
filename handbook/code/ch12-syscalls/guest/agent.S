// Chapter 12 demo agent (EL0). The supervisor is the unchanged one from
// ch01c-syscall-buckets. The agent passes openat() a path pointer that is
// inside the range the supervisor accepts, but on a page nobody mapped.

    .equ SYS_OPENAT, 56
    .equ SYS_WRITE,  64
    .equ SYS_EXIT,   93
    .equ AT_FDCWD,   -100
    .equ HOLE,       0x80031000      // below AGENT_HI, but not mapped

    .section .text.agent, "ax"
    .global agent_start
agent_start:
    adr   x1, m_try
    mov   x2, #(m_try_end - m_try)
    mov   x0, #1
    mov   x8, #SYS_WRITE
    svc   #0

    mov   x0, #AT_FDCWD
    ldr   x1, =HOLE
    mov   x2, #0
    mov   x8, #SYS_OPENAT
    svc   #0

    adr   x1, m_back                 // only reached if the supervisor survives
    mov   x2, #(m_back_end - m_back)
    mov   x0, #1
    mov   x8, #SYS_WRITE
    svc   #0
    mov   x0, #0
    mov   x8, #SYS_EXIT
    svc   #0

m_try:   .ascii "agent: open(<pointer into an unmapped page>)\n"
m_try_end:
m_back:  .ascii "agent: the call came back\n"
m_back_end:

    .ltorg
