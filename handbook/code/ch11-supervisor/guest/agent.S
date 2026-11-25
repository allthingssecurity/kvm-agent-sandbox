// Chapter 11 demo agent (EL0). The supervisor and the VMM are the unchanged
// ones from ch01b-supervisor. The agent tries to skip the supervisor and
// ring the VMM's doorbell itself, with the same store the supervisor uses.

    .equ SYS_WRITE, 64
    .equ SYS_EXIT,  93
    .equ DOORBELL,  0x09000000

    .macro say msg
    adr   x1, \msg
    mov   x2, #(\msg\()_end - \msg)
    mov   x0, #1
    mov   x8, #SYS_WRITE
    svc   #0
    .endm

    .section .text.agent, "ax"
    .global agent_start
agent_start:
    say   m_try
    ldr   x7, =DOORBELL
    str   xzr, [x7]                  // what the supervisor's hypercall does
    say   m_back
    mov   x0, #0
    mov   x8, #SYS_EXIT
    svc   #0

m_try:   .ascii "agent: ring the doorbell myself\n"
m_try_end:
m_back:  .ascii "agent: still here, the store did nothing\n"
m_back_end:

    .ltorg
