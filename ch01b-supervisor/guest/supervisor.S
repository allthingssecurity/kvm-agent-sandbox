// Chapter 1b supervisor: runs at guest level 0 (EL1). Plays the role of libDune.
//
//   1. Points VBAR_EL1 (the "system calls and faults come here" register) at its own handlers.
//   2. Turns on the page tables the VMM prepared (its pages: EL1 only; agent pages: EL0 allowed).
//   3. Drops to guest level 3 (EL0) into the agent code with `eret`.
//   4. From then on every system call and every fault of the agent lands in `from_el0_sync`:
//      allowed calls are forwarded to the VMM through a "doorbell" write (a VM exit);
//      denied calls and faults are handled here and never leave guest mode.
//   Everything it decides is recorded in an audit log in its own memory, which the VMM reads afterwards.

    .equ HC_PAGE,       0x80040000   // shared page: supervisor writes a request, VMM writes the result
    .equ PT_L1,         0x80050000   // top-level page table (built by the VMM, owned by us)
    .equ SUP_STACK_TOP, 0x80070000
    .equ LOG_BASE,      0x80070000   // audit log: u64 count, then 48-byte entries from +64
    .equ LOG_MAX,       100
    .equ AGENT_STACK,   0x80030000
    .equ AGENT_LO,      0x80010000   // pointers from the agent must lie in [AGENT_LO, AGENT_HI)
    .equ AGENT_HI,      0x80031000
    .equ DOORBELL,      0x09000000   // no memory here: a store traps out of guest mode to KVM -> VMM

    .equ HC_WRITE, 1                 // requests to the VMM
    .equ HC_EXIT,  2
    .equ HC_PANIC, 3

    .equ LOG_ALLOWED, 1              // audit log entry kinds
    .equ LOG_DENIED,  2
    .equ LOG_FAULT,   3
    .equ LOG_EXIT,    4

    .equ SYS_WRITE, 64               // Linux arm64 system call numbers
    .equ SYS_EXIT,  93
    .equ EACCES,    13
    .equ EFAULT,    14

    .section .text.sup, "awx"
    .global sup_start
sup_start:
    ldr   x0, =SUP_STACK_TOP
    mov   sp, x0

    // 1. "System calls and faults come to me."
    adr   x0, vectors
    msr   vbar_el1, x0

    // 2. Install our page tables and turn the MMU on.
    mov   x0, #0x00ff                // MAIR: attribute 0 = normal cacheable memory, attribute 1 = device
    msr   mair_el1, x0
    ldr   x0, =0x200803519           // TCR: 4 KiB pages, 39-bit addresses, 40-bit physical, no TTBR1
    msr   tcr_el1, x0
    ldr   x0, =PT_L1
    msr   ttbr0_el1, x0
    isb
    tlbi  vmalle1
    dsb   nsh
    isb
    mrs   x0, sctlr_el1
    orr   x0, x0, #1                 // M: MMU on
    orr   x0, x0, #(1 << 2)          // C: data cache on
    orr   x0, x0, #(1 << 12)         // I: instruction cache on
    msr   sctlr_el1, x0
    isb

    // 3. Drop to guest level 3 (EL0) and start the agent code.
    ldr   x0, =agent_start
    msr   elr_el1, x0                // where `eret` goes
    ldr   x0, =AGENT_STACK
    msr   sp_el0, x0
    mov   x0, #0x3c0                 // SPSR: return to EL0, interrupts masked
    msr   spsr_el1, x0
    mov   x0, #0                     // don't leak supervisor values to the agent
    mov   x1, #0
    eret

// ---------------------------------------------------------------------------------------------
// Exception vectors: 16 slots of 0x80 bytes. The CPU picks a slot by where the exception came from.
// ---------------------------------------------------------------------------------------------
    .macro ventry target
    .balign 0x80
    b     \target
    .endm

    .balign 0x800
vectors:
    ventry sup_panic                 // from EL1 using SP_EL0
    ventry sup_panic
    ventry sup_panic
    ventry sup_panic
    ventry sup_panic                 // from EL1 using SP_EL1: a bug in the supervisor itself
    ventry sup_panic
    ventry sup_panic
    ventry sup_panic
    ventry from_el0_sync             // from EL0 (64-bit), synchronous: system calls and faults
    ventry sup_panic                 // from EL0, IRQ (not used)
    ventry sup_panic
    ventry sup_panic
    ventry sup_panic                 // from EL0 (32-bit): not used
    ventry sup_panic
    ventry sup_panic
    ventry sup_panic

// ---------------------------------------------------------------------------------------------
// Everything the agent does that needs level 0 arrives here.
// ---------------------------------------------------------------------------------------------
from_el0_sync:
    sub   sp, sp, #256               // save all agent registers on the supervisor stack
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

    mrs   x9, esr_el1                // why are we here? (exception syndrome)
    lsr   x10, x9, #26               // exception class
    cmp   x10, #0x15                 // 0x15 = SVC instruction from 64-bit code
    b.eq  handle_svc

    // Anything else (writing protected memory, a privileged instruction, ...): the CPU blocked it.
    // Record it and skip the instruction. A real sandbox would kill the agent instead.
    mov   x0, #LOG_FAULT
    mov   x1, x9
    mrs   x2, far_el1                // the address it tried to touch
    mrs   x3, elr_el1                // the instruction that did it
    mov   x4, #0
    bl    log_event
    mrs   x3, elr_el1
    add   x3, x3, #4
    msr   elr_el1, x3
    b     restore

handle_svc:                          // Linux convention: x8 = call number, x0..x2 = arguments
    ldr   x8, [sp, #64]
    cmp   x8, #SYS_WRITE
    b.eq  sys_write
    cmp   x8, #SYS_EXIT
    b.eq  sys_exit
    // Not on the allow-list.
deny_eacces:
    mov   x5, #-EACCES
deny:                                // x5 = error to return
    mov   x0, #LOG_DENIED
    ldr   x1, [sp, #64]
    ldr   x2, [sp, #0]
    ldr   x3, [sp, #8]
    ldr   x4, [sp, #16]
    bl    log_event
    str   x5, [sp, #0]               // the agent sees this in x0
    b     restore
deny_efault:
    mov   x5, #-EFAULT
    b     deny

sys_write:
    ldr   x0, [sp, #0]               // fd: only stdout and stderr
    cmp   x0, #1
    b.eq  1f
    cmp   x0, #2
    b.ne  deny_eacces
1:  ldr   x1, [sp, #8]               // buffer pointer: never trust it
    ldr   x2, [sp, #16]              // length
    ldr   x6, =AGENT_LO
    cmp   x1, x6
    b.lo  deny_efault
    adds  x7, x1, x2                 // end = buf + len, rejecting wrap-around
    b.cs  deny_efault
    ldr   x6, =AGENT_HI
    cmp   x7, x6
    b.hi  deny_efault

    mov   x0, #LOG_ALLOWED
    ldr   x1, [sp, #64]
    ldr   x2, [sp, #0]
    ldr   x3, [sp, #8]
    ldr   x4, [sp, #16]
    bl    log_event
    ldr   x6, =HC_PAGE               // ask the VMM to do the real write
    mov   x0, #HC_WRITE
    ldr   x1, [sp, #8]
    ldr   x2, [sp, #16]
    stp   x0, x1, [x6]
    str   x2, [x6, #16]
    bl    hypercall
    ldr   x0, [x6, #32]              // result written by the VMM
    str   x0, [sp, #0]
    b     restore

sys_exit:
    mov   x0, #LOG_EXIT
    ldr   x1, [sp, #0]
    mov   x2, #0
    mov   x3, #0
    mov   x4, #0
    bl    log_event
    ldr   x6, =HC_PAGE
    mov   x0, #HC_EXIT
    ldr   x1, [sp, #0]
    stp   x0, x1, [x6]
    bl    hypercall
    b     .                          // the VMM does not resume us

restore:
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
    eret                             // back to the agent at EL0

// Ring the doorbell: a store to an address with no memory. This is the only way out of guest mode.
hypercall:
    ldr   x7, =DOORBELL
    dsb   sy                         // make the request in HC_PAGE visible first
    str   xzr, [x7]                  // -> VM exit -> KVM -> KVM_RUN returns in the VMM
    ret

// Append {kind=x0, x1, x2, x3, x4, x5} to the audit log. Clobbers x6, x7, x9.
log_event:
    ldr   x6, =LOG_BASE
    ldr   x7, [x6]
    cmp   x7, #LOG_MAX
    b.hs  1f
    add   x9, x7, #1
    str   x9, [x6]
    mov   x9, #48
    mul   x7, x7, x9
    add   x7, x7, x6
    add   x7, x7, #64
    stp   x0, x1, [x7]
    stp   x2, x3, [x7, #16]
    stp   x4, x5, [x7, #32]
1:  ret

// A fault inside the supervisor itself: report it to the VMM and stop.
sup_panic:
    ldr   x6, =HC_PAGE
    mov   x0, #HC_PANIC
    mrs   x1, esr_el1
    mrs   x2, elr_el1
    mrs   x3, far_el1
    stp   x0, x1, [x6]
    stp   x2, x3, [x6, #16]
    bl    hypercall
    b     .

    .ltorg
