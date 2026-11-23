// Chapter 1c supervisor (guest level 0): every system call of the agent arrives here and goes into
// one of three buckets.
//
//   ANSWER IT   getpid, clock_gettime, mmap      handled right here, no exit
//   REFUSE IT   anything not allowed             error returned right here, no exit
//   FORWARD IT  write, openat, read, close       checked here, then the doorbell: exit to the VMM,
//                                                which makes the real system call on the host
//
// Every decision goes into the notebook (audit log), which the VMM reads after the run.

    .equ RAM_BASE,      0x80000000
    .equ HC_PAGE,       0x80040000   // doorbell request page: [0] op, [8] a, [16] b, [24] c, [32] result
    .equ PT_L1,         0x80050000
    .equ PT_L3,         0x80053000   // last-level page table for our RAM (one entry per 4 KiB page)
    .equ SUP_STACK_TOP, 0x80070000
    .equ LOG_BASE,      0x80070000   // notebook: u64 count, then 48-byte entries from +64
    .equ LOG_MAX,       200
    .equ AGENT_STACK,   0x80030000
    .equ AGENT_LO,      0x80010000   // memory the agent may read:  [AGENT_LO, AGENT_HI)
    .equ AGENT_HI,      0x80040000
    .equ AGENT_W_LO,    0x80020000   // memory the agent may write: [AGENT_W_LO, AGENT_W_HI)
    .equ AGENT_W_HI,    0x80030000
    .equ POOL_HI,       0x80040000   // mmap hands out pages from 0x80032000 up to here
    .equ DOORBELL,      0x09000000
    .equ PAGE_EL0_RW,   0x0060000000000743   // page entry: valid, normal memory, EL0+EL1 read/write, no exec

    .equ HC_WRITE, 1                 // doorbell requests (handled by the VMM)
    .equ HC_EXIT,  2
    .equ HC_PANIC, 3
    .equ HC_OPEN,  4
    .equ HC_READ,  5
    .equ HC_CLOSE, 6

    .equ LOG_FORWARDED, 1            // notebook entry kinds
    .equ LOG_REFUSED,   2
    .equ LOG_FAULT,     3
    .equ LOG_EXIT,      4
    .equ LOG_ANSWERED,  5

    .equ SYS_OPENAT, 56              // Linux arm64 system call numbers
    .equ SYS_CLOSE,  57
    .equ SYS_READ,   63
    .equ SYS_WRITE,  64
    .equ SYS_EXIT,   93
    .equ SYS_CLOCK_GETTIME, 113
    .equ SYS_REBOOT, 142
    .equ SYS_GETPID, 172
    .equ SYS_MMAP,   222
    .equ EPERM,  1
    .equ EBADF,  9
    .equ ENOMEM, 12
    .equ EACCES, 13
    .equ EFAULT, 14
    .equ EINVAL, 22

    // Is [ptr, ptr+len) inside [lo, hi)? If not, branch to fail. Clobbers x6, x7.
    .macro check_buf ptr, len, lo, hi, fail
    ldr   x6, =\lo
    cmp   \ptr, x6
    b.lo  \fail
    adds  x7, \ptr, \len
    b.cs  \fail
    ldr   x6, =\hi
    cmp   x7, x6
    b.hi  \fail
    .endm

    // Write a notebook entry for the current system call; x5 = its result.
    .macro log_call kind
    mov   x0, #\kind
    ldr   x1, [sp, #64]              // call number
    ldr   x2, [sp, #0]               // arguments
    ldr   x3, [sp, #8]
    ldr   x4, [sp, #16]
    bl    log_event
    .endm

    .section .text.sup, "awx"
    .global sup_start
sup_start:
    ldr   x0, =SUP_STACK_TOP
    mov   sp, x0
    adr   x0, vectors                // the door: system calls and faults come to us
    msr   vbar_el1, x0
    mov   x0, #0x00ff                // memory types: 0 = normal, 1 = device
    msr   mair_el1, x0
    ldr   x0, =0x200803519           // 4 KiB pages, 39-bit addresses, 40-bit physical
    msr   tcr_el1, x0
    ldr   x0, =PT_L1
    msr   ttbr0_el1, x0
    isb
    tlbi  vmalle1
    dsb   nsh
    isb
    mrs   x0, sctlr_el1
    orr   x0, x0, #1                 // MMU on
    orr   x0, x0, #(1 << 2)          // data cache on
    orr   x0, x0, #(1 << 12)         // instruction cache on
    msr   sctlr_el1, x0
    isb
    ldr   x0, =agent_start           // drop to guest level 3 and start the agent
    msr   elr_el1, x0
    ldr   x0, =AGENT_STACK
    msr   sp_el0, x0
    mov   x0, #0x3c0
    msr   spsr_el1, x0
    mov   x0, #0
    mov   x1, #0
    eret

    .macro ventry target
    .balign 0x80
    b     \target
    .endm

    .balign 0x800
vectors:
    ventry sup_panic
    ventry sup_panic
    ventry sup_panic
    ventry sup_panic
    ventry sup_panic
    ventry sup_panic
    ventry sup_panic
    ventry sup_panic
    ventry from_el0_sync             // from the agent: system calls and faults
    ventry sup_panic
    ventry sup_panic
    ventry sup_panic
    ventry sup_panic
    ventry sup_panic
    ventry sup_panic
    ventry sup_panic

from_el0_sync:
    sub   sp, sp, #256               // save all agent registers
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
    mrs   x9, esr_el1
    lsr   x10, x9, #26
    cmp   x10, #0x15                 // a system call?
    b.eq  handle_svc
    // A fault the CPU blocked: note it, skip the instruction.
    mov   x0, #LOG_FAULT
    mov   x1, x9
    mrs   x2, far_el1
    mrs   x3, elr_el1
    mov   x4, #0
    mov   x5, #0
    bl    log_event
    mrs   x3, elr_el1
    add   x3, x3, #4
    msr   elr_el1, x3
    b     restore

handle_svc:
    ldr   x8, [sp, #64]
    cmp   x8, #SYS_GETPID            // ANSWER IT
    b.eq  sys_getpid
    cmp   x8, #SYS_CLOCK_GETTIME
    b.eq  sys_clock_gettime
    cmp   x8, #SYS_MMAP
    b.eq  sys_mmap
    cmp   x8, #SYS_WRITE             // FORWARD IT (after checks)
    b.eq  sys_write
    cmp   x8, #SYS_OPENAT
    b.eq  sys_openat
    cmp   x8, #SYS_READ
    b.eq  sys_read
    cmp   x8, #SYS_CLOSE
    b.eq  sys_close
    cmp   x8, #SYS_EXIT
    b.eq  sys_exit
    mov   x5, #-EPERM                // REFUSE IT: not on the allow-list at all
    b     refuse

deny_eacces:  mov x5, #-EACCES
              b   refuse
deny_efault:  mov x5, #-EFAULT
              b   refuse
deny_ebadf:   mov x5, #-EBADF
              b   refuse
deny_einval:  mov x5, #-EINVAL
              b   refuse
deny_enomem:  mov x5, #-ENOMEM
refuse:
    log_call LOG_REFUSED
    str   x5, [sp, #0]               // the agent sees the error in x0
    b     restore

// ------------------------------- ANSWER IT: no exit -------------------------------------------

sys_getpid:                          // "which process am I?" We decide: process 1.
    mov   x5, #1
    log_call LOG_ANSWERED
    str   x5, [sp, #0]
    b     restore

sys_clock_gettime:                   // read the CPU's own clock and convert it to seconds + ns
    ldr   x1, [sp, #8]               // where the agent wants the answer (struct timespec)
    mov   x2, #16
    check_buf x1, x2, AGENT_W_LO, AGENT_W_HI, deny_efault
    mrs   x3, cntvct_el0             // ticks since the clock started
    mrs   x4, cntfrq_el0             // ticks per second
    udiv  x5, x3, x4                 // seconds
    msub  x6, x5, x4, x3             // leftover ticks
    ldr   x7, =1000000000
    mul   x6, x6, x7
    udiv  x6, x6, x4                 // nanoseconds
    stp   x5, x6, [x1]               // written straight into the agent's memory
    mov   x5, #0
    log_call LOG_ANSWERED
    str   x5, [sp, #0]
    b     restore

sys_mmap:                            // "give me 4 KiB of memory": we edit the agent's page table
    ldr   x1, [sp, #8]
    cmp   x1, #4096                  // this demo hands out single pages
    b.ne  deny_einval
    adr   x6, pool_next
    ldr   x2, [x6]                   // next free page
    ldr   x7, =POOL_HI
    cmp   x2, x7
    b.hs  deny_enomem
    add   x3, x2, #4096
    str   x3, [x6]
    ldr   x7, =RAM_BASE              // its entry in the page table: PT_L3 + page number * 8
    sub   x3, x2, x7
    lsr   x3, x3, #12
    ldr   x7, =PT_L3
    add   x3, x7, x3, lsl #3
    ldr   x7, =PAGE_EL0_RW
    orr   x4, x2, x7
    str   x4, [x3]                   // the page now exists for the agent
    dsb   ishst
    tlbi  vmalle1
    dsb   ish
    isb
    mov   x3, x2                     // zero it: fresh memory must never hold old data
    add   x4, x2, #4096
1:  stp   xzr, xzr, [x3], #16
    cmp   x3, x4
    b.lo  1b
    mov   x5, x2
    log_call LOG_ANSWERED
    str   x5, [sp, #0]
    b     restore

// ------------------------------- FORWARD IT: checks, then one exit each -----------------------

sys_write:
    ldr   x0, [sp, #0]               // only stdout and stderr
    cmp   x0, #1
    b.eq  1f
    cmp   x0, #2
    b.ne  deny_ebadf
1:  ldr   x1, [sp, #8]
    ldr   x2, [sp, #16]
    check_buf x1, x2, AGENT_LO, AGENT_HI, deny_efault
    ldr   x6, =HC_PAGE
    mov   x3, #HC_WRITE
    stp   x3, x1, [x6]               // op, buffer
    str   x2, [x6, #16]              // length
    bl    hypercall
    ldr   x5, [x6, #32]
    log_call LOG_FORWARDED
    str   x5, [sp, #0]
    b     restore

sys_openat:
    ldr   x1, [sp, #8]               // the path (a pointer from the agent: check it)
    mov   x2, #256
    check_buf x1, x2, AGENT_LO, AGENT_HI, deny_efault
    adr   x3, ws_prefix              // rule 1: the path must start with "/workspace/"
    mov   x4, #0
2:  ldrb  w6, [x3, x4]
    cbz   w6, 3f
    ldrb  w7, [x1, x4]
    cmp   w6, w7
    b.ne  deny_eacces
    add   x4, x4, #1
    b     2b
3:  mov   x4, #0                     // rule 2: no ".." anywhere (no climbing out of /workspace)
4:  ldrb  w6, [x1, x4]
    cbz   w6, 5f
    cmp   x4, #255
    b.hs  deny_efault
    cmp   w6, #'.'
    b.ne  6f
    add   x9, x4, #1
    ldrb  w7, [x1, x9]
    cmp   w7, #'.'
    b.eq  deny_eacces
6:  add   x4, x4, #1
    b     4b
5:  ldr   x6, =HC_PAGE               // allowed: the VMM opens the real file
    mov   x3, #HC_OPEN
    stp   x3, x1, [x6]
    bl    hypercall
    ldr   x5, [x6, #32]
    log_call LOG_FORWARDED
    str   x5, [sp, #0]
    b     restore

sys_read:
    ldr   x0, [sp, #0]               // only files the VMM opened for us (fd 3 and up)
    cmp   x0, #3
    b.lo  deny_ebadf
    ldr   x1, [sp, #8]               // the buffer must be memory the agent may write
    ldr   x2, [sp, #16]
    check_buf x1, x2, AGENT_W_LO, AGENT_W_HI, deny_efault
    ldr   x6, =HC_PAGE
    mov   x3, #HC_READ
    stp   x3, x0, [x6]               // op, fd
    stp   x1, x2, [x6, #16]          // buffer, length
    bl    hypercall
    ldr   x5, [x6, #32]
    log_call LOG_FORWARDED
    str   x5, [sp, #0]
    b     restore

sys_close:
    ldr   x0, [sp, #0]
    cmp   x0, #3
    b.lo  deny_ebadf
    ldr   x6, =HC_PAGE
    mov   x3, #HC_CLOSE
    stp   x3, x0, [x6]
    bl    hypercall
    ldr   x5, [x6, #32]
    log_call LOG_FORWARDED
    str   x5, [sp, #0]
    b     restore

sys_exit:
    ldr   x5, [sp, #0]
    mov   x0, #LOG_EXIT
    mov   x1, x5
    mov   x2, #0
    mov   x3, #0
    mov   x4, #0
    bl    log_event
    ldr   x6, =HC_PAGE
    mov   x0, #HC_EXIT
    stp   x0, x5, [x6]
    bl    hypercall
    b     .

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
    eret

hypercall:                           // the doorbell: the only way out of guest mode. Keeps x6.
    ldr   x7, =DOORBELL
    dsb   sy
    str   xzr, [x7]
    ret

log_event:                           // notebook entry {x0..x5}. Clobbers x6, x7, x9.
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

    .balign 8
pool_next:  .quad 0x80032000         // next page mmap will hand out
ws_prefix:  .asciz "/workspace/"
    .ltorg
