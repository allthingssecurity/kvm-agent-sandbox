// The guest for chapters 9 and 10 (a copy of ch01-hello-kvm/guest/guest.S).
// It runs at EL1 with the MMU off, so addresses are guest-physical.
// It prints a string by storing each byte to a UART address with no RAM
// behind it. Each store traps to the VMM as a KVM_EXIT_MMIO.
// Then it asks PSCI to power off.
    .global _start
_start:
    adr   x2, msg              // x2 = address of the string (in guest RAM)
    movz  x0, #0x0900, lsl #16 // x0 = 0x0900_0000, our "UART" (no memory there)
1:  ldrb  w1, [x2], #1         // load next byte from RAM, advance pointer
    cbz   w1, 2f               // zero terminator: done
    strb  w1, [x0]             // MMIO store -> trap to the VMM
    b     1b
2:  movz  w0, #0x0008          // w0 = 0x8400_0008 = PSCI SYSTEM_OFF
    movk  w0, #0x8400, lsl #16
    hvc   #0                   // call the hypervisor -> KVM_EXIT_SYSTEM_EVENT
    b     .                    // never reached
msg: .asciz "Hello from the guest! Every character you see was a VM exit.\n"
