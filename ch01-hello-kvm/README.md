# Chapter 1: hello, KVM

The smallest complete virtual machine: raw KVM ioctls (only the `libc` crate), one page of guest RAM,
ten hand-written ARM instructions, one emulated "UART" register. The guest prints a string; every character
is a VM exit handled in `src/main.rs`; then it powers off through PSCI.

Files: `src/main.rs` (the VMM), `guest/guest.S` (the guest, already embedded as bytes in main.rs).

## Run it (macOS on Apple Silicon M3 or newer, ~0.4 GB disk)

    # once: a tiny Alpine Linux VM with nested virtualization, so it has /dev/kvm
    limactl create --name=vmm --vm-type=vz --cpus=2 --memory=1 --disk=2 \
      --set '.nestedVirtualization=true' --mount-only "$PWD/..:w" --tty=false template:alpine
    limactl start vmm && limactl prune          # prune drops the ~470 MB download cache
    rustup target add aarch64-unknown-linux-musl

    cargo build --release                        # on the Mac: static aarch64 Linux binary
    limactl shell vmm ./target/aarch64-unknown-linux-musl/release/hello-kvm

On any aarch64 Linux machine with /dev/kvm, skip Lima and run the binary directly.

## Regenerating the guest bytes

    clang -c -target arm64-none-elf guest/guest.S -o guest/guest.o
    llvm-objdump -d guest/guest.o
