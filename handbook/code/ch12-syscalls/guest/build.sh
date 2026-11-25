#!/bin/sh
# Assemble the guest on macOS (or Linux) with clang, link it at its guest addresses with Rust's lld,
# and write a flat binary that the VMM loads at 0x80000000.
set -e
cd "$(dirname "$0")"
BIN="$(rustc --print sysroot)/lib/rustlib/$(rustc -vV | sed -n 's/host: //p')/bin"
clang -c -target aarch64-none-elf supervisor.S -o supervisor.o
clang -c -target aarch64-none-elf agent.S -o agent.o
"$BIN/rust-lld" -flavor gnu -e sup_start -T link.ld supervisor.o agent.o -o guest.elf
"$BIN/rust-objcopy" -O binary guest.elf guest.bin
echo "guest.bin: $(wc -c < guest.bin) bytes"
