#!/bin/sh
# Build the three parts on macOS (or Linux): supervisor -> flat binary, agent -> static ELF, VMM -> static binary.
set -e
cd "$(dirname "$0")"
BIN="$(rustc --print sysroot)/lib/rustlib/$(rustc -vV | sed -n 's/host: //p')/bin"
(cd supervisor && cargo build --release -q 2>/dev/null || cargo build --release)
"$BIN/rust-objcopy" -O binary supervisor/target/aarch64-unknown-none-softfloat/release/supervisor supervisor.bin
(cd agent && cargo build --release -q)
(cd vmm && cargo build --release -q)
echo "built: supervisor.bin ($(wc -c < supervisor.bin) bytes), agent, vmm"
