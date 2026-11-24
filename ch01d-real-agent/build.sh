#!/bin/sh
# Build the three parts on macOS (or Linux): supervisor -> flat binary, agent -> static ELF, VMM -> static binary.
set -e
cd "$(dirname "$0")"
BIN="$(rustc --print sysroot)/lib/rustlib/$(rustc -vV | sed -n 's/host: //p')/bin"
(cd supervisor && cargo build --release -q 2>/dev/null || cargo build --release)
# supervisor.bin is only to show the size; the VMM embeds the supervisor's ELF file.
[ -x "$BIN/rust-objcopy" ] && "$BIN/rust-objcopy" -O binary supervisor/target/aarch64-unknown-none-softfloat/release/supervisor supervisor.bin
(cd agent && cargo build --release -q)
(cd vmm && cargo build --release -q)
(cd redteam && cargo build --release -q)
echo "built: supervisor ($( [ -f supervisor.bin ] && echo "$(wc -c < supervisor.bin) bytes" || echo ELF )), agent, redteam, vmm (+ loadtest, pool)"
