#!/bin/sh
# Build the VMM as it was at commit 6fb29ce, before the clock fix (war story:
# `date` printed 1970). Run on the Mac; the result runs in the lab VM.
# Back then the VMM embedded a flat supervisor.bin made with rust-objcopy.
set -e
cd "$(dirname "$0")"
mkdir -p old
git -C ../../.. archive 6fb29ce ch01d-real-agent/supervisor ch01d-real-agent/vmm | tar -x -C old
cd old/ch01d-real-agent
BIN="$(rustc --print sysroot)/lib/rustlib/$(rustc -vV | sed -n 's/host: //p')/bin"
(cd supervisor && cargo build --release -q)
"$BIN/rust-objcopy" -O binary supervisor/target/aarch64-unknown-none-softfloat/release/supervisor supervisor.bin
(cd vmm && cargo build --release -q)
echo "built: $(pwd)/vmm/target/aarch64-unknown-linux-musl/release/vmm"
