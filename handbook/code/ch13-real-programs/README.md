# Chapter 13 demos

All commands run inside the lab VM from `ch01d-real-agent/`, with
`V=./vmm/target/aarch64-unknown-linux-musl/release/vmm`.

- `showstack.c`: prints argc, argv, envp and the auxiliary vector it was
  started with. Build in the lab VM with `make` (a static PIE), then compare
  `../handbook/code/ch13-real-programs/showstack a b` with
  `$V ../handbook/code/ch13-real-programs/showstack -- a b`.
- `agent`: a symbolic link to `ch01d-real-agent/compat/bin/busybox` (run
  `compat/run-busybox.sh` once to create it). Through this name busybox gets
  argv[0] = "agent": `$V ../handbook/code/ch13-real-programs/agent -- ls`.
- `wrong-address/`: the same idea as showstack in Rust, linked with Rust's
  defaults at 0x200000. Build on the Mac with `cargo build --release`; the
  VMM refuses it because the address is outside the program area.
- `build-old.sh`: builds the VMM from before the clock fix (run on the Mac).
  Then `old/ch01d-real-agent/vmm/target/aarch64-unknown-linux-musl/release/vmm
  compat/bin/busybox -- date` prints 1970.
