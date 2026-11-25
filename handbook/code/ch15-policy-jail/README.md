# Chapter 15 demos

- `seccomp-order/`: war story 10. Build on the Mac (`cargo build --release`),
  run in the lab VM: `./target/aarch64-unknown-linux-musl/release/seccomp-order wrong`
  opens /dev/null for writing although the filter has a check against it;
  `... right` is killed by seccomp (exit status 159).
- `typo.policy`, `outside.policy`, `unknown-call.policy`: three broken policies.
  From `ch01d-real-agent/`: `$V --policy ../handbook/code/ch15-policy-jail/typo.policy`.
  The VMM refuses each one before it creates a VM.
