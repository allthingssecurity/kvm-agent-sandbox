# Chapter 14 demos

Run inside the lab VM from `ch01d-real-agent/`, with
`V=./vmm/target/aarch64-unknown-linux-musl/release/vmm`.

- `peek-tmp.c`: writes a file to /tmp, then reads /tmp's memory directly.
  Build in the lab VM with `make`, run `$V ../handbook/code/ch14-files/peek-tmp`.
  The read() works; the direct load stops the program.
- `make-ppoll-bug.sh` (run on the Mac): today's code with the first version
  of `ppoll` put back. Then run
  `ppoll-bug/ch01d-real-agent/vmm/target/aarch64-unknown-linux-musl/release/vmm
  compat/bin/busybox -- sh -c 'read l < /workspace/notes.txt; echo status $? line: $l'`.
- `old/` is a leftover build of commit 650e299 (not used by the chapter).
