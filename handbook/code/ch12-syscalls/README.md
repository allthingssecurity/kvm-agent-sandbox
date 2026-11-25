# Chapter 12 demo: a pointer into a hole

The VMM (`src/main.rs`), the supervisor (`guest/supervisor.S`) and the linker
script are copies of `ch01c-syscall-buckets/`, unchanged. Only `guest/agent.S`
is new: it calls `openat` with a path pointer that passes the supervisor's
range check but points at an unmapped page.

Build on the Mac, run in the lab VM:

    $ sh guest/build.sh && nice cargo build --release
    $ limactl shell vmm sh -c 'cd /path/to/repo/handbook/code/ch12-syscalls && ./target/aarch64-unknown-linux-musl/release/hole-demo'
