# Chapter 11 demo: the agent rings the doorbell itself

The VMM (`src/main.rs`), the supervisor (`guest/supervisor.S`) and the linker
script are copies of `ch01b-supervisor/`, unchanged. Only `guest/agent.S` is
new: it stores to the doorbell address 0x0900_0000 from EL0.

Build on the Mac, run in the lab VM:

    $ sh guest/build.sh && nice cargo build --release
    $ limactl shell vmm sh -c 'cd /path/to/repo/handbook/code/ch11-supervisor && ./target/aarch64-unknown-linux-musl/release/doorbell-demo'
