# kvm-agent-sandbox

Run untrusted agent code inside a KVM virtual machine **without a guest kernel, without emulated devices, and without
booting anything**. A ~520-line Rust *supervisor* sits at the guest's kernel level and becomes the program's kernel: every
Linux system call the program makes is **answered**, **refused** or **forwarded** according to a policy file. Only
forwarded calls leave the VM, and the VMM carries them out on the host inside a jail.

The program itself is an ordinary, unmodified static Linux binary: Rust with the standard library, heap, hash maps and
files. It doesn't know it's sandboxed.

> Status: a working research prototype from a book on writing a VMM from scratch. It is **not** audited and not ready
> for hostile production traffic. The limitations are listed below.

## Measured numbers

From a MacBook (Apple M4 Pro), inside a Lima VM running Alpine Linux 6.18 with **2 vCPUs and 1 GiB RAM**, using **nested
virtualization**: every VM exit crosses two hypervisors, so exits are slower than on bare-metal Linux. The laptop was
also running other work. Treat these as conservative, single-machine numbers; bare-metal runs are still to do.

| | 4 KiB guest pages (default) | 2 MiB transparent huge pages |
|---|---|---|
| **Cold start**: new process, create VM, load the ELF, supervisor starts, agent prints a line, VM exits | **p50 5.0 ms**, p99 6.0 ms | **p50 3.0 ms**, p99 3.4 ms |
| **Throughput** on 2 vCPUs (full lifecycle per sandbox) | up to **363 sandboxes/s** | up to **555 sandboxes/s** |
| **Memory per idle sandbox** (host memory actually consumed: VMM process, guest pages touched, KVM structures) | **3.4 MB**: 170 idle sandboxes in 582 MB | 16.8 MB: 40 idle sandboxes in 672 MB |
| **CPU with every sandbox idle** | 0.2% of the machine (170 sandboxes) | 0.2% (40 sandboxes) |
| Memory returned after killing all | yes (775 MB vs 772 MB at start) | yes |

The default trades start-up speed for density: with huge pages, each scattered region the guest touches costs 2 MiB.

Raw outputs: [`ch01d-real-agent/results/`](ch01d-real-agent/results/).

The demo agent (heap, a hash map, file reads, five forbidden actions) makes **51 system calls: 27 answered inside the VM,
8 refused inside the VM, 16 forwarded**. That's **17 VM exits** in total, and the run takes 10–30 ms including VM creation.

## How it works

```
                    REAL mode (the host)                     GUEST mode (inside the VM)
 level 0 (kernel)   host Linux + KVM                         SUPERVISOR  (Rust, no_std, ~520 lines)
 level 3 (user)     VMM  (Rust, ~720 lines, jailed)          AGENT       (unmodified static Linux ELF)
```

1. **The VMM** opens `/dev/kvm`, creates a VM with 128 MiB of lazily allocated RAM, and loads the supervisor. It loads
   the agent's ELF the way Linux's `execve` would (segments, then the starting stack with argv and auxv), writes page tables
   ("supervisor memory: level 0 only"), writes the **policy table**, and starts one vCPU at guest level 0.
2. **The supervisor** points the CPU's exception "door" (`VBAR_EL1`) at its own handlers, turns the MMU on, and drops to
   guest level 3 at the agent's entry point.
3. **Every system call** (`svc`) of the agent jumps to the supervisor. This happens inside the VM; it isn't an exit.

| Bucket | Examples | VM exits |
|---|---|---|
| **Answer it** | `brk`, `mmap` (the supervisor edits the agent's page tables), signal setup, `set_tid_address`, `clock_gettime`, `getpid` | **0** |
| **Refuse it** | Paths outside the policy, `..` escapes, writes, `socket`, `clone`/`execve`, anything unknown | **0** |
| **Forward it** | `write` to stdout, `openat`/`read`/`fstat`/`close` under `/workspace`, `getrandom`, `nanosleep` | 1 each |

Forwarding means the supervisor checks the call, copies paths into its own memory, writes a request to a shared page and
"rings the doorbell": a store to an address with no memory behind it. KVM hands that exit to the VMM, which performs the
real host system call and writes back the result.

A fault (touching forbidden memory, a privileged instruction) stops the agent. Every decision goes into an audit log in
supervisor memory, which the VMM reads and prints after the run.

### Walls, from inside out

1. **Supervisor policy**, inside the VM: per-system-call allow/deny with errno, path prefixes checked on the supervisor's
   own copy, pointer checks, and memory limits.
2. **CPU and KVM**: the agent at guest level 3 can't touch supervisor pages or change the door register. Stage-2 page
   tables confine the whole VM to its own RAM.
3. **VMM checks and limits**: it re-checks every forwarded request with the same policy, and enforces a wall-clock
   watchdog (it interrupts `KVM_RUN`), an output cap and an open-files cap. A full audit log stops the agent instead of
   losing entries.
4. **Host jail on the VMM process**:
   - **seccomp**: 33 host system calls; `ioctl` only for `KVM_RUN`, `write` only to stdout and stderr.
   - **Landlock**: the VMM can open files only beneath the workspace, read-only.
   - **rlimits**: no new processes, no core dumps.
   - The self-test (`--jail-selftest`) proves it: `open("/etc/passwd")` is refused, and `socket()` kills the VMM with SIGSYS.

### Policy as data

```ini
time_limit_ms   = 3000
memory_mb       = 32
max_output_kb   = 64
max_open_files  = 8
workspace       = ./workspace
read            = /workspace/

allow = brk mmap munmap mprotect madvise set_tid_address rt_sigaction rt_sigprocmask sigaltstack
allow = write writev openat read close fstat lseek getrandom nanosleep clock_nanosleep
deny socket socketpair bind connect = EACCES     # no network
deny clone clone3 execve            = EPERM      # no new processes
```

Anything not mentioned is refused, and unknown keys or system-call names are errors. The same supervisor binary obeys
whatever policy it's given: see [`policies/`](ch01d-real-agent/policies/).

## Compared with Firecracker

Firecracker is the reference design for microVM sandboxes, and it's battle-tested at AWS. Its site states: *"Boot in
<125ms"*, *"<5 MiB overhead per VM"*, *"Create up to 150 microVMs per second per host"*, and *"Only 5 emulated devices"*.
Those figures come from [firecracker-microvm.github.io](https://firecracker-microvm.github.io/), which doesn't say what
hardware or end point they measure. **This is not a side-by-side benchmark.**

| | Firecracker (its published figures) | This sandbox (measured above) |
|---|---|---|
| What runs inside each VM | A full Linux guest kernel | No kernel: a ~520-line supervisor |
| Emulated devices | 5 (virtio-net, virtio-block, virtio-vsock, serial, keyboard controller) | **0**: no virtio, no serial, no device tree |
| Boot | Boots a guest kernel (<125 ms) | **Nothing to boot**: 3–5 ms for the whole lifecycle |
| Memory | <5 MiB VMM overhead, plus the guest kernel and its memory | **3.4 MB total** per idle sandbox |
| Creation rate | Up to 150 microVMs/s per host | 363–555/s on just 2 vCPUs, nested |
| What the sandbox sees | Devices and packets | **Every system call**, with its paths and arguments, in an audit log |
| Policy granularity | Network and disk level | Per system call, per path prefix, per errno. L7 rules and credential injection are possible. |
| **Compatibility** | **Anything Linux runs**: Python, Node, shells, `pip install` | **Only what the supervisor implements**: static, single-threaded programs today |
| Maturity | Years in production | A prototype |

**Where this design wins:** fast, cheap, closely watched execution of known tools and static programs. That means no
kernel boot, no devices, no guest OS to patch, and visibility into every system call the code makes.

**Where Firecracker wins:** running arbitrary code. Supporting Python or Node here means implementing much more of the
Linux system-call interface (threads, a file system, pipes, `epoll`, `fork`), which is the multi-year job gVisor did. A
practical platform could use both: this sandbox for the fast path, and a microVM for "run anything".

## Limitations (today)

- One vCPU and no threads (`clone` is refused). No `fork`/`exec`. Static, non-PIE binaries only.
- Files are read-only, under `/workspace` only. No network: `socket` is refused, with no L4 or L7 forwarding yet.
- `mprotect` is accepted but not enforced, and `munmap` doesn't free memory (a bump allocator, capped by `memory_mb`).
- No guest timer interrupts: time limits are enforced from the host by the watchdog.
- arm64 (aarch64) only. x86_64 needs a port (VMX, different page tables and system-call numbers).
- Not fuzzed, not audited. The supervisor's system-call layer is the attack surface: fuzz it before trusting it.

## Try it

You need Linux with `/dev/kvm` on arm64. On an Apple-silicon Mac (M3 or newer), a small Lima VM works, using about
0.4 GB of disk:

```sh
limactl create --name=vmm --vm-type=vz --cpus=2 --memory=1 --disk=2 \
  --set '.nestedVirtualization=true' --mount-only "$PWD:w" --tty=false template:alpine
limactl start vmm && limactl prune
rustup target add aarch64-unknown-linux-musl aarch64-unknown-none-softfloat

cd ch01d-real-agent
./build.sh                                   # supervisor.bin, the agent ELF, the VMM (cross-built on the Mac)
limactl shell vmm ./vmm/target/aarch64-unknown-linux-musl/release/vmm                   # run the agent
limactl shell vmm ./vmm/target/aarch64-unknown-linux-musl/release/vmm --policy policies/strict.policy
limactl shell vmm ./run-tests.sh             # watchdog, memory, output, jail self-test
limactl shell vmm ./vmm/target/aarch64-unknown-linux-musl/release/loadtest              # the numbers above
```

Run your own program: build it as a static arm64 Linux binary linked at `0x81000000` (see
`agent/.cargo/config.toml`), then run `vmm path/to/program -- args`.

## Repository layout

The chapters build up to the sandbox:

| Folder | What it shows |
|---|---|
| [`ch01-hello-kvm`](ch01-hello-kvm/) | The smallest KVM VM: raw ioctls, 10 hand-written instructions, every printed character is a VM exit |
| [`ch01b-supervisor`](ch01b-supervisor/) | A supervisor at guest level 0 and untrusted code at level 3; the CPU blocks attacks |
| [`ch01c-syscall-buckets`](ch01c-syscall-buckets/) | Answer, refuse or forward each system call (in assembly) |
| [`ch01d-real-agent`](ch01d-real-agent/) | **The sandbox**: Rust supervisor, a real ELF agent, policy files, limits, watchdog, jailed VMM, load test |

Chapters 1b and 1c build their guest with `guest/build.sh` before `cargo build`. Chapter 1d's `build.sh` does everything.
