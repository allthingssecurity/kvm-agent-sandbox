# kvm-agent-sandbox

Run untrusted agent code inside a KVM virtual machine **without a guest kernel, without emulated devices, and without
booting anything**. A ~530-line Rust *supervisor* sits at the guest's kernel level and becomes the program's kernel: every
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
| **Cold start**: new process, create VM, load the ELF, supervisor starts, agent prints a line, VM exits | **p50 3.8 ms**, p99 4.5 ms | **p50 3.0 ms**, p99 3.4 ms |
| **Throughput** on 2 vCPUs (full lifecycle per sandbox) | up to **385 sandboxes/s** | up to **555 sandboxes/s** |
| **Memory per idle sandbox** (host memory actually consumed: VMM process, guest pages touched, KVM structures) | **3.3 MB**: 180 idle sandboxes in 601 MB | 16.8 MB: 40 idle sandboxes in 672 MB |
| **CPU with every sandbox idle** | 0.0% of the machine (180 sandboxes) | 0.2% (40 sandboxes) |
| Memory returned after killing all | yes (787 MB vs 797 MB at start) | yes |

The default trades start-up speed for density: with huge pages, each scattered region the guest touches costs 2 MiB. (The
huge-page column was measured before the security fixes described under [Security testing](#security-testing); the 4 KiB
column after them.)

Raw outputs: [`ch01d-real-agent/results/`](ch01d-real-agent/results/).

The demo agent (heap, a hash map, file reads, five forbidden actions) makes **51 system calls: 27 answered inside the VM,
8 refused inside the VM, 16 forwarded**. That's **17 VM exits** in total, and the run takes 10–30 ms including VM creation.

## How it works

```
                    REAL mode (the host)                     GUEST mode (inside the VM)
 level 0 (kernel)   host Linux + KVM                         SUPERVISOR  (Rust, no_std, ~530 lines)
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
   own copy, and memory limits. Every pointer the agent passes is checked by asking the MMU (`AT S1E0R`/`AT S1E0W`)
   whether the agent itself could read or write it. The supervisor never touches memory on the agent's behalf that the
   agent couldn't touch.
2. **CPU and KVM**: the agent at guest level 3 can't touch supervisor pages or change the door register. Memory beyond
   `memory_mb` isn't mapped at all. Stage-2 page tables confine the whole VM to its own RAM.
3. **VMM checks and limits**: it re-checks every forwarded request with the same policy, resolves symlinks and checks
   the result, and writes results only into the agent's own memory areas. It enforces a wall-clock watchdog (it
   interrupts `KVM_RUN`), an output cap and an open-files cap. A full audit log stops the agent instead of losing
   entries.
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

## Can it run any code? Tested with Hermes Agent and deepagents

**No, not yet.** It runs static Linux binaries that stay within the ~30 system calls the supervisor implements. We
checked what two real agent frameworks would run inside a sandbox:

- **[deepagents](https://github.com/langchain-ai/deepagents):** its sandbox backend implements every file tool (`ls`,
  `read_file`, `glob`, `write_file`, `edit_file`) as a `python3 -c "..."` command sent through `execute()`.
- **[Hermes Agent](https://github.com/NousResearch/hermes-agent):** `terminal()` runs bash. `execute_code` runs a Python
  script that calls tools back over a Unix socket, or through request files for remote backends.

We extracted the exact commands and scripts from their source and traced them with `strace` on Alpine Linux
([`compat/`](ch01d-real-agent/compat/), raw output in
[`results/compat-agent-frameworks.txt`](ch01d-real-agent/results/compat-agent-frameworks.txt)):

| | |
|---|---|
| Distinct system calls the 8 workloads use | **54** |
| Implemented by the supervisor | 25 |
| **Missing** | **29**. Every workload starts with `execve` (a new program). Others need `clone`/`wait4` (subprocesses), `getdents64` (list a directory), `newfstatat`, `fcntl`, `dup3`, `pipe2`, `mkdirat`/`renameat` (write files), and `socket`/`connect`/`epoll` (Hermes' callback channel) |

And Python itself is a dynamically linked program that opens hundreds of files at start-up.

**What does run today:** unmodified real-world static binaries. The loader accepts static PIEs, the usual static build
on Alpine and most distributions. Alpine's `busybox` (1.1 MB, not recompiled) inside the sandbox:

| Command | Result |
|---|---|
| `busybox echo …`, `busybox cat /workspace/notes.txt`, `busybox wc -l …` | **works**, 4–15 ms including VM creation |
| `busybox ls /workspace` | fails: `newfstatat` isn't implemented |
| `busybox sh -c 'echo hi; cat f \| wc -l'` | the shell starts and runs `echo`, then stops at the pipe (`pipe2`, then `fork`) |

**Running Hermes or deepagents tool code needs:**
- `fork`/`exec`, a writable file system, pipes and directory listing in the supervisor;
- then an interpreter, which is where gVisor spent years;
- or this sandbox for vetted tools and static programs, with a microVM for "run anything".

## Security testing

[`run-redteam.sh`](ch01d-real-agent/run-redteam.sh) runs a hostile agent ([`redteam/`](ch01d-real-agent/redteam/)). It
tries what a prompt-injected agent tool would try, using raw `svc` instructions so it can pass any number and any
pointer. Results ([`results/redteam.txt`](ch01d-real-agent/results/redteam.txt)):

| Attacks | Result |
|---|---|
| **Steal host secrets**: `/etc/shadow`, `~/.ssh/id_rsa`, `~/.aws/credentials`, `/proc/self/environ`, `/proc/self/mem`, `/proc/1/root/...`, `/dev/kvm` | 9/9 refused |
| **Escape the workspace**: `..`, `/workspace//etc/passwd`, planted symlinks to `/etc/passwd` and `/etc`, prefix confusion, 300-byte paths | 7/7 refused. The supervisor caught 4; **the VMM's second check caught the 3 it let through** |
| **Write, create or persist**: write/append/truncate opens, `mkdir`, `unlink`, `symlink`, `link`, `rename`, `chmod`, `chown` | 11/11 refused |
| **Network and processes**: TCP and Unix sockets, `connect`, `execve /bin/sh`, `clone`, `clone3`, a 1,000-iteration fork bomb | 8/8 refused, 0 processes created |
| **Host kernel attack surface**: `ptrace`, `bpf`, `io_uring`, `userfaultfd`, `perf_event_open`, `mount`, `unshare`, `setns`, `keyctl`, `init_module`, `process_vm_readv`, `seccomp`, unknown numbers | 19/19 refused |
| **Turn the supervisor against itself**: pass pointers to its code, policy, page tables, audit log or doorbell page (or to the agent's own read-only code, or a 2^64-byte length) to 11 different system calls | 17/17 refused with `EFAULT` |
| **Memory and fd games**: mmap length overflow, 1 TiB, `MAP_FIXED` over the supervisor, mapping a file, `brk` into the supervisor, pointers into unmapped holes, fd exhaustion, stdin, closed fds | 13/13 refused |
| **Must stop the sandbox**: read the policy, erase the audit log, edit page tables, patch its own code, run code from the heap, stack or supervisor, `msr vbar_el1`, `msr sctlr_el1` (MMU off), `hvc`, `smc`, `eret`, `dc zva` on the log, ring the doorbell, touch memory outside RAM or beyond the memory limit, overflow the stack, `wfi`, sleep for an hour, spin | 21/21 stopped by the CPU or the watchdog |
| *(1 more check must succeed: opening an allowed file. 85 checks in all)* | 85/85 pass |
| **Fuzzing**: 100 runs × 8,000 random system calls with hostile arguments (supervisor addresses, holes, huge lengths) | **800,000 calls, 0 supervisor crashes** |

**The first run found three real bugs** ([`results/redteam-before-fixes.txt`](ch01d-real-agent/results/redteam-before-fixes.txt)):

1. **The memory limit didn't hold against direct stores.** With `memory_mb = 32`, the agent wrote to 83 MiB it never
   asked for: the page tables mapped the whole mmap area, and only `mmap` respected the limit. **Fix:** memory beyond
   `memory_mb` isn't mapped at all. A side effect: a stack overflow now faults instead of silently running into the
   mmap area.
2. **The supervisor could be crashed.** It checked pointers against an address range, but that range has unmapped gaps.
   A pointer into a gap made the supervisor itself fault, in 14 of 20 fuzz runs. That was fail-closed (only that
   sandbox died) but agent-triggerable. **Fix:** every pointer is checked with the MMU's own `AT S1E0R`/`AT S1E0W`
   translation, so the supervisor touches only what the agent could touch.
3. **An `mmap` length near 2^64 wrapped around** in the round-up and "succeeded" with zero bytes. **Fix:** checked
   arithmetic.

Two defense-in-depth changes came with the fixes: the VMM now writes forwarded results only into the agent's areas
(without trusting the supervisor's check), and `/workspace//etc/passwd` is shown to be stopped by the VMM's
canonicalize-and-compare check.

**What this testing does not show:**
- **Not covered:** side channels (timing, cache), the host kernel's KVM code, and nested-virtualization behavior.
- **Fuzzing depth:** the fuzzing is random, not coverage-guided.
- **Audit:** no outside audit has been done.
- **Trusted base:** the supervisor (~530 lines) and the VMM's request handlers are the code to trust. That is small
  enough to review line by line, which is the design's main security argument.

## Compared with Firecracker

Firecracker is the reference design for microVM sandboxes, and it's battle-tested at AWS. Its site states: *"Boot in
<125ms"*, *"<5 MiB overhead per VM"*, *"Create up to 150 microVMs per second per host"*, and *"Only 5 emulated devices"*.
Those figures come from [firecracker-microvm.github.io](https://firecracker-microvm.github.io/), which doesn't say what
hardware or end point they measure. **This is not a side-by-side benchmark.**

| | Firecracker (its published figures) | This sandbox (measured above) |
|---|---|---|
| What runs inside each VM | A full Linux guest kernel | No kernel: a ~530-line supervisor |
| Emulated devices | 5 (virtio-net, virtio-block, virtio-vsock, serial, keyboard controller) | **0**: no virtio, no serial, no device tree |
| Boot | Boots a guest kernel (<125 ms) | **Nothing to boot**: 3–4 ms for the whole lifecycle |
| Memory | <5 MiB VMM overhead, plus the guest kernel and its memory | **3.3 MB total** per idle sandbox |
| Creation rate | Up to 150 microVMs/s per host | 385–555/s on just 2 vCPUs, nested |
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

- One vCPU and no threads (`clone` is refused). No `fork`/`exec`. Static binaries only (fixed-address or static PIE).
- The audit log holds 10,000 entries, and a full log stops the agent, so a run is limited to 10,000 system calls. Long-running agents need the log streamed to the VMM.
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
(cd redteam && cargo build --release)       # the hostile agent
limactl shell vmm ./run-redteam.sh           # 85 attacks, 21 must-stop attacks, 100 fuzz runs
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
