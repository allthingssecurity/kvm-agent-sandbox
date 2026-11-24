# kvm-agent-sandbox

Run untrusted agent code inside a KVM virtual machine **without a guest kernel, without emulated devices, and without
booting anything**. A ~1,200-line Rust *supervisor* sits at the guest's kernel level and becomes the program's kernel: every
Linux system call the program makes is **answered**, **refused** or **forwarded** according to a policy file. Only
forwarded calls leave the VM, and the VMM carries them out on the host inside a jail.

The program itself is an ordinary, unmodified static Linux binary: a Rust program with the standard library, or real
tools such as Alpine's `busybox` (`ls`, `find`, `grep -r`, `awk`, `sed`, `tar`, `sh` scripts with built-in commands). It
doesn't know it's sandboxed. It can read a host folder (read-only) and write to `/tmp`, which lives in the VM's memory, so
**nothing it writes ever reaches the host**.

> Status: a working research prototype from a book on writing a VMM from scratch. It is **not** audited and not ready
> for hostile production traffic. The limitations are listed below.

## Measured numbers

From a MacBook (Apple M4 Pro), inside a Lima VM running Alpine Linux 6.18 with **2 vCPUs and 1 GiB RAM**, using **nested
virtualization**: every VM exit crosses two hypervisors, so exits are slower than on bare-metal Linux. The laptop was
also running other work. Treat these as conservative, single-machine numbers; bare-metal runs are still to do.

| | 4 KiB guest pages (default) | 2 MiB transparent huge pages |
|---|---|---|
| **Cold start**: new process, create VM, load the ELF, supervisor starts, agent prints a line, VM exits | **p50 4.2 ms**, p99 5.3 ms | **p50 3.0 ms**, p99 3.4 ms |
| **Throughput** on 2 vCPUs (full lifecycle per sandbox) | up to **338 sandboxes/s** | up to **555 sandboxes/s** |
| **Memory per idle sandbox** (host memory actually consumed: VMM process, guest pages touched, KVM structures) | **3.1 MB**: 190 idle sandboxes in 579 MB | 16.8 MB: 40 idle sandboxes in 672 MB |
| **CPU with every sandbox idle** | 0.0% of the machine (190 sandboxes) | 0.2% (40 sandboxes) |
| Memory returned after killing all | yes | yes |

The default trades start-up speed for density: with huge pages, each scattered region the guest touches costs 2 MiB. The
huge-page column was measured with the first, ~520-line supervisor; the 4 KiB column with the current one, which has a
file-descriptor table, folders and `/tmp`. Between those versions on the same laptop, cold start measured 3.8–5.0 ms and
throughput 338–385/s; run-to-run noise on a busy laptop is of that size.

Raw outputs: [`ch01d-real-agent/results/`](ch01d-real-agent/results/).

The demo agent (heap, a hash map, file reads, five forbidden actions) makes **51 system calls: 27 answered inside the VM,
8 refused inside the VM, 16 forwarded**. That's **17 VM exits** in total, and the run takes 10–30 ms including VM creation.
Real tools take 3.5–6.5 ms each, VM creation included: `grep -rn` over the workspace makes 39 system calls and 14 exits.
`mkdir -p /tmp/a/b/c` makes 20 system calls and **one** exit, the final one.

## How it works

```
                    REAL mode (the host)                     GUEST mode (inside the VM)
 level 0 (kernel)   host Linux + KVM                         SUPERVISOR  (Rust, no_std, ~1,200 lines)
 level 3 (user)     VMM  (Rust, ~850 lines, jailed)          AGENT       (unmodified static Linux ELF)
```

1. **The VMM** opens `/dev/kvm`, creates a VM with 256 MiB of lazily allocated RAM (a page costs host memory only once it is touched), and loads the supervisor. It loads
   the agent's ELF the way Linux's `execve` would (segments, then the starting stack with argv and auxv), writes page tables
   ("supervisor memory: level 0 only"), writes the **policy table**, and starts one vCPU at guest level 0.
2. **The supervisor** points the CPU's exception "door" (`VBAR_EL1`) at its own handlers, turns the MMU on, and drops to
   guest level 3 at the agent's entry point.
3. **Every system call** (`svc`) of the agent jumps to the supervisor. This happens inside the VM; it isn't an exit.

| Bucket | Examples | VM exits |
|---|---|---|
| **Answer it** | Memory (`brk`, `mmap`), signal setup, `clock_gettime`, identity (`getpid`, `uname`, `getuid`), limits; the **fd table** (`dup3`, `fcntl`, `close`), the **current folder** (`getcwd`, relative paths), and **every file operation in `/tmp`**: `openat`, `read`, `write`, `mkdirat`, `renameat`, `unlinkat`, `getdents64`, `newfstatat` | **0** |
| **Refuse it** | Paths outside the policy, writes outside `/tmp`, `socket`, `clone`/`execve`, anything unknown | **0** |
| **Forward it** | `write` to stdout, reading `/workspace` (`openat`, `read`, `newfstatat`, `getdents64`, `readlinkat`, `chdir`), `getrandom`, `nanosleep` | 1 each |

About 70 Linux system calls in all. The supervisor keeps the state a kernel keeps for a process: a table of 64 file
descriptors (shared offsets after `dup`, like Linux), the current folder, and `/tmp`'s file table. Paths are cleaned up
by text before any check (`""`, `.` and `..` are resolved), so what the prefix check sees is exactly what gets opened.

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
   `memory_mb` isn't mapped at all. `/tmp`'s data sits in pages mapped for level 0 only, capped by `tmp_kb`. Stage-2
   page tables confine the whole VM to its own RAM.
3. **VMM checks and limits**: it re-checks every forwarded request with the same policy, resolves symlinks and checks
   the result, and writes results only into the agent's own memory areas. It enforces a wall-clock watchdog (it
   interrupts `KVM_RUN`), an output cap and an open-files cap. A full audit log stops the agent instead of losing
   entries.
4. **Host jail on the VMM process**:
   - **seccomp**: 34 host system calls; `ioctl` only for `KVM_RUN`, `write` only to stdout and stderr.
   - **Landlock**: the VMM can open files only beneath the workspace, read-only.
   - **rlimits**: no new processes, no core dumps.
   - The self-test (`--jail-selftest`) proves it: `open("/etc/passwd")` is refused, and `socket()` kills the VMM with SIGSYS.

### Policy as data

```ini
time_limit_ms   = 3000
memory_mb       = 32
tmp_kb          = 4096       # /tmp, in VM memory; 0 = no /tmp
max_output_kb   = 64
max_open_files  = 8
workspace       = ./workspace
read            = /workspace/

allow = brk mmap munmap mprotect madvise set_tid_address rt_sigaction rt_sigprocmask sigaltstack
allow = write writev read readv openat close fstat newfstatat lseek getdents64 readlinkat getcwd chdir
allow = dup dup3 fcntl mkdirat unlinkat renameat ftruncate getrandom nanosleep clock_nanosleep
deny socket socketpair bind connect = EACCES     # no network
deny clone clone3 execve            = EPERM      # no new processes
```

Anything not mentioned is refused, and unknown keys or system-call names are errors. The same supervisor binary obeys
whatever policy it's given: see [`policies/`](ch01d-real-agent/policies/).

## Can it run any code? Tested with Hermes Agent and deepagents

**Not yet: no Python, no shell pipelines.** It runs static Linux binaries that stay within the ~70 system calls the
supervisor implements. We checked what two real agent frameworks would run inside a sandbox:

- **[deepagents](https://github.com/langchain-ai/deepagents):** its sandbox backend implements every file tool (`ls`,
  `read_file`, `glob`, `write_file`, `edit_file`) as a `python3 -c "..."` command sent through `execute()`.
- **[Hermes Agent](https://github.com/NousResearch/hermes-agent):** `terminal()` runs bash. `execute_code` runs a Python
  script that calls tools back over a Unix socket, or through request files for remote backends.

We extracted the exact commands and scripts from their source and traced them with `strace` on Alpine Linux
([`compat/`](ch01d-real-agent/compat/), raw output in
[`results/compat-agent-frameworks.txt`](ch01d-real-agent/results/compat-agent-frameworks.txt)):

| | First version | Now |
|---|---|---|
| Distinct system calls the 8 workloads use | 54 | 54 |
| Implemented by the supervisor | 25 | **46** |
| **Missing** | 29 | **8**: `execve`, `clone`, `wait4`, `pipe2` (running programs), `rt_sigreturn` (delivering signals), `socket`, `connect`, `epoll_create1` (Hermes' callback channel) |

Two caveats:
- **`mmap`:** it counts as implemented, but only anonymous memory is supported. Python's loader also maps its library
  files.
- **Python itself:** it is a dynamically linked program that opens hundreds of files at start-up.

**What runs today:** unmodified real-world static binaries. The loader accepts static PIEs, the usual static build on
Alpine and most distributions. [`compat/run-busybox.sh`](ch01d-real-agent/compat/run-busybox.sh) runs Alpine's
`busybox` (1.1 MB, not recompiled); results are in [`results/busybox.txt`](ch01d-real-agent/results/busybox.txt):

| | Result |
|---|---|
| Reading: `ls -la`, `find`, `grep -rn`, `cat`, `head`, `tail`, `wc`, `sort`, `awk`, `sed`, `md5sum`, `sha256sum`, `base64`, `od`, `xxd`, `stat`, `du`, `diff`, `cmp`, `realpath` | **all work**, 3.9–6.0 ms each, VM included |
| Writing to `/tmp`: `mkdir -p`, `cp`, `tar -cf` | **work**, entirely inside the VM |
| `sh` scripts with built-in commands: redirects (`>`, `>>`, `<`), `while read`, `for f in *`, `cd`, arithmetic | **work** |
| `uname`, `id`, `nproc`, `date`, `env` | **work** |
| Writing to `/workspace`, `ls /` | refused, as intended |
| `sh -c 'cat f \| wc -l'`, or any non-built-in command in a script | **fails**: needs `pipe2`, then a new program (`execve`) |
| `free`, `ps` | fail: there is no `/proc` |

**What's left for Hermes and deepagents:**
1. **Running programs.** This design has a shortcut: a VM starts in about 4 ms, so `execve` could start a *new sandbox*
   (one program per VM), with the VMM connecting their pipes. Python's `subprocess` and most tools spawn new programs
   rather than truly forking. A real `fork`, which shells use for pipelines, is harder.
2. **Python.** It needs a static build, file-backed `mmap`, and threads.

Until then: use this sandbox for known tools and static programs, and a microVM for "run anything".

## Security testing

[`run-redteam.sh`](ch01d-real-agent/run-redteam.sh) runs a hostile agent ([`redteam/`](ch01d-real-agent/redteam/)). It
tries what a prompt-injected agent tool would try, using raw `svc` instructions so it can pass any number and any
pointer. Results ([`results/redteam.txt`](ch01d-real-agent/results/redteam.txt)):

| Attacks | Result |
|---|---|
| **Steal host secrets**: `/etc/shadow`, `~/.ssh/id_rsa`, `~/.aws/credentials`, `/proc/self/environ`, `/proc/self/mem`, `/proc/1/root/...`, `/dev/kvm` | 9/9 refused |
| **Escape the workspace**: `..`, `/workspace//etc/passwd`, planted symlinks to `/etc/passwd` and `/etc`, prefix confusion, 300-byte paths | 7/7 safe. The supervisor stopped 4; `//` resolves inside the workspace (`ENOENT`); **the VMM's second check stopped the 2 symlinks** |
| **Write, create or persist in `/workspace`**: write/append/truncate opens, `mkdir`, `unlink`, `symlink`, `link`, `rename`, `chmod`, `chown`, and a check that nothing appeared | 12/12 refused |
| **Network and processes**: TCP and Unix sockets, `connect`, `execve /bin/sh`, `clone`, `clone3`, a 1,000-iteration fork bomb | 8/8 refused, 0 processes created |
| **Host kernel attack surface**: `ptrace`, `bpf`, `io_uring`, `userfaultfd`, `perf_event_open`, `mount`, `unshare`, `setns`, `keyctl`, `init_module`, `process_vm_readv`, `seccomp`, unknown numbers | 17/17 refused |
| **Turn the supervisor against itself**: pass pointers to its code, policy, page tables, audit log or doorbell page (or to the agent's own read-only code, or a 2^64-byte length) to 11 different system calls | 17/17 refused with `EFAULT` (+1 allowed open) |
| **Memory and fd games**: mmap length overflow, 1 TiB, `MAP_FIXED` over the supervisor, mapping a file, `brk` into the supervisor, pointers into unmapped holes, fd exhaustion, closed fds | 13/13 handled |
| **Folders, current folder, relative paths**: `chdir` to `/etc`, `..` or a symlink to `/etc`; relative `../etc/passwd` and symlinks from `/workspace`; `openat` relative to a folder fd or to stdout; `stat`/`lstat`/`readlink` on symlinks pointing out; `getdents64`, `getcwd`, `uname`, `stat` writing into supervisor memory; signals to other processes; raising limits; `setuid(0)` | 32/32 |
| **`/tmp`**: `/tmp/../etc/passwd`; renaming files out to `/workspace` or in from it; `rmdir /tmp`; a folder into itself; read-only and write-only fds; unlink while open (the data stays readable, as on Linux, and a new file with the same name starts empty); a 1 TiB seek and a 1 TiB `ftruncate`; 70 open files (`EMFILE` at 64); 300 files (table full, names free again after unlink); filling `/tmp` past `tmp_kb` (`ENOSPC` at 4 MiB) | 22/22 |
| **Must stop the sandbox**: read the policy, erase the audit log, edit page tables, patch its own code, run code from the heap, stack or supervisor, `msr vbar_el1`, `msr sctlr_el1` (MMU off), `hvc`, `smc`, `eret`, `dc zva` on the log, ring the doorbell, touch memory outside RAM or beyond the memory limit, overflow the stack, `wfi`, sleep for an hour, spin | 21/21 stopped by the CPU or the watchdog |
| *(138 checks that must be refused or answered correctly, in all)* | **138/138 pass** |
| **Fuzzing**: 100 runs × 8,000 random system calls (63 different allowed calls plus random numbers) with hostile arguments: supervisor addresses, holes, huge lengths, paths like `..`, `/tmp/a`, `escape-link` | **800,000 calls, 0 supervisor crashes; all 100 runs finished** |

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

A defense-in-depth change came with the fixes: the VMM now writes forwarded results only into the agent's own areas,
without trusting the supervisor's check.

**Round 2: folders, the fd table and `/tmp`** roughly doubled the supervisor. Its new tests found one real bug:
`poll` always answered "nothing ready", and a shell's `read` treats that as a timeout. Rust programs never noticed. No new
security bug was found. One expectation changed: `/workspace//etc/passwd` now returns `ENOENT`. On Linux `//` means `/`,
so the path is `/workspace/etc/passwd`. In round 1 it reached the host's `/etc/passwd` path through a quirk of Rust's
`Path::join`, and only the VMM's canonicalize check stopped it.

**What this testing does not show:**
- **Not covered:** side channels (timing, cache), the host kernel's KVM code, and nested-virtualization behavior.
- **Fuzzing depth:** the fuzzing is random, not coverage-guided.
- **Audit:** no outside audit has been done.
- **Trusted base:** the supervisor (~1,200 lines) and the VMM's request handlers are the code to trust. That is still
  small enough to review line by line, which is the design's main security argument. Every system call added grows it,
  and each new one comes with its red-team tests.

## Compared with Firecracker

Firecracker is the reference design for microVM sandboxes, and it's battle-tested at AWS. Its site states: *"Boot in
<125ms"*, *"<5 MiB overhead per VM"*, *"Create up to 150 microVMs per second per host"*, and *"Only 5 emulated devices"*.
Those figures come from [firecracker-microvm.github.io](https://firecracker-microvm.github.io/), which doesn't say what
hardware or end point they measure. **This is not a side-by-side benchmark.**

| | Firecracker (its published figures) | This sandbox (measured above) |
|---|---|---|
| What runs inside each VM | A full Linux guest kernel | No kernel: a ~1,200-line supervisor |
| Emulated devices | 5 (virtio-net, virtio-block, virtio-vsock, serial, keyboard controller) | **0**: no virtio, no serial, no device tree |
| Boot | Boots a guest kernel (<125 ms) | **Nothing to boot**: about 4 ms for the whole lifecycle |
| Memory | <5 MiB VMM overhead, plus the guest kernel and its memory | **3.1 MB total** per idle sandbox |
| Creation rate | Up to 150 microVMs/s per host | 338–555/s on just 2 vCPUs, nested |
| What the sandbox sees | Devices and packets | **Every system call**, with its paths and arguments, in an audit log |
| Policy granularity | Network and disk level | Per system call, per path prefix, per errno. L7 rules and credential injection are possible. |
| **Compatibility** | **Anything Linux runs**: Python, Node, shells, `pip install` | **Only what the supervisor implements**: ~70 system calls; static, single-threaded programs; real tools like busybox, but no starting new programs yet |
| Maturity | Years in production | A prototype |

**Where this design wins:** fast, cheap, closely watched execution of known tools and static programs. That means no
kernel boot, no devices, no guest OS to patch, and visibility into every system call the code makes.

**Where Firecracker wins:** running arbitrary code. Supporting Python or Node here means implementing much more of the
Linux system-call interface (threads, a file system, pipes, `epoll`, `fork`), which is the multi-year job gVisor did. A
practical platform could use both: this sandbox for the fast path, and a microVM for "run anything".

## Limitations (today)

- One vCPU and no threads (`clone` is refused). No `fork`/`exec`. Static binaries only (fixed-address or static PIE).
- The audit log holds 10,000 entries, and a full log stops the agent, so a run is limited to 10,000 system calls. Long-running agents need the log streamed to the VMM.
- `/workspace` is read-only. `/tmp` is writable but lives in VM memory: it's gone when the sandbox ends, and deleting a
  file frees its name but not its memory (a bump allocator, capped by `tmp_kb`). No pipes, no symlinks in `/tmp`, no
  `chmod`. No `/proc`.
- No network: `socket` is refused, with no L4 or L7 forwarding yet.
- `mprotect` is accepted but not enforced, and `munmap` doesn't free memory (a bump allocator, capped by `memory_mb`).
- No guest timer interrupts: time limits are enforced from the host by the watchdog.
- arm64 (aarch64) only. x86_64 needs a port (VMX, different page tables and system-call numbers).
- Not audited, and fuzzed only randomly (see above). The supervisor's system-call layer is the attack surface.

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
limactl shell vmm ./run-redteam.sh           # 138 attacks, 21 must-stop attacks, 20 fuzz runs (FUZZ_SEEDS=100 for more)
limactl shell vmm sh -c 'sudo apk add busybox-static && ./compat/run-busybox.sh'   # real tools
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
