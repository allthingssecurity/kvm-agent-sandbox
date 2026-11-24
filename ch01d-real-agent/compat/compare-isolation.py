"""Compare the cost of isolation per tool call, on the same Linux machine, with the same commands.

  native   : a new process in an already-running container. This is what a bash tool does inside a
             long-lived sandbox container (a long-lived agent container): no isolation between calls.
  bwrap    : a fresh namespace sandbox per call (new user/pid/net/ipc/uts/mount namespaces, read-only
             root, private /tmp): roughly what a container gives, without image or pod start-up.
  kvm-vm   : this repository: a fresh KVM VM per call, with the supervisor instead of a kernel.

Run inside the Linux VM from ch01d-real-agent:  python3 compat/compare-isolation.py
Needs: busybox-static, bubblewrap, python3.
"""
import os, statistics, subprocess, time

N = int(os.environ.get("RUNS", "100"))
VMM = "./vmm/target/aarch64-unknown-linux-musl/release/vmm"
BB = "compat/bin/busybox"
BWRAP = ["bwrap", "--unshare-all", "--die-with-parent", "--ro-bind", "/", "/", "--dev", "/dev",
         "--proc", "/proc", "--tmpfs", "/tmp", "--bind", os.path.abspath("workspace"), "/workspace"]

def ours(*args):
    return [VMM, "--policy", "policies/default.policy", BB, "--", *args]

CASES = [
    ("cat a file",              ["busybox", "cat", "/workspace/notes.txt"]),
    ("grep -rn over workspace", ["busybox", "grep", "-rn", "agent", "/workspace"]),
    ("sha256sum a file",        ["busybox", "sha256sum", "/workspace/notes.txt"]),
    ("ls -la workspace",        ["busybox", "ls", "-la", "/workspace"]),
]

def timed(cmd):
    t = time.perf_counter()
    r = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return (time.perf_counter() - t) * 1e3, r.returncode

def bench(cmd):
    for _ in range(5): timed(cmd)  # warm the page cache
    runs = [timed(cmd) for _ in range(N)]
    bad = sum(1 for _, rc in runs if rc != 0)
    ms = sorted(t for t, _ in runs)
    return statistics.median(ms), ms[int(0.99 * (len(ms) - 1))], bad

print(f"{N} runs each; median / p99 in ms (wall clock, including process start)\n")
print(f"{'tool call':<26} {'native':>15} {'bwrap (netns..)':>17} {'kvm-vm (ours)':>15}")
for name, cmd in CASES:
    bb = [BB if cmd[0] == "busybox" else cmd[0], *cmd[1:]]
    row = [bench(bb), bench(BWRAP + bb), bench(ours(*cmd[1:]))]
    cells = [f"{m:6.2f} / {p:6.2f}" + ("!" if bad else "") for m, p, bad in row]
    print(f"{name:<26} {cells[0]:>15} {cells[1]:>17} {cells[2]:>15}")

print("\nPython start-up, which most agent skills need (the kvm-vm sandbox can't run Python yet):")
py = ["python3", "-c", "print(open('/workspace/notes.txt').read().count('agent'))"]
for label, cmd in [("native", py), ("bwrap", BWRAP + py)]:
    m, p, bad = bench(cmd)
    print(f"  {label:<8} python3 -c ...   {m:6.2f} / {p:6.2f} ms" + (f"  ({bad} failed)" if bad else ""))

print("\nMemory of one idle sandbox, resident (RSS), measured after 1 s:")
def idle_rss(cmd):
    p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.0)
    total, pids = 0, [str(p.pid)]
    for pid in os.listdir("/proc"):  # the whole process tree (bwrap forks)
        if pid.isdigit():
            try:
                stat = open(f"/proc/{pid}/stat").read().split()
                if stat[3] == str(p.pid): pids.append(pid)
            except OSError: pass
    for pid in pids:
        try:
            for line in open(f"/proc/{pid}/status"):
                if line.startswith("VmRSS:"): total += int(line.split()[1])
        except OSError: pass
    p.kill(); p.wait()
    return total / 1024
print(f"  native sleep            {idle_rss([BB, 'sleep', '30']):6.2f} MB")
print(f"  bwrap + sleep           {idle_rss(BWRAP + [BB, 'sleep', '30']):6.2f} MB")
print(f"  native python3 (idle)   {idle_rss(['python3', '-c', 'import time; time.sleep(30)']):6.2f} MB")
print(f"  kvm-vm + sleep (VMM)    {idle_rss(ours('sleep', '30')):6.2f} MB   (RSS of the VMM; host memory per idle sandbox measured by loadtest: 3.1 MB)")

print("\nNetwork from inside (curl-like TCP connect to 1.1.1.1:443):")
probe = "import socket; s=socket.socket(); s.settimeout(2); s.connect(('1.1.1.1',443)); print('connected')"
for label, cmd in [("native", ["python3", "-c", probe]), ("bwrap", BWRAP + ["python3", "-c", probe])]:
    r = subprocess.run(cmd, capture_output=True, text=True)
    print(f"  {label:<8} {'CONNECTED' if 'connected' in r.stdout else 'blocked: ' + (r.stderr.strip().splitlines() or ['?'])[-1][:60]}")
r = subprocess.run(ours("nc", "-w", "2", "1.1.1.1", "443"), capture_output=True, text=True)
print(f"  {'kvm-vm':<8} {'blocked: socket() refused by the policy' if 'socket' in r.stdout and 'EACCES' in r.stdout else r.stdout[-200:]}")
