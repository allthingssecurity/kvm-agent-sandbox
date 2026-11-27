# Median start-up time of "print 1": each interpreter as a plain process,
# then in a fresh sandbox VM. Run from ch01d-real-agent/ in the lab.
import statistics, subprocess, sys, time

B = "../handbook/code/ch18-ai-code/build/"
V = ["./vmm/target/aarch64-unknown-linux-musl/release/vmm",
     "--policy", "../handbook/code/ch18-ai-code/ai.policy"]
PROGS = [("lua", [B + "lua", "-e", "print(1)"]),
         ("quickjs", [B + "qjs", "-e", "print(1)"]),
         ("micropython", [B + "micropython", "-c", "print(1)"])]

def median_ms(cmd, n=30):
    times = []
    for _ in range(n):
        t = time.perf_counter()
        subprocess.run(cmd, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)
        times.append(time.perf_counter() - t)
    return statistics.median(times) * 1000

print(f"{'':12} {'plain':>8} {'sandbox':>8}")
for name, cmd in PROGS:
    box = V + [cmd[0], "--"] + cmd[1:]
    print(f"{name:12} {median_ms(cmd):6.2f} ms {median_ms(box):6.2f} ms")
print(f"{'CPython':12} {median_ms([sys.executable, '-c', 'print(1)']):6.2f}"
      " ms  (plain, for scale)")
