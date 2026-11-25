#!/bin/sh
# Rebuild today's supervisor and VMM with the FIRST version of ppoll put back
# (war story: "nothing is ready", so the shell's `read` gives up). Run on the Mac.
set -e
cd "$(dirname "$0")"
mkdir -p ppoll-bug
git -C ../../.. archive HEAD ch01d-real-agent/supervisor ch01d-real-agent/vmm | tar -x -C ppoll-bug
cd ppoll-bug/ch01d-real-agent
python3 - <<'PY'
p = "supervisor/src/main.rs"
s = open(p).read()
start = s.index("fn ppoll(s: &State")
end = s.index("\n}\n", start) + 3
old = '''fn ppoll(_s: &State, fds: u64, nfds: u64) -> i64 {
    // CHAPTER 14 DEMO: the first version of ppoll, before the fix.
    if nfds > 64 || !user_writable(fds, nfds * 8) { return -EFAULT; }
    for i in 0..nfds {
        unsafe { ((fds + i * 8 + 6) as *mut u16).write_volatile(0) } // revents = 0: nothing wrong
    }
    0
}
'''
open(p, "w").write(s[:start] + old + s[end:])
PY
(cd supervisor && cargo build --release -q)
(cd vmm && cargo build --release -q)
echo "built: $(pwd)/vmm/target/aarch64-unknown-linux-musl/release/vmm"
