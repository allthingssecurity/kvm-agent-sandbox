#!/bin/sh
# Run real, unmodified tools in the sandbox: Alpine's static busybox (a static PIE, not recompiled).
# Inside the Linux VM:  limactl shell vmm ./compat/run-busybox.sh
# Needs: apk add busybox-static  (the script copies /bin/busybox.static to compat/bin/busybox).
cd "$(dirname "$0")/.."
V=./vmm/target/aarch64-unknown-linux-musl/release/vmm
B=compat/bin/busybox
mkdir -p compat/bin
[ -x $B ] || cp /bin/busybox.static $B || { echo "install busybox-static first"; exit 1; }

printf '%-62s %-10s %6s %9s\n' "command (cwd = /workspace)" "result" "exits" "time"
run() {
    out=$($V $B -- "$@" 2>&1)
    code=$(echo "$out" | sed -n 's/.*agent exited with code \([0-9]*\).*/\1/p')
    exits=$(echo "$out" | sed -n 's/.*VM exits: \([0-9]*\).*/\1/p')
    ms=$(echo "$out" | sed -n 's/.*Total time \([0-9.]*\) ms.*/\1/p')
    if [ "$code" = 0 ]; then res=ok; elif [ -n "$code" ]; then res="exit $code"; else res=$(echo "$out" | grep -o "STOPPED: [a-z ]*" | head -1); fi
    printf '%-62s %-10s %6s %7s ms\n' "$*" "$res" "$exits" "$ms"
}
# reading the workspace (forwarded to the host, read-only)
run ls -la /workspace
run ls
run find /workspace -name '*.txt'
run grep -rn agent /workspace
run cat /workspace/notes.txt
run head -c 20 /workspace/notes.txt
run tail -n 1 /workspace/notes.txt
run wc -l /workspace/notes.txt
run sort /workspace/notes.txt
run awk '{print $1}' /workspace/notes.txt
run sed s/agent/AGENT/ /workspace/notes.txt
run md5sum /workspace/notes.txt
run sha256sum /workspace/notes.txt
run base64 /workspace/notes.txt
run od -c -N 8 /workspace/notes.txt
run xxd -l 16 /workspace/notes.txt
run stat /workspace/notes.txt
run du -a /workspace
run diff /workspace/notes.txt /workspace/notes.txt
run cmp /workspace/notes.txt /workspace/notes.txt
run realpath /workspace/notes.txt
# writing: only /tmp, which lives in VM memory
run mkdir -p /tmp/a/b/c
run cp /workspace/notes.txt /tmp/copy.txt
run tar -cf /tmp/ws.tar /workspace
# the shell, with its built-in commands (other commands need exec: not yet)
run sh -c 'echo hello > /tmp/f; echo world >> /tmp/f; while read l; do echo got: $l; done < /tmp/f'
run sh -c 'cd /workspace; for f in *; do echo file: $f; done; pwd'
run sh -c 'x=0; while [ $x -lt 1000 ]; do x=$((x+1)); done; echo $x'
# identity and system
run uname -a
run id
run nproc
run date
run env
# expected to fail
run sh -c 'echo x > /workspace/new.txt'
run ls /
run sh -c 'cat /workspace/notes.txt | wc -l'
run sh -c 'mkdir /tmp/x'
run free
run ps
