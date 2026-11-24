#!/bin/sh
# Attack the sandbox from inside. Run inside Linux with /dev/kvm:  limactl shell vmm ./run-redteam.sh
# A test passes only if the attack is refused or stopped in the expected way. A stop caused by a
# supervisor crash ("supervisor fault") or an attack that "SURVIVED" counts as a failure.
cd "$(dirname "$0")"
V=./vmm/target/aarch64-unknown-linux-musl/release/vmm
R=./redteam/target/aarch64-unknown-linux-musl/release/redteam
P=policies/redteam.policy

# A workspace that looks like a cloned repository with planted symlinks.
mkdir -p redteam/workspace
printf 'a file the agent may read\n' > redteam/workspace/notes.txt
ln -sfn /etc/passwd redteam/workspace/escape-link
ln -sfn /etc redteam/workspace/etc-link

echo "################ 1. attacks that must come back as errors"
timeout 30 $V --policy $P $R -- probe | sed -n '/^-- steal/,/passed, .* failed/p'

echo; echo "################ 2. attacks that must stop the sandbox"
pass=0; fail=0
check() { # name, expected phrase in the STOPPED line
    out=$(timeout 30 $V --policy $P $R -- fatal "$1" 2>&1); line=$(echo "$out" | grep "STOPPED" | sed 's/VMM: agent STOPPED: //')
    if echo "$out" | grep -q "SURVIVED\|supervisor fault" || ! echo "$line" | grep -q "$2"; then
        fail=$((fail+1)); echo "FAIL  $1"; echo "$out" | grep "redteam:\|STOPPED\|Error\|fault" | sed 's/^/        /'
    else pass=$((pass+1)); printf 'PASS  %-26s %s\n' "$1" "$line"; fi
}
for a in read-policy erase-audit-log edit-page-tables patch-own-code ring-doorbell touch-outside-ram \
         zero-audit-log-dczva beyond-memory-limit stack-overflow; do check $a "memory access it isn't allowed"; done
for a in run-supervisor-code run-from-heap run-from-stack; do check $a "jump into memory it may not run"; done
for a in set-vector-table read-page-table-register turn-off-mmu hypervisor-call firmware-call eret; do check $a "illegal instruction"; done
for a in wait-for-interrupt sleep-an-hour spin; do check $a "time limit"; done
echo "$pass passed, $fail failed"

echo; echo "################ 3. fuzzing: random system calls with hostile arguments"
seeds=${FUZZ_SEEDS:-20}; calls=${FUZZ_CALLS:-5000}; bad=0
for s in $(seq 1 $seeds); do
    out=$(timeout 30 $V --policy $P $R -- fuzz $s $calls 2>&1); code=$?
    how=$(echo "$out" | grep -o "supervisor still answering\|STOPPED: .*\|Error: .*" | head -1)
    case "$how" in
        "supervisor still answering"|"STOPPED: output limit"*|"STOPPED: write to address 0"*|"STOPPED: memory access"*) ;;
        *) bad=$((bad+1)); echo "FAIL seed $s (exit $code): $how" ;;
    esac
    echo "$how" | sed 's/: class.*//; s/ of .*//'
done | sort | uniq -c
echo "($seeds runs x $calls calls; a run fails only on a supervisor crash, a VMM error or a hang)"
