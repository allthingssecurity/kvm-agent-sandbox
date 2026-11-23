#!/bin/sh
# Run inside Linux with /dev/kvm (e.g. `limactl shell vmm ./run-tests.sh`). Each scenario prints its exit status.
cd "$(dirname "$0")"
V=./vmm/target/aarch64-unknown-linux-musl/release/vmm
run() { echo; echo "################ $1"; shift; timeout 30 "$@"; echo "[exit status $?]"; }
run "1. default policy, normal agent"   $V --policy policies/default.policy
run "2. strict policy, same agent"      $V --policy policies/strict.policy
run "3. infinite loop -> watchdog"      $V -- spin
run "4. memory hog -> memory limit"     $V -- hog
run "5. endless output -> output limit" sh -c "$V -- spam | tail -n 6"
run "6. jail self-test (the VMM attacks its own jail)" $V --jail-selftest
