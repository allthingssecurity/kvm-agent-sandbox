#!/bin/sh
# A host process swaps workspace/d between a real folder and a symlink to /etc, as fast as it can,
# while the sandboxed program opens /workspace/d/passwd thousands of times.
cd "$(dirname "$0")"
W=redteam/workspace; mkdir -p $W/real-d && echo "harmless file inside the workspace" > $W/real-d/passwd
( while :; do ln -sfn real-d $W/d; ln -sfn /etc $W/d; done ) & SWAPPER=$!
for i in 1 2 3 4 5 6 7 8 9 10; do
    ./vmm/target/aarch64-unknown-linux-musl/release/vmm --policy policies/redteam.policy \
        redteam/target/aarch64-unknown-linux-musl/release/redteam -- race 3000 | grep "^race:"
done | awk '{n+=$2; i+=$4; r+=$10; l+=$15} END {printf "total: %d opens, %d inside, %d refused/missing, %d LEAKED\n", n, i, r, l}'
kill $SWAPPER
