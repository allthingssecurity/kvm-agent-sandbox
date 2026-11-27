#!/bin/sh
# Run every demo of chapter 18 and print what the book shows.
# Inside the lab VM:  sh run-all.sh > results.txt 2>&1
cd "$(dirname "$0")/../../../ch01d-real-agent"
C=../handbook/code/ch18-ai-code B=../handbook/code/ch18-ai-code/build
V=./vmm/target/aarch64-unknown-linux-musl/release/vmm
box() { echo "\$ \$V --policy \$C/ai.policy $*" | sed "s|$B|\$B|"
        $V --policy $C/ai.policy "$@" 2>&1; echo; }

echo "=== 18.3 and 18.4: Python";  box $B/micropython -- /workspace/report.py
box $B/micropython -- /workspace/attack.py
echo "=== 18.5: Lua and JavaScript"; box $B/lua -- /workspace/report.lua
box $B/qjs -- --std /workspace/report.js

echo "=== 18.6: zip-slip as a plain process"
mkdir -p /tmp/x && python3 $C/workspace/untar.py $C/workspace/evil.tar /tmp/x
cat "$HOME/PWNED.txt" && mv "$HOME/PWNED.txt" "$HOME/PWNED.plain-run.txt"
echo; echo "=== 18.6: zip-slip in the sandbox"
box $B/micropython -- /workspace/untar.py /workspace/evil.tar /tmp/x
ls "$HOME/PWNED.txt" 2>&1

echo; echo "=== 18.7: start-up, fresh VM per call"; python3 $C/starts.py
for p in "micropython -c" "lua -e" "qjs -e"; do
    set -- $p; echo; echo "=== 18.7: pool, $1"
    ./vmm/target/aarch64-unknown-linux-musl/release/pool --calls 40 \
        $B/$1 -- $2 "print(1)" 2>&1 | tail -7
done
