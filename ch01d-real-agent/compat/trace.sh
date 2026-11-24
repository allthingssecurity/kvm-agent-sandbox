#!/bin/sh
# Run each agent framework's real tool command under strace; list the system calls it makes.
cd "$(dirname "$0")"; out=traces; rm -rf $out; mkdir -p $out
trace() { name=$1; shift; strace -f -qq -o $out/$name.raw "$@" >/dev/null 2>&1
  sed -E 's/^[0-9]+ +//; s/^([a-z0-9_]+)\(.*/\1/; /^[a-z0-9_]+$/!d' $out/$name.raw | sort | uniq -c | sort -rn > $out/$name.calls
  printf '%-34s %5s distinct system calls, %6s calls in total\n' "$name" "$(wc -l < $out/$name.calls)" "$(awk '{s+=$1} END {print s}' $out/$name.calls)"; }
for k in _build_ls_cmd _build_read_cmd _build_glob_cmd _build_write_preflight_cmd _build_edit_inline_cmd; do
  python3 -c "import json,sys; sys.stdout.write(json.load(open('da_cmds.json'))['$k'])" > $out/$k.sh
  trace "deepagents$k" sh -c "$(cat $out/$k.sh)"
done
mkdir -p h_uds h_file; cp hermes_tools_uds.py h_uds/hermes_tools.py; cp hermes_tools_file.py h_file/hermes_tools.py
trace hermes_execute_code_uds  env PYTHONPATH=h_uds HERMES_RPC_SOCKET=/tmp/hermes.sock python3 model_code.py
trace hermes_execute_code_file env PYTHONPATH=h_file HERMES_RPC_DIR=/tmp/hermes_rpc timeout 2 python3 model_code.py
trace hermes_terminal bash -c 'cd /workspace && ls -la && grep -c agent notes.txt'
cat $out/*.calls | awk '{print $2}' | sort -u > $out/ALL
echo; echo "union of all: $(wc -l < $out/ALL) distinct system calls"
