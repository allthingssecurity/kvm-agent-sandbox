#!/bin/sh
# Fetch the real tool code of two agent frameworks and extract what they would run in a sandbox.
# Run on any machine with curl and python3; then run ./trace.sh inside Linux (needs python3, bash, strace).
# Pinned to the commits tested (2026-11-24). Both projects are MIT-licensed; their code isn't stored in this repo.
set -e; cd "$(dirname "$0")"
DA=efba634640e75a901d35d85e05c8f2f7c91909de   # langchain-ai/deepagents
HA=a15b9710395aa1c4858fb6dd9e4c5014c5ced4e9   # NousResearch/hermes-agent
curl -fsSL https://raw.githubusercontent.com/langchain-ai/deepagents/$DA/libs/deepagents/deepagents/backends/sandbox.py -o da_sandbox.py
curl -fsSL https://raw.githubusercontent.com/NousResearch/hermes-agent/$HA/tools/code_execution_tool.py -o h_code_execution_tool.py
python3 -I extract_da.py da_sandbox.py da_cmds.json      # deepagents' ls/read/glob/write/edit commands
python3 -I extract_h.py "$PWD/h_code_execution_tool.py" # Hermes' hermes_tools.py module, both transports
