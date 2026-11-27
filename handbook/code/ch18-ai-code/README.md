# Chapter 18 demos: running code an AI wrote

Run everything inside the lab VM.

    sh build.sh          # static lua, qjs and micropython in build/, and workspace/evil.tar
    sh run-all.sh        # every demo in the chapter; results.txt is one such run

`run-all.sh` works from `ch01d-real-agent/` (build the sandbox there first with its
`build.sh`). By hand, from that folder:

    V=./vmm/target/aarch64-unknown-linux-musl/release/vmm
    C=../handbook/code/ch18-ai-code B=$C/build
    $V --policy $C/ai.policy $B/micropython -- /workspace/report.py

- `ai.policy`: the default policy with this folder's `workspace/`, 84 MB and 10 s.
- `workspace/report.py`, `report.lua`, `report.js`: the same CSV summary in three languages.
- `workspace/attack.py`: what a prompt-injected script tries.
- `workspace/untar.py` + `make-evil-tar.py`: the zip-slip demo. Run as a plain
  process, `untar.py` writes `~/PWNED.txt`; `run-all.sh` renames it afterwards.
- `starts.py`: print(1) start-up times, plain and in a fresh VM.
