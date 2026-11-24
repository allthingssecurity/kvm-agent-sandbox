import ast, sys, base64, json, shlex, re, os
src = open(sys.argv[1]).read()
tree = ast.parse(src)
ns = {"base64": base64, "json": json, "shlex": shlex, "re": re, "os": os, "_get_backend_read_file_type": lambda p: "text", "normalize_read_bounds": lambda o, l: (o, l)}
# module-level constants and helper functions only (skip classes and imports of deepagents)
for node in tree.body:
    if isinstance(node, (ast.Assign, ast.AnnAssign, ast.FunctionDef)):
        try: exec(compile(ast.Module([node], []), "da", "exec"), ns)
        except Exception as e: pass
cmds = {}
def tryit(name, *a, **k):
    try: cmds[name] = ns[name](*a, **k)
    except Exception as e: print(f"# {name}: {type(e).__name__}: {e}", file=sys.stderr)
tryit("_build_ls_cmd", "/workspace")
tryit("_build_read_cmd", "/workspace/notes.txt", 0, 100)
tryit("_build_glob_cmd", "**/*.txt", "/workspace")
tryit("_build_write_preflight_cmd", "/workspace/new.txt")
tryit("_build_edit_inline_cmd", "/workspace/notes.txt", "agent", "AGENT", replace_all=False)
json.dump(cmds, open(sys.argv[2], "w"), indent=1)
for k, v in cmds.items(): print(f"{k}: {len(v)} chars, starts: {v[:60]!r}")
