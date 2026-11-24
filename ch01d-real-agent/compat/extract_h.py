import ast, sys, os
tree = ast.parse(open(sys.argv[1]).read())
ns = {}
for node in tree.body:
    if isinstance(node, (ast.Assign, ast.AnnAssign, ast.FunctionDef)):
        try: exec(compile(ast.Module([node], []), "h", "exec"), ns)
        except Exception: pass
tools = sorted(ns["_TOOL_STUBS"])
print("tool stubs:", tools)
for t in ("uds", "file"):
    open(os.path.join(os.path.dirname(sys.argv[1]), f"hermes_tools_{t}.py"), "w").write(ns["generate_hermes_tools_module"](tools, transport=t))
