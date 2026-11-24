# What a model typically writes for Hermes' execute_code tool
from hermes_tools import read_file, terminal
print(read_file("/workspace/notes.txt"))
print(terminal("ls /workspace"))
