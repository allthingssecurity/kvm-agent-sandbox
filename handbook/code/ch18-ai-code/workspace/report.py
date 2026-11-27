# What an agent writes when asked "summarise sales.csv".
import json

rows = []
for line in open("/workspace/sales.csv").read().split("\n")[1:]:
    if line:
        name, qty, price = line.split(",")
        rows.append((name, int(qty), float(price)))

total = sum(q * p for _, q, p in rows)
best = max(rows, key=lambda r: r[1] * r[2])
print(f"total {total:.2f}, best seller {best[0]}")

# Keep a scratch copy for the next step.
with open("/tmp/summary.json", "w") as f:
    f.write(json.dumps({"total": total, "best": best[0]}))
print("saved:", open("/tmp/summary.json").read())
