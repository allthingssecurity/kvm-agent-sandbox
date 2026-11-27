# What an agent writes when asked "unpack this archive".
# It trusts the names stored inside the file.
import os, sys

src, dest = sys.argv[1], sys.argv[2]
try:
    os.mkdir(dest)
except OSError:
    pass
data = open(src, "rb").read()
pos = 0
while pos + 512 <= len(data) and data[pos] != 0:
    name = data[pos:pos + 100].split(b"\0")[0].decode()
    size = int(data[pos + 124:pos + 135].decode() or "0", 8)
    with open(dest + "/" + name, "wb") as f:  # no check for ".."
        f.write(data[pos + 512:pos + 512 + size])
    print("extracted", name)
    pos += 512 + (size + 511) // 512 * 512
