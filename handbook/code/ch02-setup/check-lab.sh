#!/bin/sh
# check-lab.sh: is this machine ready for the book's examples?
# Prints one OK / MISSING / NOTE line per check. Needs no root.
# Exit status: 0 if nothing is MISSING, 1 otherwise.

missing=0
ok()   { printf 'OK       %s\n' "$*"; }
miss() { printf 'MISSING  %s\n' "$*"; missing=$((missing + 1)); }
note() { printf 'NOTE     %s\n' "$*"; }

# 1. Linux, and the CPU architecture: Part I runs on any Linux,
#    Parts II and III need arm64.
os=$(uname -s)
if [ "$os" = Linux ]; then
  ok "os: Linux"
else
  miss "os: $os (the book needs Linux; on a Mac use Lima, see 2.3)"
fi
arch=$(uname -m)
case "$arch" in
  aarch64|arm64) ok "arch: $arch (all chapters)" ;;
  x86_64)        note "arch: x86_64 (Part I only; KVM parts need arm64)" ;;
  *)             miss "arch: $arch (the book expects aarch64 or x86_64)" ;;
esac

# 2. /dev/kvm: present, and usable without sudo.
if [ -e /dev/kvm ]; then
  if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
    ok "/dev/kvm: present, read/write for $(id -un)"
  else
    miss "/dev/kvm: present, but $(id -un) can't read and write it" \
         "(add yourself to group $(stat -c %G /dev/kvm 2>/dev/null))"
  fi
else
  miss "/dev/kvm: not found (no KVM here, see 2.1)"
fi

# 3. Kernel headers must match the kernel that is running now.
#    KERNEL_RELEASE lets you test this check against another version.
running=${KERNEL_RELEASE:-$(uname -r)}
if [ -d "/lib/modules/$running/build/include" ]; then
  ok "kernel headers: match running kernel $running"
else
  found=$(ls -d /usr/src/linux-headers-* /usr/src/kernels/* 2>/dev/null |
          sed 's|.*/||; s|^linux-headers-||' | tr '\n' ' ')
  if [ -n "$found" ]; then
    miss "kernel headers: none for running kernel $running" \
         "(found: ${found% })"
  else
    miss "kernel headers: none for running kernel $running"
  fi
fi

# 4. Tools.
for tool in gcc make gdb strace; do
  if command -v "$tool" >/dev/null 2>&1; then
    ok "$tool: $(command -v "$tool")"
  else
    miss "$tool: not installed"
  fi
done

# 5. Optional: Rust, for chapters 10 to 18. Building on another
#    machine and copying the binary over is fine too.
if command -v cargo >/dev/null 2>&1; then
  ok "cargo: $(cargo --version 2>/dev/null)"
  if command -v rustup >/dev/null 2>&1 &&
     rustup target list --installed 2>/dev/null |
       grep -q '^aarch64-unknown-linux-musl$'; then
    ok "rust target: aarch64-unknown-linux-musl"
  else
    note "rust target: run 'rustup target add aarch64-unknown-linux-musl'"
  fi
else
  note "cargo: not here (fine if you build Rust elsewhere, see 2.5)"
fi

echo
if [ "$missing" -eq 0 ]; then
  echo "All required checks passed."
else
  echo "$missing check(s) missing. See chapter 2 for the fix."
fi
[ "$missing" -eq 0 ]
