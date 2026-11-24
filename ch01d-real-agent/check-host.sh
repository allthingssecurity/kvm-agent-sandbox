#!/bin/sh
# Can this Linux machine run the sandbox? Checks every requirement and says what to do if one is missing.
# Usage: ./check-host.sh      (no root needed)
ok=0; bad=0
pass() { printf '  ok    %s\n' "$1"; ok=$((ok+1)); }
fail() { printf '  NO    %s\n        -> %s\n' "$1" "$2"; bad=$((bad+1)); }
note() { printf '  note  %s\n' "$1"; }

echo "Required:"
[ "$(uname -s)" = Linux ] && pass "Linux ($(uname -r))" || fail "not Linux: $(uname -s)" "use a Linux machine or a Linux VM (on a Mac: Lima, see README)"
case "$(uname -m)" in
    aarch64|arm64) pass "64-bit ARM CPU ($(uname -m))" ;;
    *) fail "CPU is $(uname -m)" "the supervisor is arm64 code; x86_64 needs a port (not done yet)" ;;
esac
if [ -e /dev/kvm ]; then
    if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then pass "/dev/kvm is usable by $(id -un)"
    else fail "/dev/kvm exists but $(id -un) can't open it" "sudo usermod -aG kvm $(id -un), then log in again (or: sudo chmod 666 /dev/kvm on a throwaway VM)"; fi
else
    fail "no /dev/kvm" "enable virtualization: bare metal or a VM with nested virtualization; load the module (sudo modprobe kvm)"
fi
kmaj=$(uname -r | cut -d. -f1); kmin=$(uname -r | cut -d. -f2 | sed 's/[^0-9].*//')
if [ "$kmaj" -gt 5 ] || { [ "$kmaj" -eq 5 ] && [ "$kmin" -ge 6 ]; }; then pass "kernel >= 5.6 (openat2)"
else fail "kernel $(uname -r) is older than 5.6" "openat2 is needed for workspace access; use a newer kernel"; fi

echo "Optional (the sandbox runs without them, with fewer walls; it says so when it starts):"
if [ "$kmaj" -gt 6 ] || { [ "$kmaj" -eq 6 ] && [ "$kmin" -ge 12 ]; }; then pass "kernel >= 6.12: Landlock with signal and socket scopes"
elif [ "$kmaj" -gt 5 ] || { [ "$kmaj" -eq 5 ] && [ "$kmin" -ge 13 ]; }; then note "kernel < 6.12: Landlock without scopes"
else note "kernel < 5.13: no Landlock (seccomp and the VMM's checks only)"; fi
grep -qw landlock /sys/kernel/security/lsm 2>/dev/null && pass "Landlock is enabled" || note "Landlock not listed in /sys/kernel/security/lsm (may be disabled at boot: lsm=...,landlock)"
[ "$(cat /proc/sys/user/max_user_namespaces 2>/dev/null || echo 0)" -gt 0 ] && pass "user namespaces allowed" || note "user namespaces disabled: the VMM runs without them"
grep -q "\[always\]\|\[madvise\]" /sys/kernel/mm/transparent_hugepage/enabled 2>/dev/null && pass "transparent huge pages available (speed setting)" || note "no transparent huge pages: slower (VMM_HUGEPAGES has no effect)"

echo "For the tests and comparisons:"
for b in /bin/busybox.static /bin/busybox /usr/bin/busybox; do
    if [ -x "$b" ] && [ "$(head -c 4 "$b" | tail -c 3)" = ELF ] && ! grep -q "/lib/ld-" "$b"; then pass "static busybox: $b"; BB=$b; break; fi
done
[ -n "$BB" ] || fail "no static busybox" "Alpine: sudo apk add busybox-static   Debian/Ubuntu: sudo apt install busybox-static"
command -v bwrap >/dev/null && pass "bubblewrap (for the namespace-sandbox comparison)" || note "no bwrap: comparisons skip that row (Alpine: apk add bubblewrap, Debian: apt install bubblewrap)"
command -v python3 >/dev/null && pass "python3 (compat/compare-isolation.py)" || note "no python3: skip compat/compare-isolation.py"

echo; [ $bad -eq 0 ] && echo "Ready: $ok checks passed." || { echo "$bad requirement(s) missing."; exit 1; }
