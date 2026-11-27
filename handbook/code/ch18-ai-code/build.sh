#!/bin/sh
# Build Lua, QuickJS and MicroPython as static arm64 programs.
# Run inside the lab VM. Everything goes into ./build (about 60 MB).
set -e
cd "$(dirname "$0")"
mkdir -p build && cd build
LUA=lua-5.4.7 QJS=quickjs-2025-04-26 MPY=micropython-1.29.0

# Lua: one Makefile target, static link.
[ -d $LUA ] || wget -q https://www.lua.org/ftp/$LUA.tar.gz -O - | tar xzf -
make -s -C $LUA -j2 posix MYLDFLAGS=-static
cp $LUA/src/lua lua

# QuickJS: the qjs program only, static link.
[ -d $QJS ] || wget -q https://bellard.org/quickjs/$QJS.tar.xz -O - | tar xJf -
make -s -C $QJS -j2 qjs LDFLAGS=-static
cp $QJS/qjs qjs

# MicroPython: the full source tarball is 150 MB with every vendored
# library, so unpack only what the Unix port needs.
if [ ! -d $MPY ]; then
    wget -q https://micropython.org/resources/source/$MPY.tar.xz
    tar xJf $MPY.tar.xz $(for d in py extmod shared mpy-cross ports/unix \
        tools drivers lib/re1.5 lib/uzlib lib/littlefs lib/oofatfs \
        lib/crypto-algorithms lib/libm lib/libm_dbl; do echo $MPY/$d; done)
fi
make -s -C $MPY/mpy-cross -j2
# No threads, no FFI, no TLS, no btree: they need libraries we don't ship
# and calls the sandbox refuses anyway. MicroPython uses getrandom() only
# with glibc; with musl it opens /dev/random, which the sandbox refuses.
# The two CFLAGS turn getrandom() on for musl too.
make -s -C $MPY/ports/unix -j2 MICROPY_PY_THREAD=0 MICROPY_PY_FFI=0 \
    MICROPY_PY_SSL=0 MICROPY_PY_BTREE=0 FROZEN_MANIFEST= LDFLAGS_EXTRA=-static \
    CFLAGS_EXTRA="-D_HAVE_GETRANDOM -include sys/random.h"
cp $MPY/ports/unix/build-standard/micropython micropython

# The booby-trapped archive for section 18.6.
cd .. && python3 make-evil-tar.py
ls -l build/lua build/qjs build/micropython workspace/evil.tar
