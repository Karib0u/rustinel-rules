#!/usr/bin/env bash
# Exercise the setcap argument match using a disposable copy of /bin/sh.
set -eu
DIR=/opt/rustinel_atomic_setcap.d
BIN="$DIR/setcap"
mkdir -- "$DIR"
trap 'rm -f -- "$BIN"; rmdir -- "$DIR"' EXIT
cp /bin/sh "$BIN"
chmod 0755 "$BIN"
timeout 3 "$BIN" -c 'sleep 1; :' cap_setuid=ep "$DIR/dummy"
