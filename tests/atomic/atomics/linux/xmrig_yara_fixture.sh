#!/usr/bin/env bash
# Atomic test - rule yara-lnx-xmrig-coinminer
#   "XMRig / coinminer strings in Linux ELF binaries" (yara file_scan)
#
# Append marker strings to a harmless ELF overlay and keep its process alive
# while the asynchronous scanner resolves the image through /proc.
set -eu
DIR=$(mktemp -d "${TMPDIR:-/tmp}/rustinel_atomic_xmrig.XXXXXX")
trap 'rm -rf "$DIR"' EXIT
BIN="$DIR/sh"
cp /bin/sh "$BIN"
printf '%s\n' 'xmrig' 'stratum+tcp://' 'donate-level' 'randomx' 'monero' >> "$BIN"
chmod 0755 "$BIN"
# A command after sleep keeps the copied shell alive instead of replacing it.
"$BIN" -c 'sleep 3; :' >/dev/null 2>&1
