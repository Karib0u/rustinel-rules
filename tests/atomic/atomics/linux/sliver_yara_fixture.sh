#!/usr/bin/env bash
# Atomic test - rule yara-lnx-sliver-implant
#   "Sliver C2 implant artifacts in Linux ELF images"  (yara file_scan)
#
# Appends two marker strings the production signature keys on (2 of its string
# set) to a harmless ELF overlay and keeps its process alive while the
# asynchronous scanner resolves the image through /proc. The strings are plain
# text; the copied shell is unchanged and runs nothing of Sliver.
set -eu
DIR=$(mktemp -d "${TMPDIR:-/tmp}/rustinel_atomic_sliver.XXXXXX")
trap 'rm -rf "$DIR"' EXIT
BIN="$DIR/sh"
cp /bin/sh "$BIN"
printf '%s\n' 'sliverpb' 'bishopfox/sliver' >> "$BIN"
chmod 0755 "$BIN"
"$BIN" -c 'sleep 3; :' >/dev/null 2>&1
