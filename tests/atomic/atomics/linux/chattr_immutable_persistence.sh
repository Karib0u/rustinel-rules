#!/usr/bin/env bash
# Atomic test for Immutable Attribute Added to Linux Persistence Paths.
# The copied shell receives the flag and path as positional parameters.
set -eu
DIR=/opt/rustinel_atomic_chattr_immutable_persistence.d
BIN="$DIR/chattr"
mkdir "$DIR"
trap 'rm -f "$BIN"; rmdir "$DIR"' EXIT
cp /bin/sh "$BIN"
timeout 3 "$BIN" -c 'sleep 1; :' +i /etc/crontab
