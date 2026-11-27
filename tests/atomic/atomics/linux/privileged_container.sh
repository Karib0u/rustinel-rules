#!/usr/bin/env bash
# Atomic test for Privileged Container or Host Root Mount.
# The copied shell receives all Docker arguments as positional parameters.
set -eu
DIR=/opt/rustinel_atomic_privileged_container.d
BIN="$DIR/docker"
mkdir "$DIR"
trap 'rm -f "$BIN"; rmdir "$DIR"' EXIT
cp /bin/sh "$BIN"
timeout 3 "$BIN" -c 'sleep 1; :' run --privileged placeholder
