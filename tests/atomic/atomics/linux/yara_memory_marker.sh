#!/usr/bin/env bash
# Atomic test - rule yara-fixture-memory-marker  (yara process_memory)
#
# A long-lived shell builds the marker from fragments at runtime and holds it in
# a variable, so the bytes exist only in its memory: not in the image, the script
# or the command line. Only a process-memory scan can see them. The shell runs
# from a temp copy because the engine does not scan trusted system paths such as
# /usr/bin or /bin. The harness enables scanner.yara_memory_enabled for the whole
# run; the engine waits yara_memory_delay_ms after process start before reading,
# so the shell must outlive it.
set -u
DIR=$(mktemp -d "${TMPDIR:-/tmp}/rustinel_atomic_memory.XXXXXX")
trap 'rm -rf "$DIR"' EXIT
BIN="$DIR/sh"
cp /bin/sh "$BIN"
chmod 0755 "$BIN"
"$BIN" -c 'a=RUSTINEL; b=MEMORY; c=FIXTURE; d=b83e41c7; m="$a-$b-$c-$d"; sleep 8; : "$m"' >/dev/null 2>&1
exit 0
