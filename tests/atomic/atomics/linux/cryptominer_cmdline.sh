#!/usr/bin/env bash
# Atomic test - rule 43dae6e5-fb47-46a0-90a3-a0992f985eaa
#   "Cryptominer Command Line"  (process_creation)
#
# Copies /bin/sh to a neutral file name and passes a stratum pool URL and the
# donate-level option as arguments; nothing connects.
# The shell copy lives under /opt (not world-writable) so the broad
# execution-from-temp rule does not shadow this one. Nothing connects.
set -u
DIR=/opt/rustinel_atomic_miner.d
BIN="$DIR/rustinel_atomic_miner"
mkdir -p "$DIR" 2>/dev/null || true
cp /bin/sh "$BIN" 2>/dev/null || cp /usr/bin/sh "$BIN" 2>/dev/null || true
chmod 0755 "$BIN" 2>/dev/null || true
timeout 3 "$BIN" -c 'sleep 1; :' stratum+tcp://pool.invalid:3333 --donate-level 1 >/dev/null 2>&1 || true
rm -rf "$DIR" 2>/dev/null || true
exit 0
