#!/usr/bin/env bash
# Atomic test - rule 66fd4673-d86b-41d1-ba33-60d7c66dc962
#   "Backdoor Account Creation (Duplicate UID 0)"  (process_creation)
#
# Copies /bin/sh to a file whose basename is exactly useradd and runs it with the
# duplicate-UID-0 command line (-o -u 0). The -c body is 'sleep 1; :' — the
# trailing no-op keeps the shell from tail-exec'ing into sleep (which would drop
# its useradd Image and args), so it lives ~1s as useradd for /proc enrichment;
# no account is created.
set -u
DIR=/tmp/rustinel_atomic_useradd.d
BIN="$DIR/useradd"
mkdir -p "$DIR" 2>/dev/null || true
cp /bin/sh "$BIN" 2>/dev/null || cp /usr/bin/sh "$BIN" 2>/dev/null || true
chmod 0755 "$BIN" 2>/dev/null || true
timeout 3 "$BIN" -c 'sleep 1; :' -o -u 0 rustinelbackdoor >/dev/null 2>&1 || true
rm -rf "$DIR" 2>/dev/null || true
exit 0
