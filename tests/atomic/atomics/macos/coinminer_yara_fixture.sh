#!/usr/bin/env bash
# Atomic test — rule yara-macos-coinminer-strings
#   "Cryptominer Mach-O strings"  (yara file_scan)
#
# Copies a Mach-O binary (so the magic at offset 0 matches the rule), appends
# miner marker strings as an overlay, reads and executes the copy, then removes
# it. The overlay keeps the Mach-O header intact but invalidates the code
# signature, so AMFI may SIGKILL the exec before the engine scans it — which is
# why this test is marked allow_failure in the manifest (the file_scan path is
# the least deterministic to time in CI). The read still offers the engine a
# file event to hash.
set -u
DST="/tmp/rustinel_atomic_xmrig"
cp /usr/bin/true "$DST" 2>/dev/null || cp /bin/echo "$DST" 2>/dev/null || true
printf '%s\n' 'xmrig' 'stratum+tcp://' '--donate-level' 'randomx' 'cryptonight' >> "$DST" 2>/dev/null || true
chmod 0755 "$DST" 2>/dev/null || true
cat "$DST" >/dev/null 2>&1 || true
"$DST" >/dev/null 2>&1 || true
rm -f "$DST" 2>/dev/null || true
exit 0
