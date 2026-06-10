#!/usr/bin/env bash
# Atomic test - rule yara-lnx-xmrig-coinminer
#   "XMRig / coinminer strings in Linux ELF binaries"  (yara file_scan)
#
# Copies /bin/true, appends miner marker strings as an ELF overlay, executes the
# copy, then removes it. The overlay does not affect execution.
set -u
BIN=/tmp/rustinel_atomic_xmrig
cp /bin/true "$BIN" 2>/dev/null || cp /usr/bin/true "$BIN" 2>/dev/null || true
printf '%s\n' 'xmrig' 'stratum+tcp://' 'donate-level' 'randomx' 'monero' >> "$BIN" 2>/dev/null || true
chmod 0755 "$BIN" 2>/dev/null || true
"$BIN" >/dev/null 2>&1 || true
rm -f "$BIN" 2>/dev/null || true
exit 0
