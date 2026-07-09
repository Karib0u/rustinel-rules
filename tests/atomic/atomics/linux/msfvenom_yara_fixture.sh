#!/usr/bin/env bash
# Atomic test - rule yara-lnx-msfvenom-stager
#   "Metasploit / Mettle (Linux Meterpreter) stage markers"  (yara file_scan)
#
# Copies /bin/true, appends Meterpreter/Mettle marker strings as an ELF overlay,
# executes the copy, then removes it. The overlay does not affect execution.
set -u
BIN=/tmp/rustinel_atomic_msfvenom
cp /bin/true "$BIN" 2>/dev/null || cp /usr/bin/true "$BIN" 2>/dev/null || true
printf '%s\n' 'mettle' 'meterpreter' 'core_channel_open' 'stdapi_sys_config' 'libmettle' >> "$BIN" 2>/dev/null || true
chmod 0755 "$BIN" 2>/dev/null || true
"$BIN" >/dev/null 2>&1 || true
rm -f "$BIN" 2>/dev/null || true
exit 0
