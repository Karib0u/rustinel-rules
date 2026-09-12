#!/usr/bin/env bash
# Atomic test - IOC set ioc-canary-exec  (hash IOC / file_scan)
#
# Rustinel computes hash IOCs from the resolved image path of a *process start*,
# so the only honest end-to-end test of that path is to launch a file whose bytes
# are fixed in advance. This writes the deterministic canary for the running
# architecture - a static ELF that does nothing but exit 0 - and executes it. Its
# SHA-256 is the indicator in preview/ioc/common/ioc_canary_exec.yml.
#
# Regenerate both the blobs below and the recorded hashes with:
#   uv run python tests/atomic/canary/make_canary.py
#
# This replaces the EICAR test, which could never pass: a dropped file that is
# never executed is never hashed, and EICAR is a 16-bit DOS .COM that cannot
# become a process image at all.
set -u
DIR=/tmp/rustinel_atomic_canary
BIN="$DIR/canary-exec"

case "$(uname -m)" in
  x86_64|amd64)
    B64='f0VMRgIBAQAAAAAAAAAAAAIAPgABAAAAeABAAAAAAABAAAAAAAAAAAAAAAAAAAAA
AAAAAEAAOAABAEAAAAAAAAEAAAAFAAAAAAAAAAAAAAAAAEAAAAAAAAAAQAAAAAAA
gQAAAAAAAACBAAAAAAAAAAAQAAAAAAAAMf+4PAAAAA8F'
    ;;
  aarch64|arm64)
    B64='f0VMRgIBAQAAAAAAAAAAAAIAtwABAAAAeABAAAAAAABAAAAAAAAAAAAAAAAAAAAA
AAAAAEAAOAABAEAAAAAAAAEAAAAFAAAAAAAAAAAAAAAAAEAAAAAAAAAAQAAAAAAA
hAAAAAAAAACEAAAAAAAAAAAAAQAAAAAAAACA0qgLgNIBAADU'
    ;;
  *)
    echo "no canary for $(uname -m)" >&2
    exit 0
    ;;
esac

mkdir -p "$DIR" 2>/dev/null || true
printf '%s' "$B64" | tr -d '\n' | base64 -d > "$BIN" 2>/dev/null || true
chmod 0755 "$BIN" 2>/dev/null || true
"$BIN" >/dev/null 2>&1 || true
# The hash worker runs off the process-start event; keep the file readable for a
# moment so this tests detection rather than a deletion race.
sleep 3
rm -rf "$DIR" 2>/dev/null || true
exit 0
