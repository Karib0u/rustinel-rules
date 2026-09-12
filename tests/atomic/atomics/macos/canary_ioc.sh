#!/usr/bin/env bash
# Atomic test — IOC set ioc-canary-exec  (path-regex IOC / process image path)
#
# macOS gets the path indicator rather than the hash one. arm64 refuses to
# execute an unsigned image, and an ad-hoc signature is not byte-stable across
# toolchains, so a Mach-O canary cannot have a SHA-256 known at authoring time.
# Launching an untouched copy of a system binary from the canary path exercises
# the same IOC pipeline on the same process-start event.
#
# The launch path must keep matching the paths_regex indicator in
# preview/ioc/common/ioc_canary_exec.yml.
set -u
DIR=/tmp/rustinel-canary-exec
BIN="$DIR/canary-true"
mkdir -p "$DIR" 2>/dev/null || true
# Copied, never modified: an edited Mach-O loses its signature and AMFI kills it.
cp /usr/bin/true "$BIN" 2>/dev/null || cp /bin/echo "$BIN" 2>/dev/null || true
chmod 0755 "$BIN" 2>/dev/null || true
"$BIN" >/dev/null 2>&1 || true
sleep 3
rm -rf "$DIR" 2>/dev/null || true
exit 0
