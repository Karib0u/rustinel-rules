#!/usr/bin/env bash
# Runs a private copy of sleep named rustdesk. The harness runs as root.
set -eu
dir=$(mktemp -d /home/rustinel-atomic-rmm.XXXXXX)
bin="$dir/rustdesk"
trap 'rm -f "$bin"; rmdir "$dir"' EXIT
cp /bin/sleep "$bin"
"$bin" 1
