#!/usr/bin/env bash
# Keeps the Apple signature on a private copy of true named TeamViewer.
set -eu
dir=$(mktemp -d /tmp/rustinel-atomic-rmm.XXXXXX)
bin="$dir/TeamViewer"
trap 'rm -f "$bin"; rmdir "$dir"' EXIT
cp /usr/bin/true "$bin"
"$bin"
