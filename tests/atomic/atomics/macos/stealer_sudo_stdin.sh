#!/usr/bin/env bash
# Exercise the stdin option with version output and empty stdin.
set -eu
exec /usr/bin/sudo -S --version </dev/null >/dev/null
