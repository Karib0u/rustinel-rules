#!/usr/bin/env bash
# Atomic test for Linux Firewall Rules Flushed or Firewall Disabled.
# The copied shell receives the nftables command as positional parameters.
set -eu
DIR=/opt/rustinel_atomic_firewall_disabled.d
BIN="$DIR/nft"
mkdir "$DIR"
trap 'rm -f "$BIN"; rmdir "$DIR"' EXIT
cp /bin/sh "$BIN"
timeout 3 "$BIN" -c 'sleep 1; :' flush ruleset
