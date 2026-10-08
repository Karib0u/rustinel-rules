#!/usr/bin/env bash
# Negative for rule 3e506273-8f91-42a4-8eb4-5f6071823405
#   "Shell Download-and-Execute Pipe Cradle"
#
# Downloads and pipes into `shasum` to verify a checksum. `| sh` is a prefix of
# `| shasum`, but nothing is executed. curl hits a closed local port.
set -u
bash -c 'curl -s --max-time 3 http://127.0.0.1:9/rustinel_atomic_neg | shasum -a 256' >/dev/null 2>&1 || true
exit 0
