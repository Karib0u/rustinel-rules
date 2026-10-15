#!/usr/bin/env bash
# Atomic test - Sigma correlation (event_count) fixture
#   "Fixture - Correlation Event Count" over "Fixture - Correlation Base Marker"
#
# Starts the same marker process twice. The base rule matches each start by its
# command line; the correlation fires once it has seen two within its window.
# Each shell lives a second so its command line is enriched before it exits.
set -u
for _ in 1 2; do
  sh -c 'sleep 1' rustinel-corr-fixture-7f3a >/dev/null 2>&1
done
exit 0
