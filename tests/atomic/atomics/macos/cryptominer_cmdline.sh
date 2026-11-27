#!/usr/bin/env bash
# Pass mining arguments to true, which ignores them and makes no connection.
set -eu
exec /usr/bin/true stratum+tcp://pool.invalid:3333 --donate-level 1 --coin=monero
