#!/usr/bin/env bash
# With no child command, env only prints its environment. No library is loaded.
set -eu
exec /usr/bin/env DYLD_INSERT_LIBRARIES=/private/tmp/rustinel-atomic-missing.dylib >/dev/null
