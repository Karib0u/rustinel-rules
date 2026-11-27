#!/usr/bin/env bash
# Import Foundation and return a constant without sending Apple events.
set -eu
exec /usr/bin/osascript -l JavaScript -e 'ObjC.import("Foundation"); 1' >/dev/null
