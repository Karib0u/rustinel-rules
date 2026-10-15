#!/usr/bin/env bash
# Atomic test - rule yara-fixture-memory-marker  (yara process_memory)
#
# A long-lived Python process builds the marker from fragments at runtime and
# holds it, so the bytes exist only in its heap: not in the interpreter image, the
# script, or the command line. Only a process-memory scan can see them. The
# harness enables scanner.yara_memory_enabled for the whole run; the engine waits
# yara_memory_delay_ms after process start before reading, so stay alive past it.
set -u
PY=$(command -v python3 || command -v python) || exit 0
"$PY" - <<'PYEOF' >/dev/null 2>&1
import time
parts = ["RUSTINEL", "MEMORY", "FIXTURE", "b83e41c7"]
marker = "-".join(parts)
# Keep distinct heap copies alive; an interned constant could live elsewhere.
held = [marker.encode(), bytearray(marker.encode()), marker]
time.sleep(8)
print(len(held))
PYEOF
exit 0
