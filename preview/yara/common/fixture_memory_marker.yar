rule fixture_memory_marker
{
    meta:
        id = "yara-fixture-memory-marker"
        description = "Test-only: a marker string that a long-lived atomic process assembles at runtime, so it exists only in process memory and never in any file. Proves the YARA process-memory scan path. Never a detection."
        author = "rustinel-rules"
        date = "2026-10-08"
        reference = "https://github.com/Karib0u/rustinel-rules/issues/61"
        level = "low"
        severity = "low"
        os = "common"
        telemetry = "process_memory"
        expected_false_positive_level = "low"
        test_status = "atomic"

    strings:
        // ascii for Python/bash heaps, wide for .NET (PowerShell) strings.
        $marker = "RUSTINEL-MEMORY-FIXTURE-b83e41c7" ascii wide

    condition:
        $marker
}
