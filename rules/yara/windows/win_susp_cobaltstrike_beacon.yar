rule win_susp_cobaltstrike_beacon
{
    meta:
        id = "yara-win-cobaltstrike-beacon"
        description = "Detects Cobalt Strike beacon stager and configuration artifacts in Windows PE images (beacon command markers, default named-pipe and spawnto strings). Caveat: on-disk beacons are usually packed, so a disk scan alone misses many samples; enable scanner.yara_memory_* memory scanning for full coverage."
        author = "rustinel-rules"
        date = "2026-07-09"
        reference = "https://attack.mitre.org/software/S0154/"
        software = "S0154"
        attack = "T1219"
        level = "high"
        os = "windows"
        telemetry = "file_scan"
        expected_false_positive_level = "low"
        test_status = "manual"
        test_reason = "On-disk beacons are typically packed; this rule is the primary beneficiary of optional memory scanning and is validated manually rather than in the disk-scan atomic harness."

    strings:
        // Beacon DLL names.
        $name1 = "beacon.dll" ascii wide nocase
        $name2 = "beacon.x64.dll" ascii wide nocase
        // Internal format strings from the beacon implementation.
        $fmt1 = "%s as %s\\%s: %d" ascii
        $fmt2 = "%s.4%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%s" ascii
        // Default spawn-to and named-pipe artifacts.
        $pipe1 = "\\\\%s\\pipe\\msagent_" ascii wide
        $pipe2 = "\\\\.\\pipe\\MSSE-" ascii wide
        $pipe3 = "could not spawn %s" ascii

    condition:
        uint16(0) == 0x5A4D and filesize < 50MB and
        // Two independent marker classes (name, format string, pipe/spawn); a
        // single default string is not sufficient.
        (
            (any of ($name*) and any of ($fmt*)) or
            (any of ($name*) and any of ($pipe*)) or
            (any of ($fmt*) and any of ($pipe*))
        )
}
