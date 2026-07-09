rule win_susp_cobaltstrike_beacon
{
    meta:
        id = "yara-win-cobaltstrike-beacon"
        description = "Detects Cobalt Strike beacon stager and configuration artifacts in Windows PE images (beacon command markers, default named-pipe and spawnto strings). Caveat: on-disk beacons are usually packed, so a disk scan alone misses many samples; enable scanner.yara_memory_* memory scanning for full coverage."
        author = "rustinel-rules"
        date = "2026-07-09"
        reference = "https://attack.mitre.org/software/S0154/"
        attack = "T1219"
        level = "high"
        os = "windows"
        telemetry = "file_scan"
        expected_false_positive_level = "low"
        test_status = "manual"
        test_reason = "On-disk beacons are typically packed; this rule is the primary beneficiary of optional memory scanning and is validated manually rather than in the disk-scan atomic harness."

    strings:
        $b1 = "beacon.dll" ascii wide nocase
        $b2 = "beacon.x64.dll" ascii wide nocase
        $b3 = "%s as %s\\%s: %d" ascii
        $b4 = "ReflectiveLoader" ascii
        $b5 = "%s.4%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%s" ascii
        $spawn1 = "\\\\%s\\pipe\\msagent_" ascii wide
        $spawn2 = "\\\\.\\pipe\\MSSE-" ascii wide
        $spawn3 = "could not spawn %s" ascii

    condition:
        uint16(0) == 0x5A4D and
        (
            2 of ($b*) or
            1 of ($spawn*)
        )
}
