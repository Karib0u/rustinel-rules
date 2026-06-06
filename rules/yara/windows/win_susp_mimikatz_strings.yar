rule win_susp_mimikatz_strings
{
    meta:
        id = "yara-win-mimikatz-strings"
        description = "Detects characteristic Mimikatz credential-dumping strings in Windows binaries."
        author = "rustinel-rules"
        date = "2026-06-03"
        reference = "https://attack.mitre.org/software/S0002/"
        attack = "T1003.001"
        level = "high"
        os = "windows"
        telemetry = "file_scan"
        expected_false_positive_level = "low"
        test_status = "manual"
        test_reason = "Needs a generated Windows PE fixture executed under file_scan; process and registry atomics are covered first."

    strings:
        $s1 = "sekurlsa::logonpasswords" ascii wide nocase
        $s2 = "sekurlsa::minidump" ascii wide nocase
        $s3 = "gentilkiwi" ascii wide nocase
        $s4 = "mimikatz" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and 2 of ($s*)
}
