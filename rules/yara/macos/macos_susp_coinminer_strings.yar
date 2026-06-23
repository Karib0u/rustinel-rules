rule macos_susp_coinminer_strings
{
    meta:
        id = "yara-macos-coinminer-strings"
        description = "Detects characteristic cryptominer (XMRig / stratum) strings in Mach-O binaries."
        author = "rustinel-rules"
        date = "2026-06-04"
        reference = "https://attack.mitre.org/techniques/T1496/"
        attack = "T1496"
        level = "high"
        os = "macos"
        telemetry = "file_scan"
        expected_false_positive_level = "low"
        test_status = "atomic"

    strings:
        $s1 = "stratum+tcp://" ascii nocase
        $s2 = "stratum+ssl://" ascii nocase
        $s3 = "xmrig" ascii wide nocase
        $s4 = "--donate-level" ascii nocase
        $s5 = "randomx" ascii nocase
        $s6 = "cryptonight" ascii nocase

    condition:
        (uint32(0) == 0xfeedfacf or uint32(0) == 0xfeedface or
         uint32(0) == 0xbebafeca or uint32(0) == 0xcafebabe)
        and 2 of ($s*)
}
