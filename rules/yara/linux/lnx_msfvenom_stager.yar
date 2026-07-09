rule lnx_msfvenom_meterpreter_stager
{
    meta:
        id = "yara-lnx-msfvenom-stager"
        description = "Detects Metasploit / Mettle (Linux Meterpreter) stage markers in ELF images. Metasploit is the highest-volume commodity payload generator."
        author = "rustinel-rules"
        date = "2026-07-09"
        reference = "https://attack.mitre.org/software/S0002/"
        attack = "T1105"
        level = "high"
        os = "linux"
        telemetry = "file_scan"
        expected_false_positive_level = "low"
        test_status = "atomic"

    strings:
        $m1 = "mettle" ascii nocase
        $m2 = "meterpreter" ascii nocase
        $m3 = "core_channel_open" ascii nocase
        $m4 = "stdapi_" ascii nocase
        $m5 = "libmettle" ascii nocase
        $m6 = "metsrv" ascii nocase

    condition:
        uint32(0) == 0x464c457f and 2 of ($m*)
}
