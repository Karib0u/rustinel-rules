rule win_msfvenom_meterpreter_stager
{
    meta:
        id = "yara-win-msfvenom-stager"
        description = "Detects Metasploit / Meterpreter Windows stager and stage markers (metsrv, ReflectiveLoader, channel/stdapi command strings) in PE images."
        author = "rustinel-rules"
        date = "2026-07-09"
        reference = "https://attack.mitre.org/software/S0002/"
        attack = "T1105"
        level = "high"
        os = "windows"
        telemetry = "file_scan"
        expected_false_positive_level = "low"
        test_status = "atomic"

    strings:
        $m1 = "metsrv" ascii wide nocase
        $m2 = "ReflectiveLoader" ascii wide
        $m3 = "meterpreter" ascii wide nocase
        $m4 = "core_channel_open" ascii wide nocase
        $m5 = "stdapi_" ascii wide nocase
        $m6 = "metsrv.dll" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and 2 of ($m*)
}
