rule lnx_msfvenom_meterpreter_stager
{
    meta:
        id = "yara-lnx-msfvenom-stager"
        description = "Detects Metasploit / Mettle (Linux Meterpreter) stage markers in ELF images: a payload-identity string together with a Meterpreter channel or stdapi command string. Static match only; it shows a Meterpreter-style payload is on disk, not that it was run."
        author = "rustinel-rules"
        date = "2026-07-09"
        reference = "https://docs.metasploit.com/docs/using-metasploit/advanced/meterpreter/meterpreter.html"
        attack = "T1105"
        level = "high"
        severity = "high"
        os = "linux"
        telemetry = "file_scan"
        expected_false_positive_level = "low"
        test_status = "atomic"

    strings:
        $id1 = "mettle" ascii nocase
        $id2 = "libmettle" ascii nocase
        $id3 = "meterpreter" ascii nocase
        $cmd1 = "core_channel_open" ascii nocase
        $cmd2 = "stdapi_" ascii nocase
    condition:
        uint32(0) == 0x464c457f and filesize < 50MB and
        // Metasploit has no ATT&CK software entry, so there is no software id.
        // One payload-identity marker plus one command/loader marker.
        any of ($id*) and any of ($cmd*)
}
