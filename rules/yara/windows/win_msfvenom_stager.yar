rule win_msfvenom_meterpreter_stager
{
    meta:
        id = "yara-win-msfvenom-stager"
        description = "Detects Metasploit / Meterpreter Windows stage markers in PE images: a payload-identity string (metsrv, meterpreter) together with a channel, stdapi or reflective-loader marker. Static match only; it shows a Meterpreter-style payload is on disk, not that it was run."
        author = "rustinel-rules"
        date = "2026-07-09"
        reference = "https://docs.metasploit.com/docs/using-metasploit/advanced/meterpreter/meterpreter.html"
        attack = "T1105"
        level = "high"
        os = "windows"
        telemetry = "file_scan"
        expected_false_positive_level = "low"
        test_status = "atomic"

    strings:
        $id1 = "metsrv" ascii wide nocase
        $id2 = "meterpreter" ascii wide nocase
        $cmd1 = "core_channel_open" ascii wide nocase
        $cmd2 = "stdapi_" ascii wide nocase
        // ReflectiveLoader alone is shared by many tools; it only supports an identity match.
        $cmd3 = "ReflectiveLoader" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 50MB and
        // Metasploit has no ATT&CK software entry, so there is no software id.
        // One payload-identity marker plus one command/loader marker.
        any of ($id*) and any of ($cmd*)
}
