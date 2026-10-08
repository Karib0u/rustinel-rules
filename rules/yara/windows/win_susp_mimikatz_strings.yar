rule win_susp_mimikatz_strings
{
    meta:
        id = "yara-win-mimikatz-strings"
        description = "Detects Mimikatz in Windows binaries via module::command strings, or a command string plus project identity. Static match only; it does not prove credentials were dumped."
        author = "rustinel-rules"
        date = "2026-06-03"
        reference = "https://attack.mitre.org/software/S0002/"
        software = "S0002"
        attack = "T1003.001"
        level = "high"
        severity = "high"
        os = "windows"
        telemetry = "file_scan"
        expected_false_positive_level = "low"
        test_status = "atomic"

    strings:
        // Module::command strings that only Mimikatz-derived code carries.
        $cmd1 = "sekurlsa::logonpasswords" ascii wide nocase
        $cmd2 = "sekurlsa::minidump" ascii wide nocase
        $cmd3 = "lsadump::sam" ascii wide nocase
        $cmd4 = "privilege::debug" ascii wide nocase
        $cmd5 = "kerberos::ptt" ascii wide nocase
        // Author / project identity.
        $id1 = "gentilkiwi" ascii wide nocase
        $id2 = "mimikatz" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and filesize < 50MB and
        (
            2 of ($cmd*) or
            (any of ($cmd*) and any of ($id*))
        )
}
