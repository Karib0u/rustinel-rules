rule win_susp_sliver_implant
{
    meta:
        id = "yara-win-sliver-implant"
        description = "Detects Sliver C2 implant artifacts (sliverpb protobuf package, RPC and transport markers) in Windows PE images. Sliver has replaced Cobalt Strike in much commodity and ransomware tradecraft."
        author = "rustinel-rules"
        date = "2026-07-09"
        reference = "https://attack.mitre.org/software/S1049/"
        attack = "T1219"
        level = "high"
        os = "windows"
        telemetry = "file_scan"
        expected_false_positive_level = "low"
        test_status = "manual"
        test_reason = "Advanced-tier YARA fixture is exercised manually; a Go implant with garbled strings will not match, matching this rule's documented scope."

    strings:
        $s1 = "sliverpb" ascii nocase
        $s2 = ".(*Sliver" ascii
        $s3 = "bishopfox/sliver" ascii nocase
        $s4 = "SliverRPC" ascii nocase
        $s5 = "sliver/protobuf" ascii nocase
        $s6 = "GetReconfigureReq" ascii

    condition:
        uint16(0) == 0x5A4D and 2 of ($s*)
}
