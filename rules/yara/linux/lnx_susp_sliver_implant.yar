rule lnx_susp_sliver_implant
{
    meta:
        id = "yara-lnx-sliver-implant"
        description = "Detects Sliver C2 implant artifacts (sliverpb protobuf package, RPC and transport markers) in Linux ELF images. Requires a package marker plus an RPC/message marker. Static match only: packed or garble-obfuscated Go implants will not match."
        author = "rustinel-rules"
        date = "2026-07-09"
        reference = "https://attack.mitre.org/software/S0633/"
        software = "S0633"
        attack = "T1219"
        level = "high"
        os = "linux"
        telemetry = "file_scan"
        expected_false_positive_level = "low"
        test_status = "manual"
        test_reason = "Advanced-tier YARA fixture is exercised manually; a Go implant with garbled strings will not match, matching this rule's documented scope."

    strings:
        // Go package / module paths compiled into the implant.
        $pkg1 = "sliverpb" ascii nocase
        $pkg2 = "bishopfox/sliver" ascii nocase
        $pkg3 = "sliver/protobuf" ascii nocase
        // Implant RPC and message types.
        $rpc1 = "SliverRPC" ascii nocase
        $rpc2 = ".(*Sliver" ascii
        $rpc3 = "GetReconfigureReq" ascii

    condition:
        uint32(0) == 0x464c457f and filesize < 100MB and
        // A package marker alone also matches Sliver client or server tooling and
        // research binaries; require an independent RPC/message marker as well.
        any of ($pkg*) and any of ($rpc*)
}
