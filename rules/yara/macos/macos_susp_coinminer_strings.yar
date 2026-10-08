rule macos_susp_coinminer_strings
{
    meta:
        id = "yara-macos-coinminer-strings"
        description = "Detects the presence of an XMRig-style cryptominer (Mach-O binaries) from at least two independent marker classes (identity, pool protocol, algorithm, public pool). A match shows miner software is on disk; it does not prove unauthorized or malicious use, so triage against approved mining before escalating."
        author = "rustinel-rules"
        date = "2026-06-04"
        reference = "https://attack.mitre.org/software/S0658/"
        software = "S0658"
        attack = "T1496"
        level = "medium"
        os = "macos"
        telemetry = "file_scan"
        expected_false_positive_level = "medium"
        test_status = "atomic"

    strings:
        // Software identity: the miner names itself.
        $id1 = "xmrig" ascii wide nocase
        $id2 = "donate-level" ascii nocase
        // Pool protocol.
        $proto1 = "stratum+tcp://" ascii nocase
        $proto2 = "stratum+ssl://" ascii nocase
        // Mining algorithm or coin.
        $algo1 = "randomx" ascii nocase
        $algo2 = "cryptonight" ascii nocase
        $algo3 = "monero" ascii nocase
        // Well-known public pools.
        $pool1 = "pool.minexmr" ascii nocase
        $pool2 = "supportxmr" ascii nocase

    condition:
        (uint32(0) == 0xfeedfacf or uint32(0) == 0xfeedface or
         uint32(0) == 0xbebafeca or uint32(0) == 0xcafebabe) and filesize < 100MB and
        // Two independent marker classes; no single string is sufficient.
        (
            (any of ($id*) and any of ($proto*)) or
            (any of ($id*) and any of ($algo*)) or
            (any of ($proto*) and any of ($algo*)) or
            (any of ($pool*) and any of ($proto*))
        )
}
