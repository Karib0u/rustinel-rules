rule lnx_susp_xmrig_coinminer
{
    meta:
        id = "yara-lnx-xmrig-coinminer"
        description = "Detects characteristic XMRig and Monero coinminer strings in Linux ELF binaries."
        author = "rustinel-rules"
        date = "2026-06-04"
        reference = "https://attack.mitre.org/software/S0597/"
        attack = "T1496"
        level = "high"
        os = "linux"
        telemetry = "file_scan"
        expected_false_positive_level = "low"
        test_status = "atomic"

    strings:
        $xmrig = "xmrig" ascii wide nocase
        $miner1 = "stratum+tcp://" ascii nocase
        $miner2 = "stratum+ssl://" ascii nocase
        $miner3 = "donate-level" ascii nocase
        $miner4 = "randomx" ascii nocase
        $miner5 = "cryptonight" ascii nocase
        $miner6 = "monero" ascii nocase
        $pool1 = "pool.minexmr" ascii nocase
        $pool2 = "supportxmr" ascii nocase

    condition:
        uint32(0) == 0x464c457f and
        (
            $xmrig or
            4 of ($miner*) or
            (2 of ($miner*) and 1 of ($pool*))
        )
}
