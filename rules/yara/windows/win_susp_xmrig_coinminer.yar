rule win_susp_xmrig_coinminer
{
    meta:
        id = "yara-win-xmrig-coinminer"
        description = "Detects characteristic XMRig and Monero coinminer strings in Windows PE binaries. Windows parity for the existing Linux and macOS coinminer rules."
        author = "rustinel-rules"
        date = "2026-07-09"
        reference = "https://attack.mitre.org/software/S0597/"
        attack = "T1496"
        level = "high"
        os = "windows"
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
        uint16(0) == 0x5A4D and
        (
            $xmrig or
            4 of ($miner*) or
            (2 of ($miner*) and 1 of ($pool*))
        )
}
