"""True-positive and near-miss checks for the YARA rules.

Each case builds a synthetic file (format magic + padding + marker strings), so
the corpus is reproducible with no binary fixtures. Near-misses are single
markers that must not fire on their own.
"""

from pathlib import Path

import pytest
import yara_x

ROOT = Path(__file__).resolve().parents[2] / "rules" / "yara"
MZ, ELF, MACHO = b"MZ\0\0", b"\x7fELF", b"\xcf\xfa\xed\xfe"

CASES = {
    "win_susp_xmrig_coinminer": (
        MZ,
        [b"xmrig\nstratum+tcp://\ndonate-level\nrandomx\nmonero"],
        [b"xmrig", b"monero randomx", b"stratum+tcp://"],
    ),
    "lnx_susp_xmrig_coinminer": (ELF, [b"xmrig\nstratum+tcp://"], [b"xmrig", b"monero"]),
    "macos_susp_coinminer_strings": (
        MACHO,
        [b"xmrig\nstratum+tcp://\n--donate-level\nrandomx\ncryptonight"],
        [b"cryptonight"],
    ),
    "win_msfvenom_stager": (
        MZ,
        [b"metsrv.dll\nReflectiveLoader\nmeterpreter\ncore_channel_open"],
        [b"ReflectiveLoader", b"meterpreter"],
    ),
    "lnx_msfvenom_stager": (
        ELF,
        [b"mettle\nmeterpreter\ncore_channel_open\nstdapi_sys\nlibmettle"],
        [b"meterpreter", b"stdapi_"],
    ),
    "win_susp_mimikatz_strings": (
        MZ,
        [b"sekurlsa::logonpasswords\nsekurlsa::minidump\ngentilkiwi\nmimikatz"],
        [b"mimikatz gentilkiwi", b"privilege::debug"],
    ),
    "win_susp_cobaltstrike_beacon": (
        MZ,
        [b"beacon.dll\n%s as %s\\%s: %d"],
        [b"beacon.dll", b"could not spawn %s"],
    ),
    "win_susp_sliver_implant": (MZ, [b"sliverpb\nSliverRPC"], [b"sliverpb", b"GetReconfigureReq"]),
    "lnx_susp_sliver_implant": (ELF, [b"bishopfox/sliver\n.(*Sliver"], [b"sliverpb"]),
}


def _scanner(stem):
    path = next(ROOT.glob(f"*/{stem}.yar"))
    return yara_x.Scanner(yara_x.compile(path.read_text()))


def _blob(magic, body):
    return magic + b"\0" * 8 + body + b"\0"


def test_every_rule_has_a_case():
    assert {p.stem for p in ROOT.glob("*/*.yar")} == set(CASES)


@pytest.mark.parametrize("stem", sorted(CASES))
def test_true_positives_match(stem):
    magic, positives, _ = CASES[stem]
    for body in positives:
        assert _scanner(stem).scan(_blob(magic, body)).matching_rules, body


@pytest.mark.parametrize("stem", sorted(CASES))
def test_near_misses_do_not_match(stem):
    magic, _, negatives = CASES[stem]
    for body in negatives:
        assert not _scanner(stem).scan(_blob(magic, body)).matching_rules, body


@pytest.mark.parametrize("stem", sorted(CASES))
def test_wrong_format_does_not_match(stem):
    magic, positives, _ = CASES[stem]
    other = b"\0\0\0\0" if magic != b"\0\0\0\0" else MZ
    assert not _scanner(stem).scan(_blob(other, positives[0])).matching_rules
