"""Replay DNS query shapes, API lookups, and distinct-name bursts on three platforms."""

import argparse
from datetime import UTC, datetime, timedelta
from pathlib import Path

from advanced_negatives import build_events, lib, replay

PLATFORMS = {
    "win": r"C:\Windows\System32\curl.exe",
    "lnx": "/usr/bin/curl",
    "macos": "/usr/bin/curl",
}
API_DOMAINS = (
    "api.telegram.org",
    "discord.com",
    "discordapp.com",
    "cdn.discordapp.com",
    "pastebin.com",
    "transfer.sh",
    "gofile.io",
    "file.io",
    "pixeldrain.com",
)
LONG_LABEL = "a" * 50
SHAPE_CASES = [
    ("49-byte label", LONG_LABEL[:-1] + ".example.com", False),
    ("50-byte label", LONG_LABEL + ".example.com", True),
    ("149-byte name plus root dot", ".".join(["a" * 47, "b" * 48, "c" * 48, "com."]), False),
    ("150-byte name", ".".join(["a" * 48, "b" * 48, "c" * 48, "com"]), True),
    ("seven labels plus root dot", "a.b.c.d.e.example.com.", False),
    ("eight labels", "a.b.c.d.e.f.example.com", True),
    ("IPv4 reverse lookup", "a.b.c.d.e.f.4.3.2.1.IN-ADDR.ARPA.", False),
    ("IPv6 reverse lookup", "a." * 32 + "ip6.arpa", False),
    ("DMARC", "_DMARC." + LONG_LABEL + ".example.com", False),
    ("DKIM", LONG_LABEL + "._domainkey.example.com.", False),
    ("SPF", "_spf." + LONG_LABEL + ".example.com", False),
    ("local name", LONG_LABEL + ".office.local.", False),
    ("internal name", LONG_LABEL + ".corp.internal", False),
    ("CDN", LONG_LABEL + ".CLOUDFRONT.NET.", False),
    ("cloud service discovery", LONG_LABEL + ".vpce.amazonaws.com", False),
    ("lookalike CDN suffix", LONG_LABEL + ".notcloudfront.net", True),
    ("CDN name under another suffix", LONG_LABEL + ".cloudfront.net.example.com", True),
]


def sample(name, image=None, **extra):
    fields = {"QueryName": name, **extra}
    if image is not None:
        fields["Image"] = image
    return {"fields": fields}


def check_queries(engine, rule, cases, correlation=None):
    events = build_events(rule, [event for _, event, _ in cases])
    title = rule.meta["title"]
    fired = {
        int(alert["process.pid"])
        for alert in replay(engine, correlation or rule, events)
        if alert["rule.name"] == title
    }
    for index, (name, _, expected) in enumerate(cases, 1):
        if (index in fired) != expected:
            raise RuntimeError(f"{title}, {name}: expected alert={expected}")
    print(f"Passed {len(cases)} cases for {title}.")


def check_bursts(engine, rule, image):
    start = datetime(2026, 11, 27, 8, tzinfo=UTC)
    burst = [sample(f"{i:02d}{'a' * 48}.example.co.uk", image) for i in range(20)]
    other_zone = [sample(f"{i:02d}{'a' * 48}.other.co.uk", image) for i in range(10, 20)]
    other_image = [
        sample(f"{i:02d}{'a' * 48}.example.co.uk", image + ".other") for i in range(10, 20)
    ]
    cases = [
        ("same registrant and executable", burst, 59, 1),
        ("one below threshold", burst[:-1], 59, 0),
        ("repeat the same name", burst[:1] * 20, 59, 0),
        ("two registrants under co.uk", burst[:10] + other_zone, 59, 0),
        ("two executable images", burst[:10] + other_image, 59, 0),
        ("no executable image", [sample(f"{i:050d}.example.co.uk") for i in range(20)], 59, 0),
        (
            "unlisted public suffix",
            [sample(f"{i:050d}.test.invalid", image) for i in range(20)],
            59,
            0,
        ),
        (
            "short, ordinary names",
            [sample(f"host{i}.example.co.uk", image) for i in range(20)],
            59,
            0,
        ),
        ("last name outside window", burst, 61, 0),
    ]
    title = rule.meta["title"]
    for name, samples, last_second, expected in cases:
        events = build_events(rule, samples)
        for index, event in enumerate(events[:-1]):
            event["event_time"] = (start + timedelta(seconds=index / 10)).isoformat()
        events[-1]["event_time"] = (start + timedelta(seconds=last_second)).isoformat()
        fired = sum(alert["rule.name"] == title for alert in replay(engine, rule, events))
        if fired != expected:
            raise RuntimeError(f"{title}, {name}: expected {expected} alerts, got {fired}")
    print(f"Passed {len(cases)} cases for {title}.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", required=True, type=Path)
    engine = parser.parse_args().engine.resolve()
    artifacts = {artifact.path.stem: artifact for artifact in lib.load_all_artifacts()}
    for platform, image in PLATFORMS.items():
        prefix = f"dns_query_{platform}"
        correlation = artifacts[f"{prefix}_tunnel_distinct_names"]
        shape = [(case, sample(host, image), expected) for case, host, expected in SHAPE_CASES]
        if platform == "lnx":
            shape.append(
                (
                    "truncated name",
                    sample(LONG_LABEL + ".example.com", image, QueryTruncated="true"),
                    False,
                )
            )
        # Load the correlation with its base to verify the standalone shape alerts still fire.
        check_queries(engine, artifacts[f"{prefix}_tunnel_name_shape"], shape, correlation)

        api = [(host, sample(host, image), True) for host in API_DOMAINS]
        api.extend(
            [
                ("uppercase rooted name", sample("API.TELEGRAM.ORG.", image), True),
                ("longer suffix", sample("api.telegram.org.example.com", image), False),
                ("lookalike domain", sample("examplediscord.com", image), False),
                ("no process attribution", sample("gofile.io"), False),
                ("empty image", sample("gofile.io", ""), False),
                ("whitespace image", sample("gofile.io", " "), False),
                ("ordinary domain", sample("example.com", image), False),
            ]
        )
        check_queries(engine, artifacts[f"{prefix}_non_browser_api"], api)
        check_bursts(engine, correlation, image)


if __name__ == "__main__":
    main()
