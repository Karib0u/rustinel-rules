#!/usr/bin/env python3
"""Sync dedicated RMM service domains from pinned LOLRMM records."""

import re
from collections import defaultdict
from collections.abc import Sequence

import lib
from sync_ioc import clean_text, sync

REPOSITORY = "https://github.com/magicsword-io/LOLRMM"
REVISION = "0c2d56639673a232ff9d2548e16c6d045d3a1217"
OUTPUT = lib.RULES_DIR / "ioc/common/ioc_lolrmm_relay_domains.yml"
LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
HOSTNAME = re.compile(rf"(?:{LABEL}\.)+[a-z]{{2,63}}")

# These zones are excluded at every depth in addition to the repository warninglist.
EXCLUDED_ZONES = {
    # Consumer, collaboration, and general-purpose network or tunnel services.
    "adobeconnect.com",
    "basecamp.com",
    "fdcollab.com",
    "freshchat.com",
    "freshcloud.io",
    "freshconnect.io",
    "freshdev.io",
    "freshworks.com",
    "freshworksapi.com",
    "in-freshbots.ai",
    "myfreshworks.com",
    "netbird.io",
    "real-time-collaboration.com",
    "rtschannel.com",
    "tailscale.com",
    "tailscale.io",
    "teleport.dev",
    "teleport.sh",
    "teleportinfra.sh",
    "tmate.io",
    "ts.net",
    "zerotier.com",
    "zoom.com",
    "zoom.us",
    "devtunnels.ms",
    "tunnels.api.visualstudio.com",
    "localxpose.io",
    "ngrok.com",
    "ngrok.app",
    "ngrok.io",
    "ngrok.dev",
    "ngrok.pro",
    "ngrok.pizza",
    "ngrok-free.app",
    "ngrok-free.dev",
    "ngrok-agent.com",
    # Shared cloud, CDN, download, and connectivity infrastructure.
    "akamaized.net",
    "aliyuncs.com",
    "argotunnel.com",
    "cfargotunnel.com",
    "cftunnel.com",
    "trycloudflare.com",
    "cloudflarestorage.com",
    "digitaloceanspaces.com",
    "firebaseapp.com",
    "web.app",
    "ghcr.io",
    "googlevideo.com",
    "pubnubapi.com",
    "software.informer.com",
    "softonic.com",
    "sophosupd.com",
    "sophosupd.net",
    "stunprotocol.org",
    "icanhazip.com",
    # Placeholder, local, and test namespaces.
    "example",
    "home.arpa",
    "invalid",
    "local",
    "localhost",
    "test",
}

# Exclude the apex and any suffix that would cover it. Dedicated subdomains
# can still qualify. These namespaces mix service traffic with marketing,
# documentation, unrelated products, or general-purpose downloads.
EXCLUDED_APEXES = {
    "acronis.com",
    "action1.com",
    "aeroadmin.com",
    "anydesk.com",
    "aomeisoftware.com",
    "atera.com",
    "auvik.com",
    "baramundi.com",
    "barracudamsp.com",
    "breeze.app",
    "breezermm.com",
    "centuriontech.com",
    "cloudberrylab.com",
    "comodo.com",
    "connectwise.com",
    "dameware.com",
    "dataplicity.com",
    "deepfreeze.com",
    "deskday.ai",
    "domotz.com",
    "electric.ai",
    "emcosoftware.com",
    "encapto.com",
    "ericom.com",
    "faronics.com",
    "fortra.com",
    "freshasset.com",
    "freshservice.com",
    "glpi-network.com",
    "glpi-project.org",
    "goto.com",
    "goverlan.com",
    "helpwire.app",
    "hoptodesk.com",
    "idrive.com",
    "imperosoftware.com",
    "invgate.com",
    "iperius.com",
    "ivanti.com",
    "kaseya.com",
    "kickidler.com",
    "level.io",
    "logmeininc.com",
    "lunixar.com",
    "manageengine.com",
    "miradore.com",
    "monitic.com",
    "mremoteng.org",
    "msp360.com",
    "n-able.com",
    "naverisk.com",
    "netop.com",
    "netreo.com",
    "nezha.wiki",
    "ninite.com",
    "ninjaone.com",
    "ninjarmm.com",
    "nomachine.com",
    "nvaccess.org",
    "ocsinventory-ng.org",
    "panorama9.com",
    "parallels.com",
    "parsec.gg",
    "pdq.com",
    "pitunnel.com",
    "pulseway.com",
    "qq.com",
    "rapid7.com",
    "radmin.com",
    "remotepass.com",
    "remotepc.com",
    "remotepulse.io",
    "remoteutilities.com",
    "remote.it",
    "repairshopr.com",
    "rodex.cc",
    "royalapps.com",
    "rport.io",
    "runsmart.io",
    "rustdesk.com",
    "screenconnect.com",
    "shellhub.io",
    "simple-help.com",
    "sophos.com",
    "splashtop.com",
    "superops.ai",
    "syncromsp.com",
    "tacticalrmm.com",
    "teamviewer.com",
    "teramind.co",
    "tiflux.com",
    "tiflux.com.br",
    "tightvnc.com",
    "ultravnc.com",
    "vector-networks.com",
    "weezo.net",
    "zabbix.com",
    "zoho.com",
    "zoho.com.au",
    "zoho.com.cn",
    "zoho.eu",
    "zoho.in",
}

# Miscellaneous catalog context and ancillary download, support, or dev hosts.
EXCLUDED_HOSTS = {
    "account.flexihub.com",
    "cdn.getgo.com",
    "changes.panorama9.com",
    "checkip.zmazonaws.com",
    "cloud.screenconnect.com",
    "devapi.monitic.com",
    "devrmm.lunixar.com",
    "docs.invgate.net",
    "download.remsupp.com",
    "downloads.zohocdn.com",
    "downloads.zohodl.com.cn",
    "faronicscloud.com",
    "forum.glpi-project.org",
    "guacamole.apache.org",
    "isodownload.baramundi.com",
    "mail.metaquest.com",
    "metaquest.com",
    "my.splashtop.com",
    "nightly.glpi-project.org",
    "one.comodo.com",
    "sentry.dev.teramind.co",
    "servably.com",
    "staging.helpwire.app",
    "trust.invgate.com",
    "upd.faronicslabs.com",
    "wangwang.taobao.com",
    # Campaign and sample context without a confirmed remote-service role.
    "blackcryptknight.com",
    "c.mid.al",
    "gd.bj2.xyz",
    "my-sharepoint-inc.com",
    "my1cloudlive.com",
    "my2cloudlive.com",
    "mymeetinggoogle.com",
    "pandoramods.top",
    "web-16fe.app",
}
EXCLUDED_LABELS = {
    "blog",
    "demo",
    "docs",
    "download",
    "downloads",
    "help",
    "resources",
    "support",
    "www",
}

# Keep the documented service hosts from the original rule where upstream lists
# a broader zone, an unsupported pattern, or omits the hostname. The rule's
# references point to the vendor documentation and ScreenConnect research.
CURATED_HOSTS = {
    ("action1.yaml", "Action1"): (
        "remote.eu.action1.com",
        "remote.eu-2.action1.com",
        "us.remote.app.action1.com",
        "us.remote.na-2.action1.com",
    ),
    ("screenconnect.yaml", "ScreenConnect"): (
        "instance-g01s1n-relay.screenconnect.com",
        "instance-itsd8c-relay.screenconnect.com",
    ),
    ("syncro.yaml", "Syncro"): (
        "realtime.kabutoservices.com",
        "rmm.syncromsp.com",
        "syncro-live.syncromsp.com",
        "traversal.syncromsp.com",
    ),
    ("tactical_rmm.yaml", "Tactical RMM"): ("icanhazip.tacticalrmm.io",),
}


def normalize_domain(value: str) -> str | None:
    value = value.strip().lower().removesuffix(".")
    host = value[2:] if value.startswith("*.") else value.removeprefix(".")
    if len(host) > 253 or not HOSTNAME.fullmatch(host):
        return None
    return f"*.{host}" if host != value else host


def within(host: str, zone: str) -> bool:
    return host == zone or host.endswith(f".{zone}")


def collect(records: list[tuple[str, dict]], warninglists: dict) -> list[dict[str, str]]:
    blocked_zones = EXCLUDED_ZONES | {
        value.strip().lower().removeprefix("*").strip(".")
        for value in warninglists["domain_suffixes"]
    }
    blocked_hosts = EXCLUDED_HOSTS | EXCLUDED_APEXES
    candidates: dict[str, set[str]] = defaultdict(set)
    for source, record in records:
        name = clean_text(record.get("Name") or source)
        for network in (record.get("Artifacts") or {}).get("Network") or []:
            for value in network.get("Domains") or []:
                domain = normalize_domain(value) if isinstance(value, str) else None
                if not domain:
                    continue
                if network.get("Detection") is False:
                    if domain.startswith("*."):
                        blocked_zones.add(domain.removeprefix("*."))
                    else:
                        blocked_hosts.add(domain)
                    continue
                host = domain.removeprefix("*.")
                if host.split(".", 1)[0] in EXCLUDED_LABELS:
                    blocked_zones.add(host)
                candidates[domain].add(f"{source} ({name})")

        for host in CURATED_HOSTS.get((source, name), ()):
            candidates[host].add(f"{source} ({name}, documented service)")

    accepted: dict[str, set[str]] = {}
    for value, sources in candidates.items():
        host = value.removeprefix("*.")
        suffix = value.startswith("*.")
        if host in blocked_hosts or any(
            within(host, zone) or (suffix and within(zone, host)) for zone in blocked_zones
        ):
            continue
        if suffix and any(within(excluded, host) for excluded in blocked_hosts):
            continue
        accepted[value] = sources

    # The engine emits one hit per matching entry. Fold covered indicators and
    # their attribution into the least specific accepted suffix.
    suffixes = sorted(
        (value for value in accepted if value.startswith("*.")),
        key=lambda value: (value.count("."), value),
    )
    for suffix in suffixes:
        if suffix not in accepted:
            continue
        host = suffix.removeprefix("*.")
        for value in list(accepted):
            if value != suffix and within(value.removeprefix("*."), host):
                accepted[suffix].update(accepted.pop(value))

    return [
        {
            "value": value,
            "comment": f"LOLRMM {REVISION[:12]} | {', '.join(sorted(sources))}",
        }
        for value, sources in sorted(accepted.items())
    ]


def main(argv: Sequence[str] | None = None) -> int:
    return sync(__doc__, REPOSITORY, REVISION, OUTPUT, "domains", collect, argv)


if __name__ == "__main__":
    raise SystemExit(main())
