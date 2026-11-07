"""Eight detections for the lab's attack stages, mapped to ATT&CK.

Each rule says which Sysmon event it needs, so a config that drops the event can be
blamed for the missed detection. Rules read fields only. They do not know the labels.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime

from sysmontel.parser import SysmonEvent

SHELLS = {"/usr/bin/bash", "/bin/bash", "/usr/bin/dash", "/bin/dash", "/bin/sh", "/usr/bin/sh"}
_TEMP_OUTPUT = re.compile(r"(?:-o|--output|-O|>)\s*(?:/tmp/|/dev/shm/|/var/tmp/)")
_ACCOUNT_TOOLS = {"useradd", "adduser"}
_SHADOW_TOOLS = {"passwd", "chage", "useradd", "usermod", "userdel", "unix_chkpwd", "pwck"}
TIME_FORMAT = "%Y-%m-%d %H:%M:%S.%f"
DECODE_WINDOW_SECONDS = 0.5  # members of one pipeline start within milliseconds


@dataclass(frozen=True)
class Rule:
    name: str
    technique: str
    needs: int  # Sysmon event id the rule reads
    check: Callable[[SysmonEvent], bool]
    what: str


def _basename(path: str) -> str:
    return path.rsplit("/", 1)[-1]


def _download_to_temp(e: SysmonEvent) -> bool:
    return _basename(e.image) in {"curl", "wget"} and bool(_TEMP_OUTPUT.search(e.command))


def _outbound_from_shell(e: SysmonEvent) -> bool:
    return e.image in SHELLS and e.get("Protocol") == "tcp" and e.get("Initiated") == "true"


def _shadow_read(e: SysmonEvent) -> bool:
    return "/etc/shadow" in e.command and _basename(e.image) not in _SHADOW_TOOLS


def _account_created(e: SysmonEvent) -> bool:
    return _basename(e.image) in _ACCOUNT_TOOLS


def _cron_persistence(e: SysmonEvent) -> bool:
    return e.target.startswith(("/etc/cron", "/var/spool/cron"))


def _ssh_key(e: SysmonEvent) -> bool:
    return e.target.endswith("/.ssh/authorized_keys")


def _hidden_temp_deleted(e: SysmonEvent) -> bool:
    return e.target.startswith(("/tmp/.", "/dev/shm/."))


RULES = [
    Rule("download_to_temp", "T1105", 1, _download_to_temp, "curl or wget wrote to a temp folder"),
    Rule("outbound_from_shell", "T1059.004", 3, _outbound_from_shell, "a shell opened a TCP link"),
    Rule("shadow_read", "T1003.008", 1, _shadow_read, "command names /etc/shadow"),
    Rule("account_created", "T1136.001", 1, _account_created, "local account created"),
    Rule("cron_persistence", "T1053.003", 11, _cron_persistence, "file created in a cron path"),
    Rule("ssh_key_persistence", "T1098.004", 11, _ssh_key, "authorized_keys created"),
    Rule("hidden_temp_deleted", "T1070.004", 23, _hidden_temp_deleted, "hidden temp file deleted"),
]

DECODE_RULE = "decoded_into_shell"
DECODE_TECHNIQUE = "T1140"
ALL_RULES = [r.name for r in RULES] + [DECODE_RULE]
RULE_NEEDS = {**{r.name: r.needs for r in RULES}, DECODE_RULE: 1}
RULE_TECHNIQUE = {**{r.name: r.technique for r in RULES}, DECODE_RULE: DECODE_TECHNIQUE}


@dataclass(frozen=True)
class Alert:
    rule: str
    technique: str
    event: SysmonEvent
    detail: str


def _seconds(event: SysmonEvent) -> float:
    return datetime.strptime(event.time, TIME_FORMAT).timestamp()


def _decoded_into_shell(events: list[SysmonEvent]) -> list[Alert]:
    """base64 -d with a shell started by the same parent moments apart.

    A pipeline is run by one parent, so its members are siblings. Decoding alone is
    normal, so a base64 -d with no sibling shell does not fire.
    """
    procs = [e for e in events if e.event_id == 1]
    alerts = []
    for e in procs:
        if _basename(e.image) != "base64" or not re.search(r"\s(-d|--decode)\b", e.command):
            continue
        for other in procs:
            if (
                other.image in SHELLS
                and other.parent_pid == e.parent_pid
                and other.pid != e.pid
                and abs(_seconds(other) - _seconds(e)) <= DECODE_WINDOW_SECONDS
            ):
                detail = f"{e.command} next to {other.image} ({other.command})"
                alerts.append(Alert(DECODE_RULE, DECODE_TECHNIQUE, e, detail))
                break
    return alerts


def detect(events: list[SysmonEvent]) -> list[Alert]:
    alerts = _decoded_into_shell(events)
    for e in events:
        for rule in RULES:
            if e.event_id == rule.needs and rule.check(e):
                evidence = e.command or e.target or e.get("DestinationPort")
                alerts.append(Alert(rule.name, rule.technique, e, f"{rule.what}: {evidence}"))
    alerts.sort(key=lambda a: a.event.time)
    return alerts
