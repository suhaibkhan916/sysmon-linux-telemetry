import pytest
from helpers import event

from sysmontel.detections import ALL_RULES, DECODE_RULE, RULE_NEEDS, RULE_TECHNIQUE, detect


def rules(*events):
    return [a.rule for a in detect(list(events))]


@pytest.mark.parametrize(
    "rule, evt",
    [
        (
            "download_to_temp",
            event(1, Image="/usr/bin/curl", CommandLine="curl -s -o /tmp/.a http://x/a"),
        ),
        ("download_to_temp", event(1, Image="/usr/bin/wget", CommandLine="wget -O /dev/shm/a x")),
        (
            "outbound_from_shell",
            event(3, Image="/usr/bin/bash", Protocol="tcp", Initiated="true"),
        ),
        ("shadow_read", event(1, Image="/usr/bin/cat", CommandLine="cat /etc/shadow")),
        ("account_created", event(1, Image="/usr/sbin/useradd", CommandLine="useradd -m x")),
        ("cron_persistence", event(11, TargetFilename="/etc/cron.d/x")),
        ("cron_persistence", event(11, TargetFilename="/var/spool/cron/crontabs/root")),
        ("ssh_key_persistence", event(11, TargetFilename="/home/a/.ssh/authorized_keys")),
        ("hidden_temp_deleted", event(23, TargetFilename="/tmp/.stage1.sh")),
    ],
)
def test_rule_fires(rule, evt):
    assert rules(evt) == [rule]


@pytest.mark.parametrize(
    "evt",
    [
        # Health check output goes to /dev/null, not a temp folder.
        event(1, Image="/usr/bin/curl", CommandLine="curl -s -o /dev/null http://x/healthz"),
        # Inbound and UDP traffic for a shell, and TCP from a non shell.
        event(3, Image="/usr/bin/bash", Protocol="tcp", Initiated="false"),
        event(3, Image="/usr/bin/bash", Protocol="udp", Initiated="true"),
        event(3, Image="/usr/bin/curl", Protocol="tcp", Initiated="true"),
        # The password tools touch shadow as their normal job.
        event(1, Image="/usr/bin/chage", CommandLine="chage -l root /etc/shadow"),
        # Reading the cron folder is not writing to it.
        event(1, Image="/usr/bin/ls", CommandLine="ls /etc/cron.d"),
        event(11, TargetFilename="/etc/passwd.123"),
        event(11, TargetFilename="/tmp/authorized_keys.bak"),
        # A normal temp file, deleted.
        event(23, TargetFilename="/tmp/app-job-1.tmp"),
        # Right field, wrong event type: FileDelete of a cron file is not creation.
        event(23, TargetFilename="/etc/cron.d/x"),
    ],
)
def test_rule_stays_quiet(evt):
    assert rules(evt) == []


def decode_pair(gap_ms=5, shell_parent=7, command="base64 -d", shell="/usr/bin/dash"):
    decoder = event(
        1,
        ProcessId=20,
        ParentProcessId=7,
        Image="/usr/bin/base64",
        CommandLine=command,
        UtcTime="2026-11-07 10:00:00.000",
    )
    other = event(
        1,
        ProcessId=21,
        ParentProcessId=shell_parent,
        Image=shell,
        CommandLine="sh",
        UtcTime=f"2026-11-07 10:00:00.{gap_ms:03d}",
    )
    return decoder, other


def test_decode_with_sibling_shell_fires():
    assert rules(*decode_pair()) == [DECODE_RULE]


def test_long_decode_flag_fires():
    assert rules(*decode_pair(command="base64 --decode")) == [DECODE_RULE]


def test_decode_alone_is_normal():
    assert rules(decode_pair()[0]) == []


def test_shell_with_another_parent_does_not_fire():
    assert rules(*decode_pair(shell_parent=8)) == []


def test_encoding_with_sibling_shell_does_not_fire():
    assert rules(*decode_pair(command="base64")) == []


def test_non_shell_sibling_does_not_fire():
    assert rules(*decode_pair(shell="/usr/bin/grep")) == []


def test_decode_window_boundary():
    assert rules(*decode_pair(gap_ms=500)) == [DECODE_RULE]
    assert rules(*decode_pair(gap_ms=501)) == []


def test_alerts_are_in_time_order():
    late = event(11, TargetFilename="/etc/cron.d/x", UtcTime="2026-11-07 10:00:09.000")
    early = event(23, TargetFilename="/tmp/.x", UtcTime="2026-11-07 10:00:01.000")
    assert rules(late, early) == ["hidden_temp_deleted", "cron_persistence"]


def test_every_rule_has_a_technique_and_a_required_event():
    assert len(ALL_RULES) == 8
    assert set(RULE_NEEDS) == set(RULE_TECHNIQUE) == set(ALL_RULES)
