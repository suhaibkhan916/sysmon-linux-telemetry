import pytest
from helpers import event

from sysmontel.lineage import (
    ROOT_MARKER,
    find_attack_root,
    guid_lineage_events,
    pid_lineage,
    split_signal,
)


def test_root_comes_from_the_marker_parent():
    events = [
        event(1, ProcessId=5, ParentProcessId=2, CommandLine="ls"),
        event(1, ProcessId=11, ParentProcessId=10, CommandLine=ROOT_MARKER),
    ]
    assert find_attack_root(events) == 10


def test_no_marker_is_an_error():
    with pytest.raises(ValueError):
        find_attack_root([event(1, ProcessId=5, ParentProcessId=2, CommandLine="ls")])


def test_lineage_walks_several_levels_in_any_order():
    child = event(1, ProcessId=20, ParentProcessId=10)
    grandchild = event(1, ProcessId=30, ParentProcessId=20)
    unrelated = event(1, ProcessId=40, ParentProcessId=2)
    assert pid_lineage([grandchild, unrelated, child], 10) == {10, 20, 30}


def test_split_labels_every_event_type_by_pid():
    events = [
        event(1, ProcessId=20, ParentProcessId=10),
        event(11, ProcessId=20, TargetFilename="/tmp/.x"),
        event(3, ProcessId=10, DestinationPort=4444),
        event(5, ProcessId=99),
        event(16),  # sensor event with no PID counts as noise
    ]
    signal, noise = split_signal(events, 10)
    assert len(signal) == 3
    assert len(noise) == 2


def test_redirect_before_exec_is_kept_by_pid_and_lost_by_guid():
    """Taken from the real capture: `cat /etc/shadow > /tmp/.s` under the attack shell."""
    root = event(1, ProcessId=10, ParentProcessId=1, ProcessGuid="{root}")
    redirect = event(11, ProcessId=20, Image="/usr/bin/bash", TargetFilename="/tmp/.s")
    cat = event(
        1,
        ProcessId=20,
        ParentProcessId=10,
        ProcessGuid="{cat}",
        ParentProcessGuid="{root}",
    )
    events = [root, redirect, cat]
    assert redirect in split_signal(events, 10)[0]
    assert redirect not in guid_lineage_events(events, 10)
    assert cat in guid_lineage_events(events, 10)


def test_all_zero_guid_links_nothing():
    root = event(1, ProcessId=10)  # zero GUID: its parent was not tracked
    stranger = event(1, ProcessId=30, ParentProcessGuid=root.get("ProcessGuid"))
    assert guid_lineage_events([root, stranger], 10) == []
