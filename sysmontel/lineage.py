"""Label events as signal or noise by walking the attack's process tree.

attack.sh starts by running `printenv LAB_ATTACK_ROOT_MARKER`. The ParentProcessId of
that event is the attack root, so labels do not depend on the detections being measured.
No config filters printenv.

Why a marker and not the PID the script sees: on Docker Desktop the container's --pid=host
view is itself a nested PID namespace. `$!` gave 8531 where Sysmon reported 8977 for the
same process, because Sysmon reports kernel root namespace PIDs.

Why PIDs and not ProcessGuid: on Linux, Sysmon's ProcessCreate fires on exec. A shell
that forks and then opens a redirect target (`cat /etc/shadow > /tmp/.s`) creates that
file before the exec, so the FileCreate has Image=/usr/bin/bash and an all-zero
ProcessGuid. Its PID is still correct, and it is the PID the later exec keeps.
guid_lineage_events is kept so the difference can be measured.

Limit: a reused PID inside the capture would be mislabelled. Captures last about a
minute and PIDs do not wrap that fast here.
"""

from __future__ import annotations

from sysmontel.parser import ZERO_GUID, SysmonEvent

ROOT_MARKER = "printenv LAB_ATTACK_ROOT_MARKER"


def find_attack_root(events: list[SysmonEvent]) -> int:
    """Return the attack root PID from the marker. Raises ValueError if there is none."""
    for e in events:
        if e.event_id == 1 and e.command == ROOT_MARKER and e.parent_pid is not None:
            return e.parent_pid
    raise ValueError("no ground truth marker in this capture")


def pid_lineage(events: list[SysmonEvent], root_pid: int) -> set[int]:
    """All PIDs descended from root_pid, as far as the kept events can show."""
    pids = {root_pid}
    changed = True
    while changed:  # repeat so the result does not depend on event order
        changed = False
        for e in events:
            if e.event_id == 1 and e.parent_pid in pids and e.pid is not None and e.pid not in pids:
                pids.add(e.pid)
                changed = True
    return pids


def split_signal(
    events: list[SysmonEvent], root_pid: int
) -> tuple[list[SysmonEvent], list[SysmonEvent]]:
    """Return (signal, noise). Signal means the event belongs to the attack tree."""
    pids = pid_lineage(events, root_pid)
    signal = [e for e in events if e.pid in pids]
    noise = [e for e in events if e.pid not in pids]
    return signal, noise


def guid_lineage_events(events: list[SysmonEvent], root_pid: int) -> list[SysmonEvent]:
    """Events reachable through ProcessGuid links only, from the attack root's GUID."""
    roots = {e.get("ProcessGuid") for e in events if e.event_id == 1 and e.pid == root_pid}
    guids = {g for g in roots if g and g != ZERO_GUID}
    changed = True
    while changed:
        changed = False
        for e in events:
            guid = e.get("ProcessGuid")
            if e.event_id == 1 and e.get("ParentProcessGuid") in guids and guid not in guids:
                guids.add(guid)
                changed = True
    return [e for e in events if e.get("ProcessGuid") in guids]
