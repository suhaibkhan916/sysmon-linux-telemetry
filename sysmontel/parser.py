"""Read Sysmon for Linux events from syslog lines.

A line looks like this, with the XML on one line:
  Nov  7 14:26:58 lab-sensor sysmon: <Event><System>...</System><EventData>...</EventData></Event>

A long command line can push a record past the syslog size limit (8 KB by default in
rsyslog). The XML is then cut off and cannot be parsed. Those lines are counted, not
hidden, because a silently lost event is worse than a reported one.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

EVENT_NAMES = {
    1: "ProcessCreate",
    3: "NetworkConnect",
    4: "ServiceStateChange",
    5: "ProcessTerminate",
    9: "RawAccessRead",
    11: "FileCreate",
    16: "ConfigChange",
    23: "FileDelete",
}

ZERO_GUID = "{00000000-0000-0000-0000-000000000000}"
TIME_FORMAT = "%Y-%m-%d %H:%M:%S.%f"


@dataclass(frozen=True)
class SysmonEvent:
    event_id: int
    computer: str
    data: dict[str, str]

    def get(self, name: str) -> str:
        return self.data.get(name, "")

    @property
    def time(self) -> str:
        return self.get("UtcTime")

    @property
    def when(self) -> datetime | None:
        """The time as a datetime, or None if the event has no usable time."""
        try:
            return datetime.strptime(self.time, TIME_FORMAT)
        except ValueError:
            return None

    @property
    def image(self) -> str:
        return self.get("Image")

    @property
    def command(self) -> str:
        return self.get("CommandLine")

    @property
    def target(self) -> str:
        return self.get("TargetFilename")

    @property
    def pid(self) -> int | None:
        return _to_int(self.get("ProcessId"))

    @property
    def parent_pid(self) -> int | None:
        return _to_int(self.get("ParentProcessId"))


@dataclass
class ParsedLog:
    events: list[SysmonEvent] = field(default_factory=list)
    bad_lines: int = 0
    other_lines: int = 0
    total_bytes: int = 0


def _to_int(value: str) -> int | None:
    try:
        return int(value)
    except ValueError:
        return None


def parse_line(line: str) -> SysmonEvent | None:
    """Return the event in one syslog line, or None if the line holds no event.

    Raises ET.ParseError if the event is cut off, ValueError if its EventID is not a number.
    """
    start = line.find("<Event>")
    if start < 0:
        return None
    root = ET.fromstring(line[start:].strip())
    event_id = int(root.findtext("System/EventID", default="0"))
    computer = root.findtext("System/Computer", default="")
    data = {d.get("Name", ""): (d.text or "") for d in root.findall("EventData/Data")}
    return SysmonEvent(event_id, computer, data)


def parse_lines(lines: list[str]) -> ParsedLog:
    log = ParsedLog()
    for line in lines:
        if not line.strip():
            continue
        log.total_bytes += len(line.encode("utf-8"))
        try:
            event = parse_line(line)
        except (ET.ParseError, ValueError):
            log.bad_lines += 1
            continue
        if event is None:
            log.other_lines += 1
        else:
            log.events.append(event)
    # UtcTime has millisecond resolution; a stable sort keeps file order for ties.
    log.events.sort(key=lambda e: e.time)
    return log


def parse_file(path: str | Path) -> ParsedLog:
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    return parse_lines(text.splitlines())
