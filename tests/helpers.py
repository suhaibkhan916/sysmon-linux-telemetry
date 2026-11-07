"""Build small events and syslog lines for tests. All values are made up."""

from __future__ import annotations

from xml.sax.saxutils import escape

from sysmontel.parser import ZERO_GUID, SysmonEvent


def event(event_id: int = 1, **fields: object) -> SysmonEvent:
    data = {"UtcTime": "2026-11-07 10:00:00.000", "ProcessGuid": ZERO_GUID}
    data.update({k: str(v) for k, v in fields.items()})
    return SysmonEvent(event_id, "lab-test", data)


def syslog_line(event_id: int = 1, **fields: object) -> str:
    data = {"UtcTime": "2026-11-07 10:00:00.000"}
    data.update({k: str(v) for k, v in fields.items()})
    body = "".join(f'<Data Name="{k}">{escape(v)}</Data>' for k, v in data.items())
    return (
        "Nov  7 10:00:00 lab-test sysmon: <Event><System>"
        f"<EventID>{event_id}</EventID><Computer>lab-test</Computer></System>"
        f"<EventData>{body}</EventData></Event>"
    )
