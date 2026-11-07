"""Measure one capture: volume, signal share, and detections kept or lost."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from sysmontel.detections import ALL_RULES, TIME_FORMAT, Alert, detect
from sysmontel.lineage import find_attack_root, guid_lineage_events, pid_lineage, split_signal
from sysmontel.parser import ParsedLog, SysmonEvent, parse_file


@dataclass
class CaptureMetrics:
    name: str
    events: int
    bytes: int
    bad_lines: int
    seconds: float
    by_id: dict[int, int]
    signal: int
    noise: int
    guid_only_signal: int
    alerts: list[Alert]
    true_positives: int
    false_positives: int
    rules_on_signal: set[str]
    noise_groups: list[tuple[str, int]]

    @property
    def signal_percent(self) -> float:
        return 100 * self.signal / self.events if self.events else 0.0

    @property
    def events_per_minute(self) -> float:
        return 60 * self.events / self.seconds if self.seconds else 0.0

    @property
    def rules_missed(self) -> list[str]:
        return [r for r in ALL_RULES if r not in self.rules_on_signal]


def _duration(events: list[SysmonEvent]) -> float:
    if len(events) < 2:
        return 0.0
    first = datetime.strptime(events[0].time, TIME_FORMAT)
    last = datetime.strptime(events[-1].time, TIME_FORMAT)
    return (last - first).total_seconds()


def top_noise(noise: list[SysmonEvent], limit: int = 10) -> list[tuple[str, int]]:
    """Largest noise groups by event type and image. This is the list to tune from."""
    counts = Counter(f"{e.event_id} {e.image or '(sensor)'}" for e in noise)
    return counts.most_common(limit)


def measure(name: str, log: ParsedLog, root_pid: int) -> CaptureMetrics:
    events = log.events
    signal, noise = split_signal(events, root_pid)
    pids = pid_lineage(events, root_pid)
    alerts = detect(events)
    on_signal = [a for a in alerts if a.event.pid in pids]
    return CaptureMetrics(
        name=name,
        events=len(events),
        bytes=log.total_bytes,
        bad_lines=log.bad_lines,
        seconds=_duration(events),
        by_id=dict(sorted(Counter(e.event_id for e in events).items())),
        signal=len(signal),
        noise=len(noise),
        guid_only_signal=len(guid_lineage_events(events, root_pid)),
        alerts=alerts,
        true_positives=len(on_signal),
        false_positives=len(alerts) - len(on_signal),
        rules_on_signal={a.rule for a in on_signal},
        noise_groups=top_noise(noise),
    )


def load_capture(log_path: str | Path) -> CaptureMetrics:
    path = Path(log_path)
    log = parse_file(path)
    return measure(path.stem, log, find_attack_root(log.events))
