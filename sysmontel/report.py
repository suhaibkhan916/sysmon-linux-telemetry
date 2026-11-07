"""Write the comparison as Markdown and JSON."""

from __future__ import annotations

import json
from pathlib import Path

from sysmontel.detections import ALL_RULES, RULE_NEEDS, RULE_TECHNIQUE
from sysmontel.metrics import CaptureMetrics
from sysmontel.parser import EVENT_NAMES


def comparison_table(captures: list[CaptureMetrics]) -> str:
    rows = [
        "| Capture | Events | Bytes | Events/min | Signal | Noise | Signal % "
        "| Rules on attack | True alerts | False alerts | Bad lines |",
        "|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for c in captures:
        rows.append(
            f"| {c.name} | {c.events} | {c.bytes} | {c.events_per_minute:.0f} | {c.signal} "
            f"| {c.noise} | {c.signal_percent:.1f} | {len(c.rules_on_signal)}/{len(ALL_RULES)} "
            f"| {c.true_positives} | {c.false_positives} | {c.bad_lines} |"
        )
    return "\n".join(rows)


def coverage_table(captures: list[CaptureMetrics]) -> str:
    head = " | ".join(c.name for c in captures)
    rows = [
        f"| Rule | ATT&CK | Needs event | {head} |",
        "|---|---|---|" + "---|" * len(captures),
    ]
    for rule in ALL_RULES:
        cells = " | ".join("yes" if rule in c.rules_on_signal else "MISSED" for c in captures)
        need = RULE_NEEDS[rule]
        rows.append(f"| {rule} | {RULE_TECHNIQUE[rule]} | {need} {EVENT_NAMES[need]} | {cells} |")
    return "\n".join(rows)


def markdown_report(captures: list[CaptureMetrics]) -> str:
    parts = [
        "# Sysmon for Linux: noise against signal",
        "",
        "Activity is scripted and synthetic. Events are real Sysmon output from a container.",
        "",
        comparison_table(captures),
        "",
        "## Detection coverage",
        "",
        coverage_table(captures),
    ]
    for c in captures:
        parts += ["", f"## {c.name}", "", "Largest noise groups (event id, image):", ""]
        parts += [f"- {count} x {group}" for group, count in c.noise_groups]
        parts += ["", "Alerts:", ""]
        parts += [f"- {a.event.time} {a.rule} ({a.technique}) {a.detail}" for a in c.alerts]
    return "\n".join(parts) + "\n"


def to_json(captures: list[CaptureMetrics]) -> str:
    return json.dumps(
        [
            {
                "name": c.name,
                "events": c.events,
                "bytes": c.bytes,
                "by_id": c.by_id,
                "signal": c.signal,
                "noise": c.noise,
                "guid_only_signal": c.guid_only_signal,
                "true_positives": c.true_positives,
                "false_positives": c.false_positives,
                "rules_missed": c.rules_missed,
            }
            for c in captures
        ],
        indent=2,
    )


def write_reports(captures: list[CaptureMetrics], out: str | Path) -> None:
    folder = Path(out)
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "report.md").write_text(markdown_report(captures), encoding="utf-8", newline="\n")
    (folder / "metrics.json").write_text(to_json(captures), encoding="utf-8", newline="\n")
