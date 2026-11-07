"""Compare Sysmon captures. Exit codes: 0 fine, 1 a capture missed a detection, 2 input problem."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from sysmontel.metrics import CaptureMetrics, load_capture
from sysmontel.report import comparison_table, coverage_table, write_reports


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sysmontel", description=__doc__)
    parser.add_argument("captures", nargs="+", help="capture .log files")
    parser.add_argument("--out", help="folder for report.md and metrics.json")
    args = parser.parse_args(argv)

    captures: list[CaptureMetrics] = []
    for name in args.captures:
        try:
            captures.append(load_capture(name))
        except (OSError, ValueError) as exc:
            print(f"cannot read {name}: {exc}", file=sys.stderr)
            return 2

    print(comparison_table(captures))
    print()
    print(coverage_table(captures))
    if args.out:
        try:
            write_reports(captures, Path(args.out))
        except OSError as exc:
            print(f"cannot write reports to {args.out}: {exc}", file=sys.stderr)
            return 2
        print(f"\nreports written to {args.out}")
    return 1 if any(c.rules_missed for c in captures) else 0


if __name__ == "__main__":
    sys.exit(main())
