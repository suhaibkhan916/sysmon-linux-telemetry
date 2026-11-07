import xml.etree.ElementTree as ET

import pytest
from helpers import syslog_line

from sysmontel.parser import parse_file, parse_line, parse_lines


def test_reads_fields_and_event_id():
    e = parse_line(syslog_line(1, ProcessId=42, Image="/usr/bin/id", CommandLine="id -u"))
    assert e is not None
    assert (e.event_id, e.computer, e.pid, e.image, e.command) == (
        1,
        "lab-test",
        42,
        "/usr/bin/id",
        "id -u",
    )


def test_xml_escapes_are_decoded():
    e = parse_line(syslog_line(1, CommandLine='bash -c "a" 3<>/dev/tcp/x/1 && b'))
    assert e is not None
    assert e.command == 'bash -c "a" 3<>/dev/tcp/x/1 && b'


def test_line_without_an_event_is_not_an_error():
    assert parse_line("Nov  7 10:00:00 lab-test rsyslogd: start") is None


def test_cut_off_event_raises():
    with pytest.raises(ET.ParseError):
        parse_line(syslog_line(1, CommandLine="x" * 50)[:90])


def test_bad_and_other_lines_are_counted_not_hidden():
    good = syslog_line(1, ProcessId=1)
    log = parse_lines([good, good[:80], "other text", "", good])
    assert (len(log.events), log.bad_lines, log.other_lines) == (2, 1, 1)
    assert log.total_bytes > 0


def test_events_are_sorted_by_time_and_ties_keep_file_order():
    late = syslog_line(1, UtcTime="2026-11-07 10:00:02.000", ProcessId=3)
    tie_a = syslog_line(1, UtcTime="2026-11-07 10:00:01.000", ProcessId=1)
    tie_b = syslog_line(1, UtcTime="2026-11-07 10:00:01.000", ProcessId=2)
    assert [e.pid for e in parse_lines([late, tie_a, tie_b]).events] == [1, 2, 3]


def test_missing_or_non_numeric_pid_is_none():
    assert parse_line(syslog_line(4, State="Started")).pid is None
    assert parse_line(syslog_line(1, ParentProcessId="-")).parent_pid is None


def test_parse_file(tmp_path):
    path = tmp_path / "x.log"
    path.write_text(syslog_line(5, ProcessId=9) + "\n", encoding="utf-8")
    assert parse_file(path).events[0].event_id == 5


def test_non_numeric_event_id_is_counted_not_a_crash():
    line = syslog_line(1, ProcessId=1).replace("<EventID>1<", "<EventID>abc<")
    log = parse_lines([line, syslog_line(1, ProcessId=2)])
    assert (len(log.events), log.bad_lines) == (1, 1)


def test_missing_or_bad_time_gives_none():
    assert parse_line(syslog_line(1, ProcessId=1)).when is not None
    assert parse_line(syslog_line(1, UtcTime="soon")).when is None
