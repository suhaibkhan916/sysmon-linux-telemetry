"""Checks against the committed captures. These are real Sysmon events from the lab run."""

import re
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from sysmontel.__main__ import main
from sysmontel.detections import ALL_RULES
from sysmontel.metrics import load_capture

ROOT = Path(__file__).resolve().parent.parent
CAPTURES = ROOT / "data" / "captures"
NOISY = CAPTURES / "config-noisy.log"
TUNED = CAPTURES / "config-tuned.log"
OVERTUNED = CAPTURES / "config-overtuned.log"


@pytest.fixture(scope="module")
def noisy():
    return load_capture(NOISY)


@pytest.fixture(scope="module")
def tuned():
    return load_capture(TUNED)


@pytest.fixture(scope="module")
def overtuned():
    return load_capture(OVERTUNED)


def test_recorded_volumes(noisy, tuned, overtuned):
    assert (noisy.events, tuned.events, overtuned.events) == (487, 37, 14)
    assert noisy.bad_lines == tuned.bad_lines == overtuned.bad_lines == 0


def test_noisy_capture_has_all_event_types_the_lab_uses(noisy):
    assert set(noisy.by_id) == {1, 3, 4, 5, 11, 16, 23}


def test_tuned_keeps_every_detection_at_a_fraction_of_the_volume(noisy, tuned):
    assert noisy.rules_missed == []
    assert tuned.rules_missed == []
    assert tuned.events < noisy.events * 0.1
    assert tuned.signal_percent > noisy.signal_percent


def test_overtuned_is_quiet_and_blind(overtuned):
    assert sorted(overtuned.rules_on_signal) == ["account_created"]
    assert len(overtuned.rules_missed) == len(ALL_RULES) - 1


def test_known_false_positive_is_the_app_update_download(noisy):
    assert noisy.true_positives == 9
    assert noisy.false_positives == 1
    assert sum("app-update.tar" in a.detail for a in noisy.alerts) == 1


def test_guid_lineage_misses_the_redirect_event(noisy, tuned):
    assert noisy.signal - noisy.guid_only_signal == 1
    assert tuned.signal - tuned.guid_only_signal == 1


@pytest.mark.parametrize("path", sorted(CAPTURES.glob("*.log")), ids=lambda p: p.name)
def test_captures_hold_no_host_paths_or_personal_data(path):
    """Docker Desktop exposed the host path in a FileCreate once. Stop that coming back."""
    text = path.read_text(encoding="utf-8")
    assert not re.search(r"Users/|/mnt/host", text, re.I)


@pytest.mark.parametrize("path", sorted((ROOT / "configs").glob("*.xml")), ids=lambda p: p.name)
def test_configs_are_well_formed(path):
    root = ET.parse(path).getroot()
    assert root.tag == "Sysmon"
    assert root.find("EventFiltering") is not None


def test_tuned_config_does_not_exclude_shells_or_unknown_processes():
    """Excluding by image is what makes the overtuned config blind."""
    text = (ROOT / "configs" / "config-tuned.xml").read_text(encoding="utf-8")
    excluded_images = re.findall(r'<Image condition="is">([^<]+)</Image>', text)
    assert "/usr/bin/bash" not in excluded_images
    assert "unknown" not in text.split("<EventFiltering>")[1]


def test_cli_exit_zero_when_nothing_is_missed(capsys):
    assert main([str(NOISY), str(TUNED)]) == 0
    assert "8/8" in capsys.readouterr().out


def test_cli_exit_one_when_a_detection_is_missed(capsys):
    assert main([str(TUNED), str(OVERTUNED)]) == 1
    assert "MISSED" in capsys.readouterr().out


def test_cli_exit_two_on_missing_file(capsys, tmp_path):
    assert main([str(tmp_path / "none.log")]) == 2
    assert "cannot read" in capsys.readouterr().err


def test_cli_exit_two_when_capture_has_no_marker(capsys, tmp_path):
    empty = tmp_path / "empty.log"
    empty.write_text("", encoding="utf-8")
    assert main([str(empty)]) == 2
    assert "marker" in capsys.readouterr().err


def test_cli_writes_reports(tmp_path, capsys):
    assert main([str(NOISY), "--out", str(tmp_path)]) == 0
    capsys.readouterr()
    report = (tmp_path / "report.md").read_text(encoding="utf-8")
    assert "Detection coverage" in report
    assert "synthetic" in report
    assert (tmp_path / "metrics.json").exists()
