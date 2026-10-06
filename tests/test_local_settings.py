"""Local expected-speeds storage + verdict thresholds (no network)."""
import json

import pytest

from network_monitor import local_settings as ls


def test_save_load_roundtrip(tmp_path):
    saved = ls.save_expected_speeds(500, 50, base_dir=tmp_path)
    assert saved == {"download_mbps": 500.0, "upload_mbps": 50.0}
    assert ls.load_expected_speeds(base_dir=tmp_path) == saved
    on_disk = json.loads((tmp_path / "expected_speeds.json").read_text())
    assert on_disk["download_mbps"] == 500.0 and "updated_at" in on_disk


def test_load_missing_and_corrupt_are_unset(tmp_path):
    assert ls.load_expected_speeds(base_dir=tmp_path) == \
        {"download_mbps": None, "upload_mbps": None}
    (tmp_path / "expected_speeds.json").write_text("not json {")
    assert ls.load_expected_speeds(base_dir=tmp_path)["download_mbps"] is None
    (tmp_path / "expected_speeds.json").write_text('{"download_mbps": "fast"}')
    assert ls.load_expected_speeds(base_dir=tmp_path)["download_mbps"] is None


def test_save_clear_and_partial(tmp_path):
    ls.save_expected_speeds(500, None, base_dir=tmp_path)
    assert ls.load_expected_speeds(base_dir=tmp_path) == \
        {"download_mbps": 500.0, "upload_mbps": None}
    ls.save_expected_speeds(None, None, base_dir=tmp_path)
    assert ls.load_expected_speeds(base_dir=tmp_path) == \
        {"download_mbps": None, "upload_mbps": None}


@pytest.mark.parametrize("bad", [0, -5, 99999, "500", True])
def test_save_rejects_bad_values(tmp_path, bad):
    with pytest.raises(ValueError):
        ls.save_expected_speeds(bad, 50, base_dir=tmp_path)


@pytest.mark.parametrize("actual,expected,verdict", [
    (100, 100, "excellent"),
    (90, 100, "excellent"),
    (89.9, 100, "good"),
    (75, 100, "good"),
    (74.9, 100, "fair"),
    (50, 100, "fair"),
    (49.9, 100, "poor"),
    (10, 100, "poor"),
])
def test_assess_thresholds(actual, expected, verdict):
    out = ls.assess_speed(actual, expected)
    assert out["verdict"] == verdict
    assert out["pct_of_expected"] == round(actual / expected * 100, 1)


def test_assess_unset_and_unmeasured():
    assert ls.assess_speed(100, None)["verdict"] == "unknown"
    assert ls.assess_speed(None, 100)["label"] == "Not measured"
    assert ls.assess_speed(None, None)["verdict"] == "unknown"


def test_overall_is_worst_direction():
    down = ls.assess_speed(95, 100)   # excellent
    up = ls.assess_speed(40, 100)     # poor
    assert ls.overall_verdict([down, up])["verdict"] == "poor"
    assert ls.overall_verdict([ls.assess_speed(10, None)]) is None
