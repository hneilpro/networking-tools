"""Local-only user settings for the Network Stability Monitor.

Expected (advertised/plan) speeds are personal context, not source
code: they live in a JSON file inside a folder that is deliberately
excluded from git (see the repo .gitignore). Nothing here is ever
sent anywhere; the file is read and written only by the local server.

Storage layout:
    network_monitor/local_data/expected_speeds.json
    {"download_mbps": 500.0, "upload_mbps": 50.0, "updated_at": "..."}

A missing, unreadable, or corrupt file is treated as "not set yet"
rather than an error, so a bad local file can never break the tool.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

# Folder inside the application package, per the user's request: the
# settings sit with the app itself, but outside version control.
LOCAL_DATA_DIR = Path(__file__).resolve().parent / "local_data"
SETTINGS_FILENAME = "expected_speeds.json"

MIN_MBPS = 0.1
MAX_MBPS = 10_000.0  # generous ceiling; catches unit mistakes/typos


def settings_path(base_dir: Path | None = None) -> Path:
    return (base_dir or LOCAL_DATA_DIR) / SETTINGS_FILENAME


def _clean_speed(value, field: str) -> float | None:
    """Validate one speed field. None / "" clears it (returns None)."""
    if value is None or value == "":
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{field} speed must be a number of Mbps.")
    number = float(value)
    if not MIN_MBPS <= number <= MAX_MBPS:
        raise ValueError(
            f"{field} speed must be between {MIN_MBPS} and {MAX_MBPS:g} Mbps.")
    return round(number, 2)


def load_expected_speeds(base_dir: Path | None = None) -> dict:
    """Return {"download_mbps": float|None, "upload_mbps": float|None}.

    Missing/corrupt local data returns both as None (not set)."""
    path = settings_path(base_dir)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"download_mbps": None, "upload_mbps": None}
    if not isinstance(data, dict):
        return {"download_mbps": None, "upload_mbps": None}
    out = {}
    for field in ("download_mbps", "upload_mbps"):
        value = data.get(field)
        if isinstance(value, (int, float)) and not isinstance(value, bool) \
                and MIN_MBPS <= float(value) <= MAX_MBPS:
            out[field] = float(value)
        else:
            out[field] = None
    return out


def save_expected_speeds(download_mbps=None, upload_mbps=None,
                         base_dir: Path | None = None) -> dict:
    """Validate and persist expected speeds as local JSON.

    Writes atomically (temp file + replace) so an interrupted save
    cannot leave a half-written file behind. Returns the saved dict."""
    download = _clean_speed(download_mbps, "Download")
    upload = _clean_speed(upload_mbps, "Upload")
    payload = {
        "download_mbps": download,
        "upload_mbps": upload,
        "updated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    }
    folder = base_dir or LOCAL_DATA_DIR
    folder.mkdir(parents=True, exist_ok=True)
    path = settings_path(base_dir)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    tmp.replace(path)
    return {"download_mbps": download, "upload_mbps": upload}


def assess_speed(actual_mbps: float | None,
                 expected_mbps: float | None) -> dict:
    """Compare one measured speed against the expected (plan) speed.

    Thresholds reflect how ISP speeds are normally judged: providers
    advertise "up to" rates and 10-20% variation is routine, while
    regulator panels treat ~95% of advertised at peak as delivered.
    So 90%+ is genuinely 'getting what you pay for', not a harsh bar."""
    out: dict = {"actual_mbps": actual_mbps, "expected_mbps": expected_mbps,
                 "pct_of_expected": None, "verdict": "unknown",
                 "label": "No expected speed set", "explanation": ""}
    if actual_mbps is None:
        out["label"] = "Not measured"
        out["explanation"] = "This direction did not produce a measurement."
        return out
    if not expected_mbps:
        out["explanation"] = ("Set your expected (plan) speed above and save it "
                              "to get a good/bad verdict on this result.")
        return out
    pct = round(actual_mbps / expected_mbps * 100, 1)
    out["pct_of_expected"] = pct
    if pct >= 90:
        out["verdict"] = "excellent"
        out["label"] = "Excellent"
        out["explanation"] = "You are getting what you pay for."
    elif pct >= 75:
        out["verdict"] = "good"
        out["label"] = "Good"
        out["explanation"] = "Close to your plan speed; within normal variation."
    elif pct >= 50:
        out["verdict"] = "fair"
        out["label"] = "Below expected"
        out["explanation"] = "Noticeably below your plan speed. Worth re-testing wired and off-peak."
    else:
        out["verdict"] = "poor"
        out["label"] = "Way below expected"
        out["explanation"] = "Less than half your plan speed. If a wired re-test agrees, this is complaint-grade evidence."
    return out


def overall_verdict(assessments: list[dict]) -> dict | None:
    """Worst-direction-governs summary across download/upload."""
    ranked = {"excellent": 0, "good": 1, "fair": 2, "poor": 3}
    known = [a for a in assessments if a.get("verdict") in ranked]
    if not known:
        return None
    worst = max(known, key=lambda a: ranked[a["verdict"]])
    return {"verdict": worst["verdict"], "label": worst["label"],
            "explanation": worst["explanation"]}
