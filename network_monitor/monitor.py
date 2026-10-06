"""Continuous sampler: one background thread per service (not per
target), a ring buffer of samples per target, an outage log, and
timed stability sessions.

One thread cycling all targets keeps probe load tiny and ordering
simple. Worst case a cycle takes target_count * timeout; the status
endpoint reports the real sample timestamps, so the UI never pretends
the cadence is exact.
"""
from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field

from rdp_troubleshooter.scanner import detect_network

from .metrics import compute_stats, stability_verdict
from .prober import ParsedUrl, probe_target

MAX_SAMPLES = 7200  # ~2 hours at 1 sample/sec per target
DEFAULT_RANGE_S = 300
DEFAULT_TARGETS = (
    {"name": "Cloudflare DNS (1.1.1.1)", "host": "1.1.1.1", "tcp_port": 443, "kind": "internet"},
    {"name": "Google DNS (8.8.8.8)", "host": "8.8.8.8", "tcp_port": 443, "kind": "internet"},
)


@dataclass
class Target:
    name: str
    host: str
    tcp_port: int
    kind: str  # "gateway" | "internet" | "custom"
    url: str | None = None
    samples: deque = field(default_factory=lambda: deque(maxlen=MAX_SAMPLES))
    consecutive_failures: int = 0
    outage_started_at: float | None = None


def _fmt_ts(ts: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


def _fault_conclusion(target_reports: list[dict]) -> str:
    """Plain-language LAN-vs-ISP call from per-target session verdicts."""
    def bad(t: dict) -> bool:
        return t["verdict"] in ("degraded", "unstable", "down")

    gateway = [t for t in target_reports if t["kind"] == "gateway"]
    external = [t for t in target_reports if t["kind"] in ("internet", "custom")]
    gw_bad = any(bad(t) for t in gateway)
    ext_bad = any(bad(t) for t in external)
    if gateway and ext_bad and not gw_bad:
        return ("Outside your home, most likely: the gateway/router stayed clean "
                "while internet targets degraded. That points at the ISP / upstream link.")
    if gw_bad and ext_bad:
        return ("Both the gateway and internet targets degraded. Start inside your home: "
                "this PC's link to the router, the router itself, or local congestion.")
    if gw_bad and not ext_bad:
        return ("Inside your home, most likely: the gateway/router itself degraded "
                "while internet targets stayed clean once reachable.")
    if ext_bad:
        return "Internet targets degraded during the session; the fault is outside this PC."
    if not target_reports or all(t["verdict"] == "warming_up" for t in target_reports):
        return "Not enough samples in this session to call it yet."
    return "No fault seen in this session: every target stayed stable for the whole run."


class MonitorService:
    def __init__(self, probe_fn=probe_target, interval_s: float = 1.0):
        self._probe_fn = probe_fn
        self._interval_s = interval_s
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._outages: list[dict] = []
        self._targets: list[Target] = []
        self._session: dict | None = None
        info = detect_network()
        if info.get("gateway_hint"):
            self._targets.append(Target("Gateway / router", info["gateway_hint"], 80, "gateway"))
        for spec in DEFAULT_TARGETS:
            self._targets.append(Target(spec["name"], spec["host"], spec["tcp_port"], spec["kind"]))
        self.local_ip = info.get("local_ip")
        self.subnet = info.get("subnet")

    # --- lifecycle ---------------------------------------------------
    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True, name="network-monitor")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _run(self) -> None:
        while not self._stop.is_set():
            cycle_start = time.monotonic()
            with self._lock:
                targets = list(self._targets)
            for target in targets:
                if self._stop.is_set():
                    break
                result = self._probe_fn(target.host, target.tcp_port)
                now = time.time()
                with self._lock:
                    target.samples.append((now, result.ms if result.ok else None))
                    if result.ok:
                        if target.outage_started_at is not None:
                            self._outages.append({
                                "target": target.name,
                                "host": target.host,
                                "started_at": target.outage_started_at,
                                "ended_at": now,
                                "duration_s": round(now - target.outage_started_at, 1),
                            })
                            target.outage_started_at = None
                        target.consecutive_failures = 0
                    else:
                        target.consecutive_failures += 1
                        if target.consecutive_failures >= 3 and target.outage_started_at is None:
                            target.outage_started_at = now
            elapsed = time.monotonic() - cycle_start
            self._stop.wait(max(0.0, self._interval_s - elapsed))

    # --- targets -------------------------------------------------------
    def add_custom_target(self, parsed: ParsedUrl) -> dict:
        with self._lock:
            for target in self._targets:
                if target.kind == "custom" and target.host == parsed.host and target.tcp_port == parsed.port:
                    return self._target_summary(target, list(target.samples)[-1:])
            target = Target(f"Custom: {parsed.host}", parsed.host, parsed.port,
                            "custom", url=parsed.url)
            self._targets.append(target)
            return self._target_summary(target, [])

    def _target_summary(self, target: Target, samples: list,
                        consecutive_failures: int | None = None) -> dict:
        stats = compute_stats(samples)
        code, explanation = stability_verdict(
            stats, target.consecutive_failures if consecutive_failures is None
            else consecutive_failures)
        return {
            "name": target.name,
            "host": target.host,
            "kind": target.kind,
            "url": target.url,
            "verdict": code,
            "verdict_explanation": explanation,
            "stats": stats.to_dict(),
            "series": [[round(ts, 1), (round(ms, 2) if ms is not None else None)]
                       for ts, ms in samples],
        }

    # --- timed sessions --------------------------------------------------
    def start_session(self, duration_s: float) -> dict:
        duration_s = float(duration_s)
        if not 1 <= duration_s <= 4 * 3600:
            raise ValueError("Session length must be between 1 second and 4 hours.")
        with self._lock:
            self._refresh_session_locked()
            if self._session and self._session["state"] == "running":
                raise RuntimeError("A session is already running.")
            self._session = {
                "started_at": time.time(),
                "duration_s": duration_s,
                "ended_at": None,
                "state": "running",
            }
            return self._session_snapshot_locked()

    def cancel_session(self) -> dict:
        with self._lock:
            self._refresh_session_locked()
            if not self._session or self._session["state"] != "running":
                raise RuntimeError("No session is running.")
            self._session["state"] = "cancelled"
            self._session["ended_at"] = time.time()
            return self._session_snapshot_locked()

    def _refresh_session_locked(self) -> None:
        if self._session and self._session["state"] == "running":
            end = self._session["started_at"] + self._session["duration_s"]
            if time.time() >= end:
                self._session["state"] = "complete"
                self._session["ended_at"] = end

    def _session_window_locked(self) -> tuple[float, float]:
        started = self._session["started_at"]
        ended = self._session["ended_at"] or time.time()
        return started, ended

    def _session_snapshot_locked(self) -> dict | None:
        if not self._session:
            return None
        self._refresh_session_locked()
        started, ended = self._session_window_locked()
        now = time.time()
        duration = self._session["duration_s"]
        elapsed = max(0.0, min(ended, now) - started) if self._session["state"] != "running" \
            else max(0.0, now - started)
        target_reports = []
        for target in self._targets:
            samples = [(ts, ms) for ts, ms in target.samples if started <= ts <= ended]
            # Session verdicts judge the session window only, never the
            # sampler's current failure streak outside it.
            summary = self._target_summary(target, samples, consecutive_failures=0)
            summary.pop("series", None)
            target_reports.append(summary)
        outages = []
        for outage in self._outages:
            if outage["ended_at"] >= started and outage["started_at"] <= ended:
                outages.append(outage)
        for target in self._targets:
            if target.outage_started_at is not None and target.outage_started_at >= started:
                outages.append({
                    "target": target.name,
                    "host": target.host,
                    "started_at": target.outage_started_at,
                    "ended_at": None,
                    "duration_s": round(ended - target.outage_started_at, 1),
                    "ongoing": True,
                })
        report = {
            "targets": target_reports,
            "outages": outages,
            "conclusion": _fault_conclusion(target_reports),
        }
        snapshot = {
            "state": self._session["state"],
            "started_at": round(started, 1),
            "ended_at": round(ended, 1) if self._session["ended_at"] else None,
            "duration_s": duration,
            "elapsed_s": round(elapsed, 1),
            "remaining_s": round(max(0.0, duration - elapsed), 1)
            if self._session["state"] == "running" else 0,
            "progress_pct": round(min(100.0, elapsed / duration * 100), 1) if duration else 100.0,
            "report": report,
        }
        snapshot["report_text"] = self._report_text(snapshot)
        return snapshot

    @staticmethod
    def _report_text(snapshot: dict) -> str:
        report = snapshot["report"]
        end_label = _fmt_ts(snapshot["ended_at"]) if snapshot["ended_at"] else "in progress"
        lines = [
            "Network Stability Session Report",
            f"Session: {_fmt_ts(snapshot['started_at'])} to {end_label} "
            f"({snapshot['duration_s']:.0f}s planned, {snapshot['elapsed_s']:.0f}s recorded, "
            f"state: {snapshot['state']})",
            "",
            "Per-target results:",
        ]
        for t in report["targets"]:
            s = t["stats"]
            lines.append(
                f"- {t['name']} ({t['host']}): {t['verdict']} - {t['verdict_explanation']} "
                f"median {s['median_ms']} ms, p95 {s['p95_ms']} ms, p99 {s['p99_ms']} ms, "
                f"worst {s['max_ms']} ms, jitter {s['jitter_ms']} ms, "
                f"loss {s['loss_pct']}% ({s['successes']}/{s['samples']} probes)"
            )
        lines.append("")
        if report["outages"]:
            lines.append("Outages (3+ failed probes in a row):")
            for o in report["outages"]:
                end = _fmt_ts(o["ended_at"]) if o.get("ended_at") else "still out"
                lines.append(f"- {o['target']}: {_fmt_ts(o['started_at'])} to {end} "
                             f"({o['duration_s']}s)")
        else:
            lines.append("Outages: none recorded.")
        lines += ["", f"Conclusion: {report['conclusion']}"]
        return "\n".join(lines) + "\n"

    def session_snapshot(self) -> dict | None:
        with self._lock:
            if not self._session:
                return None
            return self._session_snapshot_locked()

    def session_report_text(self) -> str | None:
        snapshot = self.session_snapshot()
        return snapshot["report_text"] if snapshot else None

    # --- reporting -----------------------------------------------------
    def status(self, range_s=DEFAULT_RANGE_S) -> dict:
        """Range-filtered status. range_s: seconds back from now, the
        string "all" (whole buffer), or "session" (current/last
        session window; falls back to the default range)."""
        with self._lock:
            self._refresh_session_locked()
            now = time.time()
            if range_s == "session" and self._session:
                since, until = self._session_window_locked()
            elif range_s == "all" or range_s is None:
                since, until = 0.0, now
                range_s = "all"
            else:
                if range_s == "session":  # asked for a session, none exists yet
                    range_s = DEFAULT_RANGE_S
                range_s = max(30.0, min(float(range_s), MAX_SAMPLES * 1.0))
                since, until = now - range_s, now
            targets = []
            for target in self._targets:
                samples = [(ts, ms) for ts, ms in target.samples if since <= ts <= until]
                targets.append(self._target_summary(target, samples))
            active_outages = [{
                "target": t.name, "host": t.host,
                "started_at": t.outage_started_at, "ended_at": None,
            } for t in self._targets if t.outage_started_at is not None]
            session = self._session_snapshot_locked() if self._session else None
            return {
                "local_ip": self.local_ip,
                "subnet": self.subnet,
                "targets": targets,
                "outages": list(self._outages[-50:]),
                "active_outages": active_outages,
                "running": bool(self._thread and self._thread.is_alive()),
                "range_s": range_s,
                "session": session,
            }

    def export_csv(self, session_only: bool = False) -> str:
        lines = ["target,host,timestamp_iso,latency_ms,ok"]
        with self._lock:
            since, until = (self._session_window_locked()
                            if session_only and self._session else (0.0, time.time()))
            for target in self._targets:
                for ts, ms in target.samples:
                    if not (since <= ts <= until):
                        continue
                    iso = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(ts))
                    lines.append(f"{target.name},{target.host},{iso},"
                                 f"{ms if ms is not None else ''},{1 if ms is not None else 0}")
        return "\n".join(lines) + "\n"
