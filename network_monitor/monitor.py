"""Continuous sampler: one background thread per service (not per
target), a ring buffer of samples per target, and an outage log.

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

MAX_SAMPLES = 3600  # ~1 hour at 1 sample/sec per target
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


class MonitorService:
    def __init__(self, probe_fn=probe_target, interval_s: float = 1.0):
        self._probe_fn = probe_fn
        self._interval_s = interval_s
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._outages: list[dict] = []
        self._targets: list[Target] = []
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
                    return self._target_summary(target, window=1)
            target = Target(f"Custom: {parsed.host}", parsed.host, parsed.port,
                            "custom", url=parsed.url)
            self._targets.append(target)
            return self._target_summary(target, window=1)

    def _target_summary(self, target: Target, window: int) -> dict:
        recent = list(target.samples)[-window:]
        stats = compute_stats(recent)
        code, explanation = stability_verdict(stats, target.consecutive_failures)
        return {
            "name": target.name,
            "host": target.host,
            "kind": target.kind,
            "url": target.url,
            "verdict": code,
            "verdict_explanation": explanation,
            "stats": stats.to_dict(),
            "series": [[round(ts, 1), (round(ms, 2) if ms is not None else None)]
                       for ts, ms in recent],
        }

    # --- reporting -----------------------------------------------------
    def status(self, window: int = 300) -> dict:
        with self._lock:
            return {
                "local_ip": self.local_ip,
                "subnet": self.subnet,
                "targets": [self._target_summary(t, window) for t in self._targets],
                "outages": list(self._outages[-50:]),
                "running": bool(self._thread and self._thread.is_alive()),
            }

    def export_csv(self) -> str:
        lines = ["target,host,timestamp_iso,latency_ms,ok"]
        with self._lock:
            for target in self._targets:
                for ts, ms in target.samples:
                    iso = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(ts))
                    lines.append(f"{target.name},{target.host},{iso},"
                                 f"{ms if ms is not None else ''},{1 if ms is not None else 0}")
        return "\n".join(lines) + "\n"
