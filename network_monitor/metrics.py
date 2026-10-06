"""Pure statistics for latency samples. No I/O, fully unit-testable.

A sample is (timestamp_seconds, latency_ms_or_None). None means the probe
failed (packet loss). Averages alone hide spikes, so the headline numbers
are median and p95, with jitter as the mean absolute step between
consecutive successful samples.
"""
from __future__ import annotations

import math
from dataclasses import dataclass


def percentile(values: list[float], pct: float) -> float | None:
    """Nearest-rank percentile. pct is 0-100."""
    if not values:
        return None
    ordered = sorted(values)
    rank = max(1, math.ceil(pct / 100 * len(ordered)))
    return ordered[min(rank, len(ordered)) - 1]


def median(values: list[float]) -> float | None:
    return percentile(values, 50)


@dataclass
class Stats:
    samples: int = 0
    successes: int = 0
    loss_pct: float = 0.0
    last_ms: float | None = None
    min_ms: float | None = None
    median_ms: float | None = None
    p95_ms: float | None = None
    max_ms: float | None = None
    jitter_ms: float | None = None

    def to_dict(self) -> dict:
        return {
            "samples": self.samples,
            "successes": self.successes,
            "loss_pct": round(self.loss_pct, 2),
            "last_ms": _round(self.last_ms),
            "min_ms": _round(self.min_ms),
            "median_ms": _round(self.median_ms),
            "p95_ms": _round(self.p95_ms),
            "max_ms": _round(self.max_ms),
            "jitter_ms": _round(self.jitter_ms),
        }


def _round(value: float | None) -> float | None:
    return round(value, 2) if value is not None else None


def compute_stats(samples: list[tuple[float, float | None]]) -> Stats:
    stats = Stats(samples=len(samples))
    if not samples:
        return stats
    good = [lat for _, lat in samples if lat is not None]
    stats.successes = len(good)
    stats.loss_pct = (len(samples) - len(good)) / len(samples) * 100
    if good:
        stats.last_ms = next((lat for _, lat in reversed(samples) if lat is not None), None)
        stats.min_ms = min(good)
        stats.max_ms = max(good)
        stats.median_ms = median(good)
        stats.p95_ms = percentile(good, 95)
    # Jitter: mean absolute difference between consecutive successful samples,
    # skipping over losses (a loss is already counted in loss_pct).
    diffs = [abs(b - a) for a, b in zip(good, good[1:])]
    if diffs:
        stats.jitter_ms = sum(diffs) / len(diffs)
    return stats


def stability_verdict(stats: Stats, consecutive_failures: int) -> tuple[str, str]:
    """(code, plain-language explanation) from window stats."""
    if stats.samples == 0:
        return "warming_up", "No samples yet. Monitoring just started."
    if consecutive_failures >= 3 or stats.loss_pct >= 50:
        return "down", "Most probes are failing right now. This target is effectively unreachable."
    if stats.loss_pct > 3 or (stats.jitter_ms or 0) > 30 or (stats.p95_ms or 0) > 250:
        return "unstable", "High loss, jitter, or spikes. Calls, games, and VPNs will feel this."
    if stats.loss_pct > 1 or (stats.jitter_ms or 0) > 10 or (stats.median_ms or 0) > 100:
        return "degraded", "Usable, but not clean: some jitter, loss, or high baseline latency."
    return "stable", "Low latency, low jitter, no meaningful loss in this window."
