"""Pure stats: percentiles, jitter, loss, verdicts."""
from network_monitor.metrics import compute_stats, percentile, stability_verdict


def test_percentile_nearest_rank():
    assert percentile([], 95) is None
    assert percentile([10.0], 95) == 10.0
    assert percentile([1, 2, 3, 4, 100], 50) == 3
    assert percentile([1, 2, 3, 4, 100], 95) == 100


def test_stats_empty():
    s = compute_stats([])
    assert s.samples == 0 and s.loss_pct == 0.0 and s.median_ms is None


def test_stats_all_lost():
    s = compute_stats([(1.0, None), (2.0, None)])
    assert s.successes == 0 and s.loss_pct == 100.0 and s.jitter_ms is None


def test_stats_mixed():
    s = compute_stats([(1.0, 10.0), (2.0, 20.0), (3.0, None), (4.0, 30.0)])
    assert s.samples == 4 and s.successes == 3
    assert s.loss_pct == 25.0
    assert s.min_ms == 10.0 and s.max_ms == 30.0 and s.median_ms == 20.0
    assert s.p95_ms == 30.0 and s.p99_ms == 30.0
    assert s.to_dict()["p99_ms"] == 30.0
    assert s.last_ms == 30.0
    # jitter over successes in order: |20-10|, |30-20| -> 10
    assert s.jitter_ms == 10.0


def test_verdicts():
    code, _ = stability_verdict(compute_stats([]), 0)
    assert code == "warming_up"
    code, _ = stability_verdict(compute_stats([(1.0, 12.0)] * 10), 0)
    assert code == "stable"
    code, _ = stability_verdict(compute_stats([(float(i), 12.0) for i in range(10)]), 3)
    assert code == "down"
    jittery = [(float(i), 10.0 if i % 2 == 0 else 60.0) for i in range(10)]
    code, _ = stability_verdict(compute_stats(jittery), 0)
    assert code == "unstable"
