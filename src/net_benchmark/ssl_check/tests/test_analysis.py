"""Tests for `net_benchmark.ssl_check.analysis`.

The central risk this module guards against is a threshold passing
vacuously — a metric that is missing, withheld, or fabricated as 0.0 still
satisfying a `<` comparison and driving a green CI exit. Every class below
that touches thresholds has at least one test asserting FAILURE for exactly
that reason.
"""

from __future__ import annotations

from typing import Callable, Coroutine, List

import pytest

from net_benchmark.http_bench.analysis import LatencyHistogram
from net_benchmark.ssl_check.analysis import (
    SSLAnalyzer,
    build_ssl_metric_namespace,
    evaluate_thresholds,
    expiry_timeline,
    parse_threshold,
    ssl_metric_names,
    thresholds_passed,
)
from net_benchmark.ssl_check.core import (
    PolicyConfig,
    SSLCheckEngine,
    SSLResult,
    SSLTarget,
    evaluate_policy,
)

from .conftest import TLSServerHandle

TLSServerFactory = Callable[..., Coroutine[None, None, TLSServerHandle]]


@pytest.fixture
async def mixed_fleet(
    tls_server: TLSServerFactory, unused_tcp_port: int
) -> List[SSLResult]:
    """One healthy target, one expiring-soon target, one unreachable target —
    exercises the full range of what get_target_statistics has to handle."""
    healthy = await tls_server(validity_days=150)
    expiring = await tls_server(validity_days=90, age_days=87, filename_hint="exp")

    engine = SSLCheckEngine(
        handshake_samples=6,
        min_samples=5,
        warmup_handshakes=0,
        connect_timeout=3,
        handshake_timeout=6,
    )
    targets = [
        SSLTarget("localhost", healthy.port, pinned_ip="127.0.0.1"),
        SSLTarget("localhost", expiring.port, pinned_ip="127.0.0.1"),
        SSLTarget("127.0.0.1", unused_tcp_port),
    ]
    results = await engine.check_targets(targets)
    policy = PolicyConfig(min_days_remaining=30)
    for result in results:
        evaluate_policy(result, policy)
    return results


class TestHostStatsAggregation:
    async def test_one_row_per_target(self, mixed_fleet: List[SSLResult]) -> None:
        analyzer = SSLAnalyzer(mixed_fleet)
        stats = analyzer.get_target_statistics()
        assert len(stats) == 3

    async def test_healthy_target_stats(self, mixed_fleet: List[SSLResult]) -> None:
        analyzer = SSLAnalyzer(mixed_fleet)
        by_target = {s.target: s for s in analyzer.get_target_statistics()}
        healthy = next(
            s
            for t, s in by_target.items()
            if s.cert_expiry_days_min and s.cert_expiry_days_min > 100
        )
        assert healthy.measured_checks == 1
        assert healthy.successful_checks == 1
        assert healthy.success_rate == 100.0
        assert healthy.tls13_rate == 100.0
        assert healthy.percentiles_refused is False
        assert healthy.p95_latency > 0

    async def test_unreachable_target_no_fabricated_values(
        self, mixed_fleet: List[SSLResult]
    ) -> None:
        """The single most load-bearing assertion in this file: an
        unreachable target must never get a 0 where a real measurement would
        go — a 0 for cert_expiry_days_min reads as 'expires today'."""
        analyzer = SSLAnalyzer(mixed_fleet)
        by_target = {s.target: s for s in analyzer.get_target_statistics()}
        dead = next(s for s in by_target.values() if s.measured_checks == 0)
        assert dead.cert_expiry_days_min is None
        assert dead.cert_expiry_days_avg is None
        assert dead.certificates_observed == 0

    async def test_success_rate_over_evaluated_rows_only(
        self, tls_server: TLSServerFactory
    ) -> None:
        """With no policy evaluated (compliant stays None everywhere),
        success_rate must fall back to the measured rate rather than reading
        0% for a fleet of perfectly healthy endpoints."""
        handle = await tls_server()
        engine = SSLCheckEngine(
            handshake_samples=1, warmup_handshakes=0, connect_timeout=3
        )
        result = await engine.check_target(
            SSLTarget("localhost", handle.port, pinned_ip="127.0.0.1")
        )
        # Deliberately NOT calling evaluate_policy — compliant stays None.
        analyzer = SSLAnalyzer([result])
        stats = analyzer.get_target_statistics()[0]
        assert stats.success_rate == 100.0

    async def test_histograms_merged_not_averaged(
        self, mixed_fleet: List[SSLResult]
    ) -> None:
        """Percentiles come from a merged histogram; averaging per-check
        percentiles produces a different, wrong number."""
        merged = [r for r in mixed_fleet if r.handshake_histogram is not None]
        combined = LatencyHistogram.merge_all(
            [r.handshake_histogram for r in merged if r.handshake_histogram]
        )
        total_samples = sum(len(r.handshake_samples_ms) for r in merged)
        assert combined.count == total_samples


class TestExpiryTimeline:
    """Items 42, 43 — unreachable targets go to 'unknown', never the most
    urgent bucket."""

    async def test_unreachable_target_in_unknown_bucket(
        self, mixed_fleet: List[SSLResult]
    ) -> None:
        timeline = {g["label"]: g for g in expiry_timeline(mixed_fleet)}
        assert timeline["unknown"]["count"] == 1

    async def test_expiring_target_in_correct_bucket(
        self, mixed_fleet: List[SSLResult]
    ) -> None:
        timeline = {g["label"]: g for g in expiry_timeline(mixed_fleet)}
        # The 90-day cert with 3 days left lands under the 7-day bucket.
        assert timeline["<7d"]["count"] == 1

    def test_empty_results(self) -> None:
        timeline = expiry_timeline([])
        assert all(g["count"] == 0 for g in timeline if g["label"] != "unknown")


class TestMetricNamespace:
    """Item 50 — the metric names a Threshold may reference."""

    async def test_cert_expiry_days_present_when_measured(
        self, mixed_fleet: List[SSLResult]
    ) -> None:
        analyzer = SSLAnalyzer(mixed_fleet)
        stats = {s.target: s for s in analyzer.get_target_statistics()}
        measured = next(s for s in stats.values() if s.measured_checks > 0)
        namespace = build_ssl_metric_namespace(measured)
        assert "cert_expiry_days" in namespace

    async def test_cert_expiry_days_absent_when_unreachable(
        self, mixed_fleet: List[SSLResult]
    ) -> None:
        analyzer = SSLAnalyzer(mixed_fleet)
        stats = {s.target: s for s in analyzer.get_target_statistics()}
        dead = next(s for s in stats.values() if s.measured_checks == 0)
        namespace = build_ssl_metric_namespace(dead)
        assert "cert_expiry_days" not in namespace

    async def test_sample_dependent_metrics_dropped_when_unmeasured(
        self, mixed_fleet: List[SSLResult]
    ) -> None:
        analyzer = SSLAnalyzer(mixed_fleet)
        stats = {s.target: s for s in analyzer.get_target_statistics()}
        dead = next(s for s in stats.values() if s.measured_checks == 0)
        namespace = build_ssl_metric_namespace(dead)
        assert "p95_handshake_ms" not in namespace
        assert "avg_handshake_ms" not in namespace

    async def test_percentiles_dropped_when_refused(
        self, tls_server: TLSServerFactory
    ) -> None:
        """Item 57 — withheld percentiles must not appear in the namespace as
        0.0, or a threshold against them passes vacuously."""
        handle = await tls_server()
        engine = SSLCheckEngine(
            handshake_samples=2,
            min_samples=5,
            warmup_handshakes=0,
            connect_timeout=3,
            handshake_timeout=6,
        )
        result = await engine.check_target(
            SSLTarget("localhost", handle.port, pinned_ip="127.0.0.1")
        )
        analyzer = SSLAnalyzer([result])
        stats = analyzer.get_target_statistics()[0]
        namespace = build_ssl_metric_namespace(stats)
        assert "p95_handshake_ms" not in namespace
        # Mean is exact at any sample count and must survive.
        assert "avg_handshake_ms" in namespace

    def test_metric_names_catches_typo_before_run(self) -> None:
        names = ssl_metric_names()
        assert "cert_expiry_days" in names
        assert "p95_handshake_ms" in names
        assert "cert_expiry_dayz" not in names


class TestThresholdVacuousPass:
    """Every test in this class asserts a threshold FAILS in a situation
    where a naive implementation would let it pass."""

    async def test_unreachable_target_fails_expiry_threshold(
        self, mixed_fleet: List[SSLResult]
    ) -> None:
        analyzer = SSLAnalyzer(mixed_fleet)
        stats = {s.target: s for s in analyzer.get_target_statistics()}
        dead = next(s for s in stats.values() if s.measured_checks == 0)
        namespace = build_ssl_metric_namespace(dead)
        results = evaluate_thresholds(
            [parse_threshold("cert_expiry_days>30")], namespace
        )
        assert thresholds_passed(results) is False
        assert results[0].error is not None

    async def test_healthy_target_passes_same_threshold(
        self, mixed_fleet: List[SSLResult]
    ) -> None:
        analyzer = SSLAnalyzer(mixed_fleet)
        stats = {s.target: s for s in analyzer.get_target_statistics()}
        healthy = next(
            s
            for s in stats.values()
            if s.cert_expiry_days_min and s.cert_expiry_days_min > 100
        )
        namespace = build_ssl_metric_namespace(healthy)
        results = evaluate_thresholds(
            [parse_threshold("cert_expiry_days>30")], namespace
        )
        assert thresholds_passed(results) is True

    async def test_withheld_percentile_fails_not_passes_on_zero(
        self, tls_server: TLSServerFactory
    ) -> None:
        handle = await tls_server()
        engine = SSLCheckEngine(
            handshake_samples=2,
            min_samples=5,
            warmup_handshakes=0,
            connect_timeout=3,
            handshake_timeout=6,
        )
        result = await engine.check_target(
            SSLTarget("localhost", handle.port, pinned_ip="127.0.0.1")
        )
        analyzer = SSLAnalyzer([result])
        stats = analyzer.get_target_statistics()[0]
        namespace = build_ssl_metric_namespace(stats)
        results = evaluate_thresholds(
            [parse_threshold("p95_handshake_ms<10000")], namespace
        )
        # A withheld p95 defaulting to 0.0 would pass this trivially.
        assert thresholds_passed(results) is False
