from typing import List

import pytest

from net_benchmark.http_bench.analysis import (
    HTTPAnalyzer,
    LatencyHistogram,
    ThresholdResult,
    build_metric_namespace,
    evaluate_thresholds,
    parse_threshold,
    thresholds_passed,
)
from net_benchmark.http_bench.core import HTTPProtocol, HTTPResult, QueryStatus


def test_create_dataframe(sample_results):
    analyzer = HTTPAnalyzer(sample_results)
    df = analyzer.df
    assert len(df) == 2
    assert set(df.columns) >= {"target", "total_ms", "status", "completed"}


def test_get_target_statistics(sample_results):
    analyzer = HTTPAnalyzer(sample_results)
    stats = analyzer.get_target_statistics()
    assert len(stats) == 1  # both results for same target
    s = stats[0]
    assert s.total_requests == 2
    assert s.successful_requests == 1
    assert s.success_rate == 50.0
    assert s.avg_latency == 100.0
    assert s.avg_ttfb_ms == 50.0
    assert s.http2_rate == 100.0
    assert s.cdn_fingerprint == "Cloudflare"
    assert s.cache_control_present == 1
    assert s.etag_present == 1
    assert s.last_modified_present == 1
    assert s.age_present == 1


def test_consistency_single_sample():
    """Test that consistency is 100% with one success."""
    r = create_success_result(total_ms=50)
    analyzer = HTTPAnalyzer([r])
    stats = analyzer.get_target_statistics()
    assert len(stats) == 1
    assert stats[0].consistency_score == 100.0
    assert stats[0].jitter == 0.0


def test_get_overall_statistics(sample_results):
    analyzer = HTTPAnalyzer(sample_results)
    overall = analyzer.get_overall_statistics()
    assert overall["total_requests"] == 2
    assert overall["successful_requests"] == 1
    assert overall["overall_success_rate"] == 50.0
    assert overall["overall_avg_latency"] == 100.0
    assert overall["overall_avg_ttfb"] == 50.0
    assert overall["fastest_target"] == "https://example.com"
    assert overall["assertion_pass_rate"] == 50.0  # one passed, one no assertions


def test_get_ttfb_statistics(sample_results):
    analyzer = HTTPAnalyzer(sample_results)
    ttfb = analyzer.get_ttfb_statistics()
    assert len(ttfb) == 1
    assert ttfb[0]["avg_ttfb_ms"] == 50.0


def test_get_protocol_distribution(sample_results):
    analyzer = HTTPAnalyzer(sample_results)
    dist = analyzer.get_protocol_distribution()
    protocols = {d["protocol"] for d in dist}
    assert protocols == {"HTTP/2", "unknown"}


def test_get_security_summary(sample_results):
    analyzer = HTTPAnalyzer(sample_results)
    sec = analyzer.get_security_summary()
    assert sec["security_header_counts"]["strict-transport-security"] == 1
    assert "Cloudflare" in sec["cdn_distribution"]


def test_get_status_code_distribution(sample_results):
    analyzer = HTTPAnalyzer(sample_results)
    codes = analyzer.get_status_code_distribution()
    assert any(c["status_code"] == 200 for c in codes)


def test_get_error_statistics(sample_results):
    analyzer = HTTPAnalyzer(sample_results)
    errors = analyzer.get_error_statistics()
    assert "Request timeout" in errors


def create_success_result(total_ms: float) -> HTTPResult:
    return HTTPResult(
        target="https://example.com",
        method="GET",
        start_time=1.0,
        end_time=1.0 + total_ms / 1000.0,
        total_ms=total_ms,
        status=QueryStatus.SUCCESS,
        iteration=1,
        attempt_number=1,
        http_status_code=200,
        protocol=HTTPProtocol.HTTP2,
    )


# ---------------------------------------------------------------------------
# 0.5.2 — measurement mask (`responded`) vs outcome mask (`completed`)
#
# Regression cover for: a run whose responses all carried an unexpected status
# reported "Avg latency 0.00 ms" / "HTTP/2 rate 0.0%" / "Fastest target: N/A"
# while the raw CSV alongside it held perfectly good samples. The engine marks
# a non-expected status as QueryStatus.UNKNOWN_ERROR, and every aggregate
# filtered on that verdict rather than on whether a response arrived.
# ---------------------------------------------------------------------------


def unexpected_status_result(
    iteration: int, total_ms: float, ttfb_ms: float, code: int = 403
) -> HTTPResult:
    """A fully measured response that the caller did not ask for.

    This is what HTTPBenchmarkEngine produces for a 403 when
    expected_statuses={200, 401}: status is UNKNOWN_ERROR, but every timing
    field, the negotiated protocol and all response headers are populated.
    """
    return HTTPResult(
        target="https://api.github.com/user",
        method="GET",
        start_time=1000.0,
        end_time=1000.0 + total_ms / 1000.0,
        total_ms=total_ms,
        status=QueryStatus.UNKNOWN_ERROR,
        iteration=iteration,
        attempt_number=1,
        http_status_code=code,
        protocol=HTTPProtocol.HTTP2,
        alpn_negotiated="h2",
        ttfb_ms=ttfb_ms,
        response_size_bytes=278,
        server_header="Varnish",
        security_headers={"strict-transport-security": "max-age=31536000"},
        ip_version="IPv4",
    )


def transport_failure_result(iteration: int) -> HTTPResult:
    """No response at all — no http_status_code. total_ms is the timeout
    budget, which must never reach a latency mean."""
    return HTTPResult(
        target="https://api.github.com/user",
        method="GET",
        start_time=1000.0,
        end_time=1010.0,
        total_ms=10000.0,
        status=QueryStatus.TIMEOUT,
        iteration=iteration,
        attempt_number=1,
        error_message="Request timeout",
    )


@pytest.fixture
def all_unexpected_results() -> List[HTTPResult]:
    """Ten 403s with real timings — the reported reproduction."""
    samples = [
        (322.6, 321.8),
        (419.9, 418.5),
        (371.2, 370.2),
        (438.2, 436.7),
        (440.3, 437.4),
        (443.4, 441.3),
        (442.1, 440.0),
        (416.0, 414.8),
        (417.3, 415.2),
        (419.1, 418.0),
    ]
    return [unexpected_status_result(i + 1, t, f) for i, (t, f) in enumerate(samples)]


class TestRespondedMask:
    def test_latency_survives_unexpected_status(self, all_unexpected_results):
        """The bug: 10 measured responses, avg latency reported as 0.00 ms."""
        a = HTTPAnalyzer(all_unexpected_results, expected_statuses={200, 401})
        overall = a.get_overall_statistics()

        assert overall["successful_requests"] == 0  # correct: 403 is not expected
        assert overall["responded_requests"] == 10
        assert overall["overall_avg_latency"] == pytest.approx(413.01, abs=0.01)
        assert overall["overall_avg_ttfb"] == pytest.approx(411.39, abs=0.01)

    def test_protocol_and_ranking_survive_unexpected_status(
        self, all_unexpected_results
    ):
        overall = HTTPAnalyzer(
            all_unexpected_results, expected_statuses={200, 401}
        ).get_overall_statistics()
        assert overall["http2_rate"] == 100.0
        assert overall["fastest_target"] == "https://api.github.com/user"
        assert overall["slowest_target"] == "https://api.github.com/user"

    def test_summary_masks_are_consistent(self, all_unexpected_results):
        """HSTS coverage and HTTP/2 rate must not disagree about the same rows.

        The original symptom was "HSTS coverage 100.0%" printed directly above
        "HTTP/2 rate 0.0%" for ten HTTP/2 responses that all carried HSTS.
        """
        overall = HTTPAnalyzer(
            all_unexpected_results, expected_statuses={200, 401}
        ).get_overall_statistics()
        assert overall["hsts_coverage"] == 100.0
        assert overall["http2_rate"] == 100.0

    def test_target_stats_classification(self, all_unexpected_results):
        s = HTTPAnalyzer(
            all_unexpected_results, expected_statuses={200, 401}
        ).get_target_statistics()[0]
        assert s.total_requests == 10
        assert s.responded_requests == 10
        assert s.successful_requests == 0
        assert s.transport_error_rate == 0.0
        assert s.unexpected_status_rate == 100.0
        assert s.expected_response_rate == 0.0
        assert s.p95_latency > 0.0
        assert s.avg_ttfb_ms > 0.0

    def test_transport_failure_excluded_from_latency(self, all_unexpected_results):
        """A timeout's total_ms is a budget, not a sample — it must stay out."""
        results = all_unexpected_results + [transport_failure_result(11)]
        a = HTTPAnalyzer(results, expected_statuses={200, 401})
        overall = a.get_overall_statistics()

        assert overall["total_requests"] == 11
        assert overall["responded_requests"] == 10
        # unchanged by the 10000 ms timeout
        assert overall["overall_avg_latency"] == pytest.approx(413.01, abs=0.01)

        s = a.get_target_statistics()[0]
        assert s.transport_error_rate == pytest.approx(9.09, abs=0.01)
        assert s.unexpected_status_rate == pytest.approx(90.91, abs=0.01)

    def test_responded_never_below_successful(self, sample_results):
        """Invariant: responded_requests >= successful_requests, always."""
        for s in HTTPAnalyzer(sample_results).get_target_statistics():
            assert s.responded_requests >= s.successful_requests

    def test_expected_statuses_makes_them_successful(self, all_unexpected_results):
        """With 403 declared expected, outcome and measurement agree again."""
        a = HTTPAnalyzer(all_unexpected_results, expected_statuses={200, 403})
        s = a.get_target_statistics()[0]
        assert s.responded_requests == 10
        assert s.expected_response_rate == 100.0
        assert s.unexpected_status_rate == 0.0


class TestErrorStatisticsLabelling:
    def test_unexpected_status_keyed_by_code(self, all_unexpected_results):
        """Was {"": 10} — a blank key, because a 403 sets no error_message."""
        errors = HTTPAnalyzer(
            all_unexpected_results, expected_statuses={200, 401}
        ).get_error_statistics()
        assert errors == {"HTTP 403": 10}
        assert "" not in errors

    def test_transport_failure_keyed_by_message(self, all_unexpected_results):
        errors = HTTPAnalyzer(
            all_unexpected_results + [transport_failure_result(11)],
            expected_statuses={200, 401},
        ).get_error_statistics()
        assert errors == {"HTTP 403": 10, "Request timeout": 1}


class TestThresholdNamespace:
    def test_latency_thresholds_usable_without_successes(self, all_unexpected_results):
        """`--threshold 'p95_latency<500'` used to fail with "unknown metric"
        against a run that had measured p95 ten times over, because the
        namespace gate keyed on successful_requests."""
        s = HTTPAnalyzer(
            all_unexpected_results, expected_statuses={200, 401}
        ).get_target_statistics()[0]
        ns = build_metric_namespace(s)

        assert "p95_latency" in ns
        assert ns["p95_latency"] > 0.0
        assert ns["responded_requests"] == 10.0
        assert ns["expected_response_rate"] == 0.0

        result = evaluate_thresholds([parse_threshold("p95_latency<500")], ns)[0]
        assert result.passed is True
        assert result.error is None

    def test_sample_metrics_dropped_when_nothing_responded(self):
        """No response at all still means no samples — the gate must hold."""
        s = HTTPAnalyzer([transport_failure_result(1)]).get_target_statistics()[0]
        ns = build_metric_namespace(s)

        assert s.responded_requests == 0
        assert "p95_latency" not in ns
        assert "avg_latency" not in ns
        # classification metrics are not sample-dependent and must survive
        assert ns["transport_error_rate"] == 100.0


class TestLatencyHistogram:
    """Tests for the mergeable latency histogram (0.5.2)."""

    def test_record_and_quantile(self):
        h = LatencyHistogram()
        for v in [10, 20, 30, 40, 50]:
            h.record(v)
        assert h.count == 5
        assert h.min_ms == 10
        assert h.max_ms == 50
        assert h.mean == 30.0
        q50 = h.quantile(0.5)
        assert 25 <= q50 <= 35  # approximate bucket midpoint
        assert h.quantile(0.0) == 10
        assert h.quantile(1.0) == 50

    def test_overflow(self):
        h = LatencyHistogram(max_exponent=2)  # 0.01*4 = 0.04 ms ceiling
        h.record(100)  # far exceeds representable range
        assert h.overflow_count == 1
        assert h.count == 1
        assert h.max_ms == 100

    def test_nan_and_negative(self):
        h = LatencyHistogram()
        h.record(float("nan"))
        h.record(-5)
        assert h.count == 1
        assert h.min_ms == 0.0  # negative clamped to 0

    def test_merge(self):
        h1 = LatencyHistogram.from_values([10, 20])
        h2 = LatencyHistogram.from_values([30, 40])
        merged = h1.merge(h2)
        assert merged.count == 4
        assert merged.min_ms == 10
        assert merged.max_ms == 40
        assert merged.total == 100

    def test_merge_mismatched_layouts_raises(self):
        h1 = LatencyHistogram(lowest_ms=0.01)
        h2 = LatencyHistogram(lowest_ms=0.1)
        with pytest.raises(ValueError, match="cannot merge"):
            h1.merge(h2)

    def test_merge_all(self):
        h1 = LatencyHistogram.from_values([1, 2])
        h2 = LatencyHistogram.from_values([3, 4])
        h3 = LatencyHistogram.from_values([5, 6])
        merged = LatencyHistogram.merge_all([h1, h2, h3])
        assert merged.count == 6
        assert merged.min_ms == 1
        assert merged.max_ms == 6

    def test_merge_all_empty(self):
        assert LatencyHistogram.merge_all([]).count == 0

    def test_to_dict_and_from_dict_roundtrip(self):
        h = LatencyHistogram.from_values([10, 20, 30, 300, 5000])
        d = h.to_dict()
        h2 = LatencyHistogram.from_dict(d)
        assert h2.count == h.count
        assert h2.min_ms == h.min_ms
        assert h2.max_ms == h.max_ms
        assert h2.total == h.total
        assert h2.overflow_count == h.overflow_count
        assert dict(h2.counts) == dict(h.counts)

    def test__index_and__bounds(self):
        h = LatencyHistogram(lowest_ms=1.0, sub_buckets=4, max_exponent=4)
        # value 1.0 -> _index 0, bounds 1.0 to 1.0*(1+1/4)=1.25
        idx = h._index(1.0)
        assert idx == 0
        lo, hi = h._bounds(idx)
        assert lo == 1.0
        assert hi == 1.25
        # value 2.0 -> exponent=1 (log2(2/1)=1), frac=0 -> slice 0 -> index 1*4+0=4
        idx2 = h._index(2.0)
        assert idx2 == 4
        lo2, hi2 = h._bounds(idx2)
        assert lo2 == 2.0
        assert hi2 == 2.0 * (1.0 + 1 / 4)  # 2.5

    def test_empty_quantile(self):
        h = LatencyHistogram()
        assert h.quantile(0.5) == 0.0
        assert h.quantile(0.0) == 0.0
        assert h.quantile(1.0) == 0.0


class TestEvaluateThresholds:
    """0.5.2 threshold evaluation logic."""

    def test_valid_threshold_passes(self):
        ns = {"p95_latency": 120.0}
        results = evaluate_thresholds([parse_threshold("p95_latency<500")], ns)
        assert len(results) == 1
        assert results[0].passed is True
        assert results[0].actual == 120.0

    def test_valid_threshold_fails(self):
        ns = {"error_rate": 5.2}
        results = evaluate_thresholds([parse_threshold("error_rate<=1")], ns)
        assert results[0].passed is False
        assert results[0].actual == 5.2

    def test_unknown_metric_fails(self):
        ns = {"p95_latency": 100.0}
        results = evaluate_thresholds([parse_threshold("nonexistent<10")], ns)
        assert results[0].passed is False
        assert "unknown metric" in results[0].error

    def test_sample_dependent_metric_missing_fails_with_reason(self):
        # When responded_requests=0, p95_latency is removed from namespace.
        ns = {"responded_requests": 0.0}
        results = evaluate_thresholds([parse_threshold("p95_latency<500")], ns)
        assert results[0].passed is False
        assert "no successful requests" in results[0].error
        assert results[0].actual is None

    def test_thresholds_passed_all_true(self):
        results = [
            ThresholdResult(threshold=parse_threshold("a<5"), actual=1, passed=True)
        ]
        assert thresholds_passed(results) is True

    def test_thresholds_passed_one_false(self):
        results = [
            ThresholdResult(threshold=parse_threshold("a<5"), actual=10, passed=False)
        ]
        assert thresholds_passed(results) is False


class TestGroupedStatistics:
    """0.5.2 get_grouped_statistics method."""

    def test_group_by_protocol(self, sample_results):
        analyzer = HTTPAnalyzer(sample_results)
        groups = analyzer.get_grouped_statistics(by=["protocol"])
        # sample_results has one HTTP/2 and one unknown (timeout has protocol unknown)
        assert len(groups) >= 1
        keys = [g[0] for g in groups]
        assert {"protocol": "HTTP/2"} in keys or {"protocol": "http2"} in keys

    def test_group_by_connection_reused(self, sample_results):
        analyzer = HTTPAnalyzer(sample_results)
        groups = analyzer.get_grouped_statistics(by=["connection_reused"])
        for key, st in groups:
            assert key["connection_reused"] is False
            assert st.total_requests > 0

    def test_invalid_group_column_raises(self, sample_results):
        analyzer = HTTPAnalyzer(sample_results)
        with pytest.raises(ValueError, match="cannot group"):
            analyzer.get_grouped_statistics(by=["nonexistent"])

    def test_empty_results_returns_empty(self):
        analyzer = HTTPAnalyzer([])
        groups = analyzer.get_grouped_statistics(by=["protocol"])
        assert groups == []

    def test_no_by_returns_same_as_target_stats(self, sample_results):
        analyzer = HTTPAnalyzer(sample_results)
        groups = analyzer.get_grouped_statistics(by=[])
        stats = analyzer.get_target_statistics()
        assert len(groups) == len(stats)
        assert groups[0][1].total_requests == stats[0].total_requests


class TestThresholdsReport:
    """0.5.2 get_thresholds_report."""

    def test_report_per_target(self, sample_results):
        analyzer = HTTPAnalyzer(sample_results)
        report = analyzer.get_thresholds_report([parse_threshold("avg_latency<200")])
        assert len(report) == 1  # one target
        for target, results in report.items():
            assert target == "https://example.com"
            assert results[0].passed is True  # avg_latency=100

    def test_report_with_extra_metrics(self, sample_results):
        analyzer = HTTPAnalyzer(sample_results)
        report = analyzer.get_thresholds_report(
            [parse_threshold("custom_metric==42")],
            extra_metrics={"custom_metric": 42.0},
        )
        results = report["https://example.com"]
        assert results[0].passed is True

    def test_report_includes_duration_metrics(self, sample_results):
        analyzer = HTTPAnalyzer(sample_results)
        report = analyzer.get_thresholds_report(
            [parse_threshold("rps>0")], duration_s=2.0
        )
        results = report["https://example.com"]
        assert results[0].passed is True
