from net_benchmark.http_bench.analysis import HTTPAnalyzer
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
