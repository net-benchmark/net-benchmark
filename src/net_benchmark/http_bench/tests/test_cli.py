"""CLI integration tests for http benchmark commands."""

import os
from unittest.mock import AsyncMock, MagicMock

import pytest
from click.testing import CliRunner

from net_benchmark.http_bench.analysis import TargetStats
from net_benchmark.http_bench.cli import http
from net_benchmark.http_bench.core import (
    HTTPProtocol,
    HTTPResult,
    QueryStatus,
    TargetManager,
)
from net_benchmark.http_bench.load_test import (
    ConnectionReuseStats,
    LoadTestMode,
    LoadTestSummary,
)

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def make_success_result(target="https://example.com", total_ms=100):
    """Create a minimal successful HTTPResult for test purposes."""
    return HTTPResult(
        target=target,
        method="GET",
        start_time=1.0,
        end_time=1.0 + total_ms / 1000.0,
        total_ms=total_ms,
        status=QueryStatus.SUCCESS,
        iteration=1,
        attempt_number=1,
        http_status_code=200,
        protocol=HTTPProtocol.HTTP2,
        alpn_negotiated="h2",
        ttfb_ms=50.0,
        response_size_bytes=1024,
        compressed=True,
        content_encoding="gzip",
        content_type="text/html",
        security_headers={"strict-transport-security": "max-age=31536000"},
        cdn_fingerprint="Cloudflare",
        server_header="cloudflare",
        cert_expiry_days=365,
        cert_cn="example.com",
        ip_version="IPv4",
        tcp_connect_ms=10.0,
        tls_handshake_ms=20.0,
        dns_resolve_ms=5.0,
        dns_resolver_ip="8.8.8.8",
        cache_control="public, max-age=3600",
        etag='"abc"',
        last_modified="Wed, 21 Oct 2015 07:28:00 GMT",
        age="123",
        assertion_results={},
    )


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def mock_run_benchmark(monkeypatch):
    """Fixture that patches HTTPBenchmarkEngine.run_benchmark to return a list of fake results."""

    async def _mock_run(self, targets, iterations=1, warmup=False, warmup_fast=False):
        # Return one success per target per iteration
        results = []
        for i in range(iterations):
            for t in targets:
                results.append(make_success_result(target=t))
        return results

    monkeypatch.setattr(
        "net_benchmark.http_bench.cli.HTTPBenchmarkEngine.run_benchmark",
        _mock_run,
    )
    # Also mock close to avoid warnings
    monkeypatch.setattr(
        "net_benchmark.http_bench.cli.HTTPBenchmarkEngine.close",
        AsyncMock(),
    )


# Inside mock_load_test_components fixture
@pytest.fixture
def mock_load_test_components(monkeypatch):
    # Patch engine classes in cli
    monkeypatch.setattr("net_benchmark.http_bench.cli.HTTPBenchmarkEngine", MagicMock())
    mock_engine_cls = MagicMock()
    monkeypatch.setattr("net_benchmark.http_bench.cli.LoadTestEngine", mock_engine_cls)

    # Patch exporter references directly in the cli module (where they are used)
    monkeypatch.setattr("net_benchmark.http_bench.cli.LoadTestCSVExporter", MagicMock())
    monkeypatch.setattr(
        "net_benchmark.http_bench.cli.LoadTestExcelExporter", MagicMock()
    )
    monkeypatch.setattr("net_benchmark.http_bench.cli.LoadTestPDFExporter", MagicMock())
    monkeypatch.setattr(
        "net_benchmark.http_bench.cli.LoadTestExportBundle", MagicMock()
    )

    # Configure mock engine
    def _engine_factory(target, http_engine=None):
        engine = MagicMock()
        engine.run_throughput = AsyncMock()
        engine.run_sustained = AsyncMock()
        engine.run_ramp_up = AsyncMock()
        engine.close = AsyncMock()
        engine.run_throughput.return_value = make_summary(target=target)
        engine.run_sustained.return_value = make_summary(
            target=target, mode=LoadTestMode.SUSTAINED, target_rps=100.0
        )
        engine.run_ramp_up.return_value = make_summary(
            target=target, mode=LoadTestMode.RAMP_UP
        )
        return engine

    mock_engine_cls.side_effect = _engine_factory
    return mock_engine_cls


# ---------------------------------------------------------------------------
# Helpers for load test tests
# ---------------------------------------------------------------------------


def make_summary(
    target="https://example.com",
    mode=LoadTestMode.THROUGHPUT,
    total_requests=100,
    success_count=95,
    achieved_rps=50.0,
    target_rps=None,
    connections_opened=3,
) -> LoadTestSummary:
    """Construct a minimal LoadTestSummary that matches the real engine output."""
    stats = TargetStats(
        target=target,
        method="GET",
        total_requests=total_requests,
        successful_requests=success_count,
        success_rate=(success_count / total_requests * 100) if total_requests else 0.0,
        min_latency=5.0,
        max_latency=200.0,
        avg_latency=20.0,
        median_latency=15.0,
        std_latency=5.0,
        p95_latency=100.0,
        p99_latency=180.0,
        jitter=2.0,
        consistency_score=95.0,
        avg_ttfb_ms=10.0,
        p95_ttfb_ms=50.0,
        http2_rate=80.0,
        redirect_rate=10.0,
        avg_response_size_bytes=2048.0,
        avg_dns_ms=3.0,
        avg_tcp_ms=5.0,
        avg_tls_ms=12.0,
        avg_compressed_size_bytes=1500.0,
        avg_redirect_time_ms=0.0,
        http2_downgrade_rate=0.0,
        cache_control_present=50,
        etag_present=40,
        last_modified_present=30,
        age_present=10,
        hsts_present=80,
        csp_present=60,
        cdn_fingerprint="Cloudflare",
        server_header="nginx",
        cert_expiry_days_min=365,
        alt_svc='h3=":443"',
        ip_version="IPv4",
        connection_reuse_rate=25.0,
        tls_resumption_rate=40.0,
        http2_push_total=0,
        avg_upload_throughput_mbps=0.0,
    )

    reuse = ConnectionReuseStats(
        total_requests=total_requests,
        connections_opened=connections_opened,
    )

    status_dist = [
        {
            "status_code": 200,
            "count": success_count,
            "pct": round(success_count / total_requests * 100, 2),
        },
        {
            "status_code": 500,
            "count": total_requests - success_count,
            "pct": round((total_requests - success_count) / total_requests * 100, 2),
        },
    ]

    return LoadTestSummary(
        mode=mode,
        target=target,
        duration_s=2.0,
        target_rps=target_rps,
        stats=stats,
        status_code_distribution=status_dist,
        connection_reuse=reuse,
        intervals=[],
        results=[],
    )


# ---------------------------------------------------------------------------
# benchmark command
# ---------------------------------------------------------------------------


class TestBenchmark:
    def test_missing_targets(self, runner):
        result = runner.invoke(http, ["benchmark"])
        assert result.exit_code == 0
        assert "Provide --targets" in result.output

    def test_use_defaults(self, runner, mock_run_benchmark):
        result = runner.invoke(http, ["benchmark", "--use-defaults", "--quiet"])
        assert result.exit_code == 0
        # Should have created files
        assert os.path.exists("benchmark_results")
        # At least one CSV
        files = os.listdir("benchmark_results")
        assert any(f.endswith(".csv") for f in files)
        # Clean up
        for f in files:
            os.remove(os.path.join("benchmark_results", f))
        os.rmdir("benchmark_results")

    def test_invalid_format(self, runner):
        result = runner.invoke(
            http, ["benchmark", "--use-defaults", "--formats", "xml"]
        )
        assert result.exit_code == 0
        assert "Invalid format" in result.output

    def test_file_not_found(self, runner):
        result = runner.invoke(http, ["benchmark", "--targets", "nonexistent.txt"])
        assert result.exit_code == 0
        assert "Target file not found" in result.output

    def test_inline_targets(self, runner, mock_run_benchmark):
        result = runner.invoke(
            http,
            [
                "benchmark",
                "--targets",
                "https://a.com,https://b.com",
                "--iterations",
                "2",
                "--quiet",
            ],
        )
        assert result.exit_code == 0
        # Should have completed successfully

    def test_with_headers(self, runner, mock_run_benchmark):
        result = runner.invoke(
            http,
            [
                "benchmark",
                "--use-defaults",
                "--headers",
                "Authorization:Bearer token,X-Custom:value",
                "--quiet",
            ],
        )
        assert result.exit_code == 0

    def test_with_body(self, runner, mock_run_benchmark):
        result = runner.invoke(
            http,
            [
                "benchmark",
                "--use-defaults",
                "--method",
                "POST",
                "--body",
                '{"key":"value"}',
                "--quiet",
            ],
        )
        assert result.exit_code == 0

    def test_body_and_body_file_conflict(self, runner):
        result = runner.invoke(
            http,
            [
                "benchmark",
                "--use-defaults",
                "--body",
                "test",
                "--body-file",
                "payload.json",
            ],
        )
        assert result.exit_code == 0
        assert "Provide either --body or --body-file" in result.output

    def test_body_file_not_found(self, runner):
        result = runner.invoke(
            http, ["benchmark", "--use-defaults", "--body-file", "missing.json"]
        )
        assert result.exit_code == 0
        assert "Cannot read body file" in result.output

    def test_basic_auth(self, runner, mock_run_benchmark):
        result = runner.invoke(
            http,
            ["benchmark", "--use-defaults", "--auth", "basic:user:pass", "--quiet"],
        )
        assert result.exit_code == 0

    def test_bearer_auth(self, runner, mock_run_benchmark):
        result = runner.invoke(
            http,
            ["benchmark", "--use-defaults", "--auth", "bearer:token123", "--quiet"],
        )
        assert result.exit_code == 0

    def test_invalid_auth_format(self, runner):
        result = runner.invoke(
            http, ["benchmark", "--use-defaults", "--auth", "digest:user:pass"]
        )
        assert result.exit_code == 0
        assert "Unknown auth type" in result.output

    def test_invalid_basic_auth_format(self, runner):
        result = runner.invoke(
            http, ["benchmark", "--use-defaults", "--auth", "basic:user"]
        )
        assert result.exit_code == 0
        assert "Invalid basic auth format" in result.output

    def test_invalid_bearer_auth_format(self, runner):
        result = runner.invoke(
            http, ["benchmark", "--use-defaults", "--auth", "bearer"]
        )
        assert result.exit_code == 0
        assert "Invalid bearer auth format" in result.output

    def test_cookies(self, runner, mock_run_benchmark):
        result = runner.invoke(
            http,
            [
                "benchmark",
                "--use-defaults",
                "--cookie",
                "session=abc",
                "--cookie",
                "region=us",
                "--quiet",
            ],
        )
        assert result.exit_code == 0

    def test_invalid_cookie(self, runner):
        result = runner.invoke(
            http, ["benchmark", "--use-defaults", "--cookie", "invalid"]
        )
        assert result.exit_code == 0
        assert "Invalid cookie" in result.output

    def test_user_agent(self, runner, mock_run_benchmark):
        result = runner.invoke(
            http,
            ["benchmark", "--use-defaults", "--user-agent", "TestBot/1.0", "--quiet"],
        )
        assert result.exit_code == 0

    def test_proxy(self, runner, mock_run_benchmark):
        result = runner.invoke(
            http,
            ["benchmark", "--use-defaults", "--proxy", "http://proxy:8080", "--quiet"],
        )
        assert result.exit_code == 0

    def test_sni_override(self, runner, mock_run_benchmark):
        result = runner.invoke(
            http, ["benchmark", "--use-defaults", "--sni", "example.com", "--quiet"]
        )
        assert result.exit_code == 0

    def test_local_address(self, runner, mock_run_benchmark):
        result = runner.invoke(
            http,
            ["benchmark", "--use-defaults", "--local-address", "127.0.0.1", "--quiet"],
        )
        assert result.exit_code == 0

    def test_inject_request_id(self, runner, mock_run_benchmark):
        result = runner.invoke(
            http, ["benchmark", "--use-defaults", "--inject-request-id", "--quiet"]
        )
        assert result.exit_code == 0

    def test_assertions(self, runner, mock_run_benchmark):
        result = runner.invoke(
            http,
            [
                "benchmark",
                "--use-defaults",
                "--assert",
                "status=200",
                "--assert",
                "body_contains=test",
                "--assert",
                "header_exists=X-Cache",
                "--assert",
                "max_latency=1000",
                "--quiet",
            ],
        )
        assert result.exit_code == 0

    def test_invalid_assertion_format(self, runner):
        result = runner.invoke(
            http, ["benchmark", "--use-defaults", "--assert", "bad_assertion"]
        )
        assert result.exit_code == 0
        assert "Invalid assertion" in result.output

    def test_unknown_assertion_type(self, runner):
        result = runner.invoke(
            http, ["benchmark", "--use-defaults", "--assert", "unknown=value"]
        )
        assert result.exit_code == 0
        assert "Unknown assertion type" in result.output

    def test_max_latency_non_numeric(self, runner):
        result = runner.invoke(
            http, ["benchmark", "--use-defaults", "--assert", "max_latency=abc"]
        )
        assert result.exit_code == 0
        assert "max_latency must be a number" in result.output

    def test_json_export(self, runner, mock_run_benchmark):
        result = runner.invoke(
            http, ["benchmark", "--use-defaults", "--json", "--quiet"]
        )
        assert result.exit_code == 0
        # Should have created a JSON file
        files = os.listdir("benchmark_results")
        assert any(f.endswith(".json") for f in files)
        for f in files:
            os.remove(os.path.join("benchmark_results", f))
        os.rmdir("benchmark_results")

    def test_pdf_export_without_weasyprint(
        self, runner, mock_run_benchmark, monkeypatch
    ):
        # Simulate PDF export failure
        def mock_pdf_export(*args, **kwargs):
            raise RuntimeError("weasyprint not installed")

        monkeypatch.setattr(
            "net_benchmark.http_bench.cli.HTTPPDFExporter.export_results",
            mock_pdf_export,
        )
        result = runner.invoke(
            http, ["benchmark", "--use-defaults", "--formats", "pdf", "--quiet"]
        )
        assert result.exit_code == 0
        assert "PDF export failed" in result.output

    def test_warmup_fast(self, runner, mock_run_benchmark):
        result = runner.invoke(
            http, ["benchmark", "--use-defaults", "--warmup-fast", "--quiet"]
        )
        assert result.exit_code == 0

    def test_warmup_full(self, runner, mock_run_benchmark):
        result = runner.invoke(
            http, ["benchmark", "--use-defaults", "--warmup", "--quiet"]
        )
        assert result.exit_code == 0

    def test_no_http2(self, runner, mock_run_benchmark):
        result = runner.invoke(
            http, ["benchmark", "--use-defaults", "--no-http2", "--quiet"]
        )
        assert result.exit_code == 0

    def test_no_verify_ssl(self, runner, mock_run_benchmark):
        result = runner.invoke(
            http, ["benchmark", "--use-defaults", "--no-verify-ssl", "--quiet"]
        )
        assert result.exit_code == 0

    def test_include_charts(self, runner, mock_run_benchmark):
        result = runner.invoke(
            http, ["benchmark", "--use-defaults", "--include-charts", "--quiet"]
        )
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# monitoring command
# ---------------------------------------------------------------------------


class TestMonitoring:
    def test_missing_targets(self, runner):
        result = runner.invoke(http, ["monitoring"])
        assert result.exit_code == 0
        assert "Provide --targets" in result.output

    def test_use_defaults_one_cycle(self, runner, monkeypatch):
        # Mock the engine's run_benchmark and close to avoid real network
        async def mock_run(
            self, targets, iterations=1, warmup=False, warmup_fast=False
        ):
            return [make_success_result(t) for t in targets]

        monkeypatch.setattr(
            "net_benchmark.http_bench.cli.HTTPBenchmarkEngine.run_benchmark",
            mock_run,
        )
        monkeypatch.setattr(
            "net_benchmark.http_bench.cli.HTTPBenchmarkEngine.close",
            AsyncMock(),
        )
        # To stop after one cycle, we can set duration=1 (but duration check uses time.time, so we can just let it run one cycle and then interrupt with a side effect)
        # We'll use a side effect that raises KeyboardInterrupt after the first loop
        call_count = 0

        def limited_sleep(seconds):
            nonlocal call_count
            call_count += 1
            if call_count >= 1:
                raise KeyboardInterrupt()

        monkeypatch.setattr("time.sleep", limited_sleep)
        # Also mock time.time to avoid real waiting? Not needed because sleep is intercepted.
        result = runner.invoke(
            http, ["monitoring", "--use-defaults", "--interval", "0"]
        )
        assert result.exit_code == 0
        assert "Monitoring stopped by user" in result.output

    def test_invalid_targets_file(self, runner):
        result = runner.invoke(http, ["monitoring", "--targets", "nonexistent.txt"])
        assert result.exit_code == 0
        assert "Error loading targets" in result.output

    def test_with_alerts(self, runner, monkeypatch):
        async def mock_run(
            self, targets, iterations=1, warmup=False, warmup_fast=False
        ):
            return [make_success_result(t) for t in targets]

        monkeypatch.setattr(
            "net_benchmark.http_bench.cli.HTTPBenchmarkEngine.run_benchmark",
            mock_run,
        )
        monkeypatch.setattr(
            "net_benchmark.http_bench.cli.HTTPBenchmarkEngine.close",
            AsyncMock(),
        )
        # Force stop after one iteration
        monkeypatch.setattr("time.sleep", lambda s: exec("raise KeyboardInterrupt()"))
        result = runner.invoke(
            http,
            [
                "monitoring",
                "--use-defaults",
                "--alert-latency",
                "10",
                "--alert-failure-rate",
                "5",
                "--interval",
                "0",
            ],
        )
        assert result.exit_code == 0
        assert "Monitoring stopped by user" in result.output


# ---------------------------------------------------------------------------
# top command
# ---------------------------------------------------------------------------


class TestTop:
    def test_missing_targets(self, runner):
        result = runner.invoke(http, ["top"])
        assert result.exit_code == 0
        assert "Provide --targets" in result.output

    def test_use_defaults(self, runner, monkeypatch):
        # Mock the engine's run_benchmark to return a couple of results
        async def mock_run(self, *args, **kwargs):
            return [
                make_success_result(target="https://a.com", total_ms=100),
                make_success_result(target="https://b.com", total_ms=200),
            ]

        monkeypatch.setattr(
            "net_benchmark.http_bench.cli.HTTPBenchmarkEngine.run_benchmark",
            mock_run,
        )
        monkeypatch.setattr(
            "net_benchmark.http_bench.cli.HTTPBenchmarkEngine.close",
            AsyncMock(),
        )
        result = runner.invoke(http, ["top", "--use-defaults", "--limit", "2"])
        assert result.exit_code == 0
        # The output strips the scheme, so we check for the hostname
        assert "a.com" in result.output
        assert "b.com" in result.output

    def test_inline_targets(self, runner, monkeypatch):
        async def mock_run(self, *args, **kwargs):
            return [
                make_success_result(target="https://example.com", total_ms=50),
            ]

        monkeypatch.setattr(
            "net_benchmark.http_bench.cli.HTTPBenchmarkEngine.run_benchmark",
            mock_run,
        )
        monkeypatch.setattr(
            "net_benchmark.http_bench.cli.HTTPBenchmarkEngine.close",
            AsyncMock(),
        )
        result = runner.invoke(
            http, ["top", "--targets", "https://example.com", "--limit", "1"]
        )
        assert result.exit_code == 0
        assert "example.com" in result.output

    def test_file_not_found(self, runner):
        result = runner.invoke(http, ["top", "--targets", "nonexistent.txt"])
        assert result.exit_code == 0
        assert "Error loading targets" in result.output

    def test_metric_ttfb(self, runner, monkeypatch):
        async def mock_run(self, *args, **kwargs):
            return [
                make_success_result(target="https://a.com", total_ms=100),
            ]

        monkeypatch.setattr(
            "net_benchmark.http_bench.cli.HTTPBenchmarkEngine.run_benchmark",
            mock_run,
        )
        monkeypatch.setattr(
            "net_benchmark.http_bench.cli.HTTPBenchmarkEngine.close",
            AsyncMock(),
        )
        result = runner.invoke(
            http, ["top", "--use-defaults", "--metric", "ttfb", "--limit", "1"]
        )
        assert result.exit_code == 0

    def test_metric_success(self, runner, monkeypatch):
        async def mock_run(self, *args, **kwargs):
            return [
                make_success_result(target="https://a.com", total_ms=100),
                make_success_result(target="https://b.com", total_ms=200),
            ]

        monkeypatch.setattr(
            "net_benchmark.http_bench.cli.HTTPBenchmarkEngine.run_benchmark",
            mock_run,
        )
        monkeypatch.setattr(
            "net_benchmark.http_bench.cli.HTTPBenchmarkEngine.close",
            AsyncMock(),
        )
        result = runner.invoke(
            http, ["top", "--use-defaults", "--metric", "success", "--limit", "2"]
        )
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# compare command
# ---------------------------------------------------------------------------


class TestCompare:
    def test_need_at_least_two_targets(self, runner):
        result = runner.invoke(http, ["compare", "https://a.com"])
        assert result.exit_code == 0
        assert "Need at least 2 targets" in result.output

    def test_basic_comparison(self, runner, monkeypatch):
        async def mock_run(self, *args, **kwargs):
            return [
                make_success_result(target="https://a.com", total_ms=100),
                make_success_result(target="https://a.com", total_ms=110),
                make_success_result(target="https://b.com", total_ms=200),
                make_success_result(target="https://b.com", total_ms=190),
            ]

        monkeypatch.setattr(
            "net_benchmark.http_bench.cli.HTTPBenchmarkEngine.run_benchmark", mock_run
        )
        monkeypatch.setattr(
            "net_benchmark.http_bench.cli.HTTPBenchmarkEngine.close", AsyncMock()
        )
        # Do not use --quiet; we want to see the output
        result = runner.invoke(
            http, ["compare", "https://a.com", "https://b.com", "--iterations", "2"]
        )
        assert result.exit_code == 0
        assert "a.com" in result.output
        assert "b.com" in result.output

    def test_auto_scheme(self, runner, monkeypatch):
        async def mock_run(self, *args, **kwargs):
            targets = kwargs.get("targets", [])
            return [make_success_result(target=t) for t in targets]

        monkeypatch.setattr(
            "net_benchmark.http_bench.cli.HTTPBenchmarkEngine.run_benchmark", mock_run
        )
        monkeypatch.setattr(
            "net_benchmark.http_bench.cli.HTTPBenchmarkEngine.close", AsyncMock()
        )
        result = runner.invoke(
            http, ["compare", "example.com", "httpbin.org", "--iterations", "1"]
        )
        assert result.exit_code == 0
        assert "example.com" in result.output
        assert "httpbin.org" in result.output

    def test_show_details(self, runner, monkeypatch):
        async def mock_run(self, *args, **kwargs):
            return [
                make_success_result(target="https://a.com", total_ms=100),
                make_success_result(target="https://a.com", total_ms=110),
            ]

        monkeypatch.setattr(
            "net_benchmark.http_bench.cli.HTTPBenchmarkEngine.run_benchmark", mock_run
        )
        monkeypatch.setattr(
            "net_benchmark.http_bench.cli.HTTPBenchmarkEngine.close", AsyncMock()
        )
        result = runner.invoke(
            http,
            [
                "compare",
                "https://a.com",
                "https://b.com",
                "--iterations",
                "2",
                "--show-details",
            ],
        )
        assert result.exit_code == 0
        assert "Iter 1:" in result.output
        assert "Iter 2:" in result.output

    def test_headers_parsing(self, runner, monkeypatch):
        """Cover header parsing inside compare."""

        async def mock_run(self, *args, **kwargs):
            return [make_success_result(target="https://a.com") for _ in range(2)]

        monkeypatch.setattr(
            "net_benchmark.http_bench.cli.HTTPBenchmarkEngine.run_benchmark", mock_run
        )
        monkeypatch.setattr(
            "net_benchmark.http_bench.cli.HTTPBenchmarkEngine.close", AsyncMock()
        )
        result = runner.invoke(
            http,
            [
                "compare",
                "a.com",
                "b.com",
                "--headers",
                "X-Custom:value,Authorization:Bearer tok",
                "--iterations",
                "1",
                "--quiet",
            ],
        )
        assert result.exit_code == 0

    def test_body_file_success(self, runner, monkeypatch, tmp_path):
        """Cover body-file success path."""
        payload = tmp_path / "payload.json"
        payload.write_text('{"test":true}')

        async def mock_run(self, *args, **kwargs):
            return [make_success_result(target="https://a.com") for _ in range(2)]

        monkeypatch.setattr(
            "net_benchmark.http_bench.cli.HTTPBenchmarkEngine.run_benchmark", mock_run
        )
        monkeypatch.setattr(
            "net_benchmark.http_bench.cli.HTTPBenchmarkEngine.close", AsyncMock()
        )
        result = runner.invoke(
            http,
            [
                "compare",
                "a.com",
                "b.com",
                "--body-file",
                str(payload),
                "--iterations",
                "1",
                "--quiet",
            ],
        )
        assert result.exit_code == 0

    def test_body_file_not_found(self, runner):
        """Cover body-file error branch."""
        result = runner.invoke(
            http, ["compare", "a.com", "b.com", "--body-file", "nonexistent.json"]
        )
        assert result.exit_code == 0
        assert "Cannot read body file" in result.output

    def test_body_content_type_auto_json(self, runner, monkeypatch):
        """Cover auto JSON content-type detection."""

        async def mock_run(self, *args, **kwargs):
            return [make_success_result(target="https://a.com") for _ in range(2)]

        monkeypatch.setattr(
            "net_benchmark.http_bench.cli.HTTPBenchmarkEngine.run_benchmark", mock_run
        )
        monkeypatch.setattr(
            "net_benchmark.http_bench.cli.HTTPBenchmarkEngine.close", AsyncMock()
        )
        # Inline JSON body without content-type header
        result = runner.invoke(
            http,
            [
                "compare",
                "a.com",
                "b.com",
                "--body",
                '{"key":"val"}',
                "--iterations",
                "1",
                "--quiet",
            ],
        )
        assert result.exit_code == 0

    def test_body_file_json_extension(self, runner, monkeypatch, tmp_path):
        """Cover auto JSON content-type from .json file extension."""
        payload = tmp_path / "data.json"
        payload.write_text("{}")

        async def mock_run(self, *args, **kwargs):
            return [make_success_result(target="https://a.com") for _ in range(2)]

        monkeypatch.setattr(
            "net_benchmark.http_bench.cli.HTTPBenchmarkEngine.run_benchmark", mock_run
        )
        monkeypatch.setattr(
            "net_benchmark.http_bench.cli.HTTPBenchmarkEngine.close", AsyncMock()
        )
        result = runner.invoke(
            http,
            [
                "compare",
                "a.com",
                "b.com",
                "--body-file",
                str(payload),
                "--iterations",
                "1",
                "--quiet",
            ],
        )
        assert result.exit_code == 0

    def test_auth_basic_invalid(self, runner):
        """Cover invalid basic auth format in compare."""
        result = runner.invoke(
            http, ["compare", "a.com", "b.com", "--auth", "basic:user"]
        )
        assert result.exit_code == 0
        assert "Invalid basic auth format" in result.output

    def test_auth_bearer_invalid(self, runner):
        """Cover invalid bearer auth format."""
        result = runner.invoke(http, ["compare", "a.com", "b.com", "--auth", "bearer"])
        assert result.exit_code == 0
        assert "Invalid bearer auth format" in result.output

    def test_auth_unknown_type(self, runner):
        """Cover unknown auth type."""
        result = runner.invoke(
            http, ["compare", "a.com", "b.com", "--auth", "digest:user:pass"]
        )
        assert result.exit_code == 0
        assert "Unknown auth type" in result.output

    def test_cookie_invalid(self, runner):
        """Cover invalid cookie format."""
        result = runner.invoke(
            http, ["compare", "a.com", "b.com", "--cookie", "badcookie"]
        )
        assert result.exit_code == 0
        assert "Invalid cookie" in result.output

    def test_export_txt(self, runner, monkeypatch, tmp_path):
        """Cover .txt export branch."""

        async def mock_run(self, *args, **kwargs):
            return [
                make_success_result(target="https://a.com"),
                make_success_result(target="https://b.com"),
            ]

        monkeypatch.setattr(
            "net_benchmark.http_bench.cli.HTTPBenchmarkEngine.run_benchmark", mock_run
        )
        monkeypatch.setattr(
            "net_benchmark.http_bench.cli.HTTPBenchmarkEngine.close", AsyncMock()
        )
        out_file = tmp_path / "comp.txt"
        result = runner.invoke(
            http,
            [
                "compare",
                "a.com",
                "b.com",
                "--iterations",
                "1",
                "--quiet",
                "--output",
                str(out_file),
            ],
        )
        assert result.exit_code == 0
        assert out_file.exists()

    def test_export_json(self, runner, monkeypatch, tmp_path):
        """Cover JSON export branch explicitly (already exist but may need coverage)."""

        async def mock_run(self, *args, **kwargs):
            return [
                make_success_result(target="https://a.com"),
                make_success_result(target="https://b.com"),
            ]

        monkeypatch.setattr(
            "net_benchmark.http_bench.cli.HTTPBenchmarkEngine.run_benchmark", mock_run
        )
        monkeypatch.setattr(
            "net_benchmark.http_bench.cli.HTTPBenchmarkEngine.close", AsyncMock()
        )
        out_file = tmp_path / "comp.json"
        result = runner.invoke(
            http,
            [
                "compare",
                "a.com",
                "b.com",
                "--iterations",
                "1",
                "--quiet",
                "--output",
                str(out_file),
            ],
        )
        assert result.exit_code == 0
        assert out_file.exists()

    def test_export_csv(self, runner, monkeypatch, tmp_path):
        """Cover CSV export branch explicitly."""

        async def mock_run(self, *args, **kwargs):
            return [
                make_success_result(target="https://a.com"),
                make_success_result(target="https://b.com"),
            ]

        monkeypatch.setattr(
            "net_benchmark.http_bench.cli.HTTPBenchmarkEngine.run_benchmark", mock_run
        )
        monkeypatch.setattr(
            "net_benchmark.http_bench.cli.HTTPBenchmarkEngine.close", AsyncMock()
        )
        out_file = tmp_path / "comp.csv"
        result = runner.invoke(
            http,
            [
                "compare",
                "a.com",
                "b.com",
                "--iterations",
                "1",
                "--quiet",
                "--output",
                str(out_file),
            ],
        )
        assert result.exit_code == 0
        assert out_file.exists()

    def test_compare_interrupted(self, runner, monkeypatch):
        """Cover KeyboardInterrupt exception handling."""

        async def mock_run(self, *args, **kwargs):
            raise KeyboardInterrupt()

        monkeypatch.setattr(
            "net_benchmark.http_bench.cli.HTTPBenchmarkEngine.run_benchmark", mock_run
        )
        monkeypatch.setattr(
            "net_benchmark.http_bench.cli.HTTPBenchmarkEngine.close", AsyncMock()
        )
        result = runner.invoke(http, ["compare", "a.com", "b.com", "--iterations", "1"])
        assert result.exit_code == 0
        assert "Comparison interrupted by user" in result.output

    def test_compare_generic_exception(self, runner, monkeypatch):
        """Cover generic exception handling."""

        async def mock_run(self, *args, **kwargs):
            raise RuntimeError("test error")

        monkeypatch.setattr(
            "net_benchmark.http_bench.cli.HTTPBenchmarkEngine.run_benchmark", mock_run
        )
        monkeypatch.setattr(
            "net_benchmark.http_bench.cli.HTTPBenchmarkEngine.close", AsyncMock()
        )
        result = runner.invoke(http, ["compare", "a.com", "b.com", "--iterations", "1"])
        assert result.exit_code == 1
        assert "Error during comparison: test error" in result.output


# ---------------------------------------------------------------------------
# Load test command tests (0.5.1)
# ---------------------------------------------------------------------------


class TestLoadTest:
    def test_missing_targets(self, runner):
        result = runner.invoke(http, ["load-test"])
        assert result.exit_code == 0
        assert "Provide --targets or use --use-defaults" in result.output

    def test_invalid_format(self, runner):
        result = runner.invoke(
            http, ["load-test", "--use-defaults", "--formats", "xml"]
        )
        assert result.exit_code == 0
        assert "Invalid format 'xml'" in result.output

    def test_file_not_found(self, runner):
        result = runner.invoke(http, ["load-test", "--targets", "nonexistent.txt"])
        assert result.exit_code == 0
        assert "Target file not found" in result.output

    def test_sustained_missing_rps(self, runner):
        result = runner.invoke(
            http,
            [
                "load-test",
                "--use-defaults",
                "--mode",
                "sustained",
                "--duration",
                "5",
            ],
        )
        assert result.exit_code == 0
        assert "--mode sustained requires --rps" in result.output

    def test_throughput_mode_exports(self, runner, mock_load_test_components):
        result = runner.invoke(
            http,
            [
                "load-test",
                "--targets",
                "https://example.com",
                "--mode",
                "throughput",
                "--duration",
                "2",
                "--formats",
                "csv,excel,json",
                "--quiet",
            ],
        )
        assert result.exit_code == 0

        # Import the mocked exporters from cli
        from net_benchmark.http_bench.cli import (
            LoadTestCSVExporter,
            LoadTestExcelExporter,
            LoadTestExportBundle,
            LoadTestPDFExporter,
        )

        LoadTestCSVExporter.export_raw_results.assert_called_once()
        LoadTestCSVExporter.export_summary.assert_called_once()
        LoadTestCSVExporter.export_intervals.assert_called_once()
        LoadTestCSVExporter.export_error_breakdown.assert_called_once()
        LoadTestExcelExporter.export_results.assert_called_once()
        LoadTestExportBundle.export_json.assert_called_once()
        LoadTestPDFExporter.export_results.assert_not_called()

    def test_sustained_mode_summary_output(self, runner, mock_load_test_components):
        result = runner.invoke(
            http,
            [
                "load-test",
                "--targets",
                "https://example.com",
                "--mode",
                "sustained",
                "--rps",
                "100",
                "--duration",
                "2",
                "--enable-connection-reuse",
                "--formats",
                "csv",
            ],
        )
        assert result.exit_code == 0
        output = result.output
        assert "Mode:             sustained" in output
        assert "Target RPS:       100.0" in output
        assert "Achieved RPS:" in output
        assert "Connections open:" in output
        assert "Reuse rate:" in output
        assert "TLS resumption:" not in output

    def test_ramp_up_mode_config_output(self, runner, mock_load_test_components):
        result = runner.invoke(
            http,
            [
                "load-test",
                "--targets",
                "https://example.com",
                "--mode",
                "ramp-up",
                "--start-concurrency",
                "5",
                "--ramp-concurrency",
                "50",
                "--ramp-duration",
                "10",
                "--hold-duration",
                "5",
                "--formats",
                "csv",
            ],
        )
        assert result.exit_code == 0
        output = result.output
        assert "Concurrency:  5 -> 50" in output
        assert "Ramp:         10.0s, hold 5.0s" in output

    def test_feature_flags_config_message(self, runner, mock_load_test_components):
        result = runner.invoke(
            http,
            [
                "load-test",
                "--use-defaults",
                "--mode",
                "throughput",
                "--enable-connection-reuse",
                "--enable-tls-resumption",
                "--enable-push-detection",
                "--formats",
                "csv",
            ],
        )
        assert result.exit_code == 0
        output = result.output
        assert "Connection reuse tracking: on" in output
        assert "TLS resumption detection:  on" in output
        assert "HTTP/2 push detection:     on" in output

    def test_multiple_targets_create_separate_engines(
        self, runner, mock_load_test_components
    ):
        mock_cls = mock_load_test_components
        mock_cls.reset_mock()

        runner.invoke(
            http,
            [
                "load-test",
                "--targets",
                "https://a.com,https://b.com",
                "--mode",
                "throughput",
                "--duration",
                "2",
                "--formats",
                "csv",
                "--quiet",
            ],
        )
        assert mock_cls.call_count == 2
        calls = [c.args[0] for c in mock_cls.call_args_list]
        assert "https://a.com" in calls
        assert "https://b.com" in calls

    def test_use_defaults_targets(self, runner, mock_load_test_components):
        mock_cls = mock_load_test_components
        mock_cls.reset_mock()

        runner.invoke(
            http,
            [
                "load-test",
                "--use-defaults",
                "--mode",
                "throughput",
                "--duration",
                "2",
                "--formats",
                "csv",
                "--quiet",
            ],
        )
        expected = TargetManager.get_default_targets()
        assert mock_cls.call_count == len(expected)
        seen = [c.args[0] for c in mock_cls.call_args_list]
        for t in expected:
            assert t in seen

    def test_output_directory_creation(
        self, runner, mock_load_test_components, tmp_path
    ):
        out = tmp_path / "results"
        runner.invoke(
            http,
            [
                "load-test",
                "--targets",
                "https://example.com",
                "--output",
                str(out),
                "--formats",
                "csv",
                "--quiet",
            ],
        )
        assert out.exists()
        # Since exporters are mocked, no real files are written.
        # Verify that the exporter methods were called instead.
        from net_benchmark.http_bench.cli import LoadTestCSVExporter

        LoadTestCSVExporter.export_raw_results.assert_called_once()
