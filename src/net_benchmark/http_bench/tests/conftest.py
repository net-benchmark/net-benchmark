import time
from typing import List

import pytest

from net_benchmark.http_bench.analysis import HTTPAnalyzer
from net_benchmark.http_bench.core import (
    HTTPProtocol,
    HTTPResult,
    QueryStatus,
)


@pytest.fixture
def sample_success_result() -> HTTPResult:
    """A minimal successful result."""
    now = time.time()
    return HTTPResult(
        target="https://example.com",
        method="GET",
        start_time=now,
        end_time=now + 0.1,
        total_ms=100.0,
        status=QueryStatus.SUCCESS,
        iteration=1,
        attempt_number=1,
        http_status_code=200,
        protocol=HTTPProtocol.HTTP2,
        alpn_negotiated="h2",
        ttfb_ms=50.0,
        ttlb_ms=100.0,
        response_size_bytes=1024,
        compressed=True,
        content_encoding="gzip",
        content_type="text/html",
        security_headers={
            "strict-transport-security": "max-age=31536000",
            "content-security-policy": None,
        },
        cdn_fingerprint="Cloudflare",
        server_header="cloudflare",
        cert_expiry_days=365,
        cert_cn="example.com",
        alt_svc='h3=":443"',
        ip_version="IPv4",
        tcp_connect_ms=10.0,
        tls_handshake_ms=20.0,
        dns_resolve_ms=5.0,
        dns_resolver_ip="8.8.8.8",
        cache_control="public, max-age=3600",
        etag='"abc"',
        last_modified="Wed, 21 Oct 2015 07:28:00 GMT",
        age="123",
        assertion_results={"status_code": True},
    )


@pytest.fixture
def sample_error_result() -> HTTPResult:
    """A failed result."""
    now = time.time()
    return HTTPResult(
        target="https://example.com",
        method="GET",
        start_time=now,
        end_time=now + 5,
        total_ms=5000.0,
        status=QueryStatus.TIMEOUT,
        iteration=1,
        attempt_number=1,
        error_message="Request timeout",
    )


@pytest.fixture
def sample_results(sample_success_result, sample_error_result) -> List[HTTPResult]:
    """Mix of success and failure."""
    return [sample_success_result, sample_error_result]


@pytest.fixture
def analyzer(sample_results) -> HTTPAnalyzer:
    """HTTPAnalyzer instantiated with two results."""
    return HTTPAnalyzer(sample_results)
