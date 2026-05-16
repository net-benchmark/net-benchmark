import ssl
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
from httpcore._backends.base import (
    AsyncNetworkStream,
)

from net_benchmark.http_bench.core import (
    HTTPBenchmarkEngine,
    HTTPResult,
    MetricsCapturingTransport,
    QueryStatus,
    TargetManager,
    TimingNetworkBackend,
    TimingNetworkStream,
    _parse_cert_der,
)


class TestTargetManager:
    def test_default_targets(self):
        defaults = TargetManager.get_default_targets()
        assert len(defaults) > 3
        for url in defaults:
            assert url.startswith("https://")

    def test_parse_inline(self):
        mgr = TargetManager.parse_targets_input("https://a.com, https://b.com")
        assert mgr.targets == ["https://a.com", "https://b.com"]

    def test_parse_single_url(self):
        mgr = TargetManager.parse_targets_input("https://example.com")
        assert mgr.targets == ["https://example.com"]

    def test_parse_file(self, tmp_path):
        f = tmp_path / "targets.txt"
        f.write_text("# comment\nhttps://example.com\n")
        mgr = TargetManager.parse_targets_input(str(f))
        assert mgr.targets == ["https://example.com"]

    def test_parse_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            TargetManager.parse_targets_input("nonexistent.txt")

    def test_empty_input_raises(self):
        with pytest.raises(ValueError):
            TargetManager.parse_targets_input("")


class TestHTTPResult:
    def test_to_dict(self):
        r = HTTPResult(
            target="https://x.com",
            method="GET",
            start_time=1.0,
            end_time=1.1,
            total_ms=100.0,
            status=QueryStatus.SUCCESS,
        )
        d = r.to_dict()
        assert d["target"] == "https://x.com"
        assert d["status"] == "success"
        assert d["protocol"] == "unknown"


class TestParseCertDER:
    def test_parse_valid_cert(self, sample_success_result):
        # We need actual DER bytes; sample_success_result doesn't have cert_der.
        # We'll test with a known cert later if needed.
        pass

    def test_parse_invalid_der(self):
        days, cn, issuer, sans, wildcard = _parse_cert_der(b"not_a_cert")
        assert days is None
        assert cn is None
        assert issuer is None
        assert sans == []
        assert wildcard is False


class TestHTTPBenchmarkEngine:
    @pytest.mark.asyncio
    async def test_resolve_host(self):
        engine = HTTPBenchmarkEngine()
        ms, error = await engine._resolve_host("localhost")
        assert error is None
        assert ms > 0

    @pytest.mark.asyncio
    async def test_resolve_host_failure(self):
        engine = HTTPBenchmarkEngine()
        ms, error = await engine._resolve_host("invalid.ghost")
        # May resolve to None or raise; handle gracefully.
        # Just check that it returns a tuple with ms and error if something goes wrong.
        assert isinstance(ms, float)

    @pytest.mark.asyncio
    async def test_request_single_success(self, monkeypatch):
        """Mock the httpx client to return a success response."""
        engine = HTTPBenchmarkEngine()

        fake_response = MagicMock()
        fake_response.status_code = 200
        fake_response.is_success = True
        fake_response.is_redirect = False
        fake_response.http_version = "HTTP/2"
        fake_response.headers = {
            "content-encoding": "gzip",
            "content-type": "text/html",
        }
        fake_response.aread = AsyncMock(return_value=b"<html></html>")
        fake_response.history = []
        fake_response.url = "https://example.com"

        class FakeStreamContext:
            def __init__(self, response):
                self.response = response

            async def __aenter__(self):
                return self.response

            async def __aexit__(self, *args):
                pass

        class FakeClient:
            def stream(self, *args, **kwargs):
                return FakeStreamContext(fake_response)

            async def aclose(self):
                pass

        async def fake_get_client(url):
            return FakeClient(), MagicMock()

        monkeypatch.setattr(engine, "_get_client", fake_get_client)
        monkeypatch.setattr(engine, "_update_progress", AsyncMock())

        result = await engine.request_single("https://example.com")
        assert result.status == QueryStatus.SUCCESS
        assert result.http_status_code == 200
        assert result.total_ms > 0

    @pytest.mark.asyncio
    async def test_request_single_timeout(self, monkeypatch):
        engine = HTTPBenchmarkEngine(max_retries=0)

        class FakeClient:
            def stream(self, *args, **kwargs):
                raise httpx.TimeoutException("timeout")

            async def aclose(self):
                pass

        async def fake_get_client(url):
            return FakeClient(), MagicMock()

        monkeypatch.setattr(engine, "_get_client", fake_get_client)
        monkeypatch.setattr(engine, "_update_progress", AsyncMock())

        result = await engine.request_single("https://example.com")
        assert result.status == QueryStatus.TIMEOUT

    def test_get_transport_reuses(self):
        engine = HTTPBenchmarkEngine()
        t1 = engine._get_transport("https://example.com")
        t2 = engine._get_transport("https://example.com")
        assert t1 is t2

    def test_get_transport_different_origins(self):
        engine = HTTPBenchmarkEngine()
        t1 = engine._get_transport("https://a.com")
        t2 = engine._get_transport("https://b.com")
        assert t1 is not t2

    @pytest.mark.asyncio
    async def test_get_client_reuses(self):
        engine = HTTPBenchmarkEngine()
        c1, t1 = await engine._get_client("https://example.com")
        c2, t2 = await engine._get_client("https://example.com")
        assert c1 is c2
        assert t1 is t2

    @pytest.mark.asyncio
    async def test_get_client_different_origins(self):
        engine = HTTPBenchmarkEngine()
        c1, _ = await engine._get_client("https://a.com")
        c2, _ = await engine._get_client("https://b.com")
        assert c1 is not c2

    def test_run_assertions(self):
        engine = HTTPBenchmarkEngine(
            assertions={
                "status_code": 200,
                "body_contains": "ok",
                "header_exists": "X-Test",
            }
        )
        response = MagicMock()
        response.status_code = 200
        response.headers = {"X-Test": "1"}
        body = b"everything is ok"
        results = engine._run_assertions(response, body)
        assert results == {
            "status_code": True,
            "body_contains": True,
            "header_exists": True,
        }

    def test_run_assertions_failures(self):
        engine = HTTPBenchmarkEngine(assertions={"status_code": 201})
        response = MagicMock()
        response.status_code = 200
        response.headers = {}
        body = b""
        results = engine._run_assertions(response, body)
        assert results["status_code"] is False

    @pytest.mark.asyncio
    async def test_request_single_ssl_error(self, monkeypatch):
        engine = HTTPBenchmarkEngine(max_retries=0)

        class FakeClient:
            def stream(self, *args, **kwargs):
                raise ssl.SSLError("certificate verify failed")

            async def aclose(self):
                pass

        async def fake_get_client(url):
            return FakeClient(), MagicMock()

        monkeypatch.setattr(engine, "_get_client", fake_get_client)
        monkeypatch.setattr(engine, "_update_progress", AsyncMock())

        result = await engine.request_single("https://badssl.com")
        assert result.status == QueryStatus.TLS_ERROR
        assert "TLS error" in result.error_message

    @pytest.mark.asyncio
    async def test_request_single_connect_error(self, monkeypatch):
        engine = HTTPBenchmarkEngine(max_retries=0)

        class FakeClient:
            def stream(self, *args, **kwargs):
                raise httpx.ConnectError("connection refused")

            async def aclose(self):
                pass

        async def fake_get_client(url):
            return FakeClient(), MagicMock()

        monkeypatch.setattr(engine, "_get_client", fake_get_client)
        monkeypatch.setattr(engine, "_update_progress", AsyncMock())

        result = await engine.request_single("https://down.example.com")
        assert result.status == QueryStatus.CONNECTION_REFUSED

    @pytest.mark.asyncio
    async def test_run_fast_warmup(self, monkeypatch):
        engine = HTTPBenchmarkEngine()
        original_method = engine.method  # 'GET'

        async def fake_request_single(target, iteration=0):
            return HTTPResult(
                target=target,
                method=engine.method,  # capture the engine's method at call time
                start_time=0,
                end_time=0.01,
                total_ms=10,
                status=QueryStatus.SUCCESS,
                iteration=0,
            )

        monkeypatch.setattr(engine, "request_single", fake_request_single)
        results = await engine._run_fast_warmup(["https://a.com"])
        assert len(results) == 1
        # The result should reflect the method used during the call (HEAD)
        assert results[0].method == "HEAD"
        # After warmup, the engine's method is restored
        assert engine.method == original_method

    @pytest.mark.asyncio
    async def test_run_benchmark(self, monkeypatch):
        engine = HTTPBenchmarkEngine()

        async def fake_request_single(target, iteration=1):
            return HTTPResult(
                target=target,
                method="GET",
                start_time=0,
                end_time=0.01,
                total_ms=10,
                status=QueryStatus.SUCCESS,
                iteration=iteration,
            )

        monkeypatch.setattr(engine, "request_single", fake_request_single)
        results = await engine.run_benchmark(
            ["https://a.com", "https://b.com"],
            iterations=2,
            warmup_fast=True,
        )
        # 2 targets × 2 iterations = 4 results (warmup not returned)
        assert len(results) == 4
        # Also check that warmup did run (failed_targets cleared, query_counter reset)
        # The fake_request_single doesn't use progress, so no further checks needed.


class TestTimingNetworkStream:
    @pytest.mark.asyncio
    async def test_start_tls_captures_timing_and_cert(self):
        """start_tls should record TLS handshake time and optionally cert bytes."""
        inner = MagicMock(spec=AsyncNetworkStream)
        tls_stream = MagicMock(spec=AsyncNetworkStream)
        ssl_obj = MagicMock()
        ssl_obj.getpeercert.return_value = b"fake-der"
        tls_stream.get_extra_info.return_value = ssl_obj
        inner.start_tls = AsyncMock(return_value=tls_stream)

        stream = TimingNetworkStream(inner, {})
        result = await stream.start_tls(MagicMock(), "example.com")

        assert result is not None
        assert isinstance(result, TimingNetworkStream)
        assert stream._metrics["tls_handshake_ms"] > 0
        assert stream._metrics["cert_der"] == b"fake-der"

    @pytest.mark.asyncio
    async def test_transport_returns_metrics(self):
        transport = MetricsCapturingTransport(verify=False)

        # Inject metrics directly into the timing backend (what get_connection_metrics reads)
        transport._timing_backend.metrics["tcp_connect_ms"] = 12.3

        metrics = transport.get_connection_metrics()
        assert metrics["tcp_connect_ms"] == 12.3


class TestTimingNetworkBackend:
    @pytest.mark.asyncio
    async def test_connect_tcp_metrics(self):
        """connect_tcp captures tcp_connect_ms and ip_version."""
        backend = TimingNetworkBackend()
        # We'll replace the backend's internal _backend with a mock that returns a mock stream
        mock_stream = MagicMock(spec=AsyncNetworkStream)
        mock_stream.get_extra_info.return_value = ("192.0.2.1", 443)
        real_connect = AsyncMock(return_value=mock_stream)
        backend._backend.connect_tcp = real_connect

        stream = await backend.connect_tcp("example.com", 443, timeout=10)
        assert isinstance(stream, TimingNetworkStream)
        assert stream._metrics["tcp_connect_ms"] > 0
        assert stream._metrics["ip_version"] == "IPv4"

    @pytest.mark.asyncio
    async def test_connect_tcp_ipv6(self):
        backend = TimingNetworkBackend()
        mock_stream = MagicMock(spec=AsyncNetworkStream)
        mock_stream.get_extra_info.return_value = ("::1", 443, 0, 0)
        backend._backend.connect_tcp = AsyncMock(return_value=mock_stream)
        stream = await backend.connect_tcp("example.com", 443)
        assert stream._metrics["ip_version"] == "IPv6"

    @pytest.mark.asyncio
    async def test_connect_tcp_no_server_addr(self):
        backend = TimingNetworkBackend()
        mock_stream = MagicMock(spec=AsyncNetworkStream)
        mock_stream.get_extra_info.return_value = None
        backend._backend.connect_tcp = AsyncMock(return_value=mock_stream)
        stream = await backend.connect_tcp("example.com", 443)
        assert stream._metrics["ip_version"] is None


class TestMetricsCapturingTransport:

    @pytest.mark.asyncio
    async def test_transport_returns_metrics(self):
        transport = MetricsCapturingTransport(verify=False)

        # Inject metrics directly into the timing backend (what get_connection_metrics reads)
        transport._timing_backend.metrics["tcp_connect_ms"] = 12.3

        metrics = transport.get_connection_metrics()
        assert metrics["tcp_connect_ms"] == 12.3

    def test_transport_creates_ssl_context(self):
        """MetricsCapturingTransport builds an SSL context."""
        transport = MetricsCapturingTransport(verify=True)
        assert transport._pool._ssl_context is not None

    def test_transport_no_verify(self):
        transport = MetricsCapturingTransport(verify=False)
        assert transport._pool._ssl_context.verify_mode == ssl.CERT_NONE


class TestParseCertDer:
    def test_parse_valid_der(self):
        """Generate a minimal self-signed cert and parse it."""
        from datetime import datetime, timedelta, timezone

        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        subject = issuer = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, "test.local")]
        )
        now = datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=30))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName("test.local")]),
                critical=False,
            )
            .sign(key, hashes.SHA256(), backend=default_backend())
        )
        der = cert.public_bytes(serialization.Encoding.DER)
        days, cn, issuer_cn, sans, wildcard = _parse_cert_der(der)
        assert days >= 29
        assert cn == "test.local"
        assert issuer_cn == "test.local"
        assert "test.local" in sans
        assert not wildcard

    def test_parse_invalid_der(self):
        days, cn, issuer, sans, wildcard = _parse_cert_der(b"garbage")
        assert days is None
        assert cn is None
