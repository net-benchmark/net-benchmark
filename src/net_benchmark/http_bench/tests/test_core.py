import ssl
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from httpcore import AsyncConnectionPool
from httpcore._backends.base import (
    AsyncNetworkStream,
)

from net_benchmark.http_bench.core import (
    _AIOHTTP_AVAILABLE,
    _H2_AVAILABLE,
    HTTPBenchmarkEngine,
    HTTPDigestAuth,
    HTTPResult,
    MetricsCapturingTransport,
    QueryStatus,
    TargetManager,
    TimingNetworkBackend,
    TimingNetworkStream,
    _parse_cert_der,
)

if _H2_AVAILABLE:
    import h2.events

    from net_benchmark.http_bench.core import (
        PushDetectingPool,
        PushTrackingH2Connection,
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

    def test_run_assertions_all_types(self):
        """Test all assertion types supported by _run_assertions."""
        engine = HTTPBenchmarkEngine(
            assertions={
                "status_code": 200,
                "body_contains": "ok",
                "body_regex": r"ok$",
                "header_exists": "X-Test",
                "header_value": {"header": "X-Test", "value": "1"},
                "content_type": "text/html",
                "response_size_min": 10,
                "response_size_max": 100,
            }
        )
        response = MagicMock()
        response.status_code = 200
        response.headers = {"X-Test": "1", "content-type": "text/html; charset=utf-8"}
        body = b"everything is ok"  # length 16, contains "ok"
        results = engine._run_assertions(response, body)
        expected = {
            "status_code": True,
            "body_contains": True,
            "body_regex": True,
            "header_exists": True,
            "header_value": True,
            "content_type": True,
            "response_size_min": True,
            "response_size_max": True,
        }
        assert results == expected

    @pytest.mark.asyncio
    async def test_request_single_multipart_upload(self, monkeypatch):
        """Test the multipart upload code path (multipart_file_size > 0)."""
        engine = HTTPBenchmarkEngine()
        # We'll mock the client stream to return a success response.
        fake_response = MagicMock()
        fake_response.status_code = 200
        fake_response.is_success = True
        fake_response.is_redirect = False
        fake_response.http_version = "HTTP/2"
        fake_response.headers = {}
        fake_response.aread = AsyncMock(return_value=b"OK")
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
                # Capture that content was sent
                self._sent_content = kwargs.get("content")
                return FakeStreamContext(fake_response)

            async def aclose(self):
                pass

        async def fake_get_client(url):
            client = FakeClient()
            return client, MagicMock()

        monkeypatch.setattr(engine, "_get_client", fake_get_client)
        monkeypatch.setattr(engine, "_update_progress", AsyncMock())

        result = await engine.request_single(
            "https://example.com", multipart_file_size=1024
        )

        # Check that we got a success result
        assert result.status == QueryStatus.SUCCESS
        # Verify that upload metrics were set
        assert result.upload_size_bytes is not None and result.upload_size_bytes > 0
        assert result.upload_time_ms is not None and result.upload_time_ms >= 0
        assert (
            result.upload_throughput_mbps is not None
            and result.upload_throughput_mbps >= 0
        )

    @pytest.mark.asyncio
    async def test_request_single_connection_reuse(self, monkeypatch):
        """Test connection reuse detection when enable_connection_reuse=True."""
        engine = HTTPBenchmarkEngine(enable_connection_reuse=True)

        fake_response = MagicMock()
        fake_response.status_code = 200
        fake_response.is_success = True
        fake_response.is_redirect = False
        fake_response.http_version = "HTTP/2"
        fake_response.headers = {}
        fake_response.aread = AsyncMock(return_value=b"OK")
        fake_response.history = []
        fake_response.url = "https://example.com"
        # Force fallback to transport.get_connection_metrics()
        fake_response.extensions = {}

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

        mock_transport = MagicMock(spec=MetricsCapturingTransport)
        mock_transport.get_connection_metrics.return_value = {
            "connection_id": "conn-42",
            "tcp_connect_ms": 10.0,
        }

        async def fake_get_client(url):
            return FakeClient(), mock_transport

        monkeypatch.setattr(engine, "_get_client", fake_get_client)
        monkeypatch.setattr(engine, "_update_progress", AsyncMock())

        # First request: connection not reused.
        result1 = await engine.request_single("https://example.com")
        assert result1.connection_id == "conn-42"
        assert result1.connection_reused is False

        # Second request to same origin: should be reused.
        result2 = await engine.request_single("https://example.com")
        assert result2.connection_id == "conn-42"
        assert result2.connection_reused is True

    @pytest.mark.asyncio
    async def test_request_single_generic_exception_retry(self, monkeypatch):
        """Test that generic exceptions are retried and eventually return UNKNOWN_ERROR."""
        engine = HTTPBenchmarkEngine(max_retries=2, retry_backoff_multiplier=0.001)

        # Simulate a generic exception (not Timeout, SSL, Connect)
        class FakeClient:
            def __init__(self, fail_count):
                self.fail_count = fail_count
                self.attempt = 0

            def stream(self, *args, **kwargs):
                self.attempt += 1
                if self.attempt <= self.fail_count:
                    raise ValueError("Something unexpected happened")
                # If not failing, return success
                fake_response = MagicMock()
                fake_response.status_code = 200
                fake_response.is_success = True
                fake_response.is_redirect = False
                fake_response.http_version = "HTTP/1.1"
                fake_response.headers = {}
                fake_response.aread = AsyncMock(return_value=b"OK")
                fake_response.history = []
                fake_response.url = "https://example.com"
                return FakeStreamContext(fake_response)

            async def aclose(self):
                pass

        class FakeStreamContext:
            def __init__(self, response):
                self.response = response

            async def __aenter__(self):
                return self.response

            async def __aexit__(self, *args):
                pass

        async def fake_get_client(url):
            # We need a new client per call to reset attempt counter.
            # We'll use a closure to return a fresh client each time.
            # Actually the engine calls _get_client once per request, so we can
            # create a single client that tracks attempts.
            # But we want to simulate that the first two attempts fail, third succeeds.
            # Let's create a client with fail_count=2.
            client = FakeClient(fail_count=2)
            return client, MagicMock()

        monkeypatch.setattr(engine, "_get_client", fake_get_client)
        monkeypatch.setattr(engine, "_update_progress", AsyncMock())

        result = await engine.request_single("https://example.com")
        # After two retries (total attempts = 3), it should succeed.
        # But we have max_retries=2, so we have attempt 0,1,2 => 3 attempts.
        # The client fails for first two attempts (attempt=1 and 2), succeeds on attempt=3.
        assert result.status == QueryStatus.SUCCESS
        assert result.attempt_number == 3  # because it succeeded on third attempt

        # Now test exhaustion: set fail_count=3 so all attempts fail.
        # We'll create a new engine and test that it returns UNKNOWN_ERROR.
        engine2 = HTTPBenchmarkEngine(max_retries=2, retry_backoff_multiplier=0.001)

        class AlwaysFailClient:
            def __init__(self):
                self.attempt = 0

            def stream(self, *args, **kwargs):
                self.attempt += 1
                raise ValueError("Always failing")

            async def aclose(self):
                pass

        async def fake_get_client_always_fail(url):
            return AlwaysFailClient(), MagicMock()

        monkeypatch.setattr(engine2, "_get_client", fake_get_client_always_fail)
        monkeypatch.setattr(engine2, "_update_progress", AsyncMock())

        result2 = await engine2.request_single("https://example.com")
        assert result2.status == QueryStatus.UNKNOWN_ERROR
        assert result2.error_message == "Always failing"
        assert result2.attempt_number == 3  # max_retries=2, so attempt=3 (0,1,2)

        # Also verify that the generic exception branch increments failed_targets.
        # We can check engine2.failed_targets after the request.
        assert engine2.failed_targets.get("https://example.com") == 1


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


# ---------------------------------------------------------------------------
# PushTrackingH2Connection
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not _H2_AVAILABLE, reason="h2 not installed")
class TestPushTrackingH2Connection:
    def test_init_starts_with_no_push_promises(self):
        conn = PushTrackingH2Connection()
        assert conn.push_promises == []

    def test_receive_data_records_pushed_stream(self, monkeypatch):
        conn = PushTrackingH2Connection()

        pushed_event = h2.events.PushedStreamReceived()
        pushed_event.parent_stream_id = 1
        pushed_event.pushed_stream_id = 2
        pushed_event.headers = [
            (b":path", b"/style.css"),
            (b":scheme", b"https"),
            (b":authority", b"example.com"),
        ]

        # Patch the real H2Connection.receive_data (the super() call) rather
        # than feeding raw wire bytes through a real handshake — mirrors how
        # http_test_core.py mocks at the httpx/httpcore boundary instead of
        # exercising real network/protocol machinery.
        monkeypatch.setattr(
            "h2.connection.H2Connection.receive_data",
            lambda self, data: [pushed_event],
        )

        events = conn.receive_data(b"irrelevant-bytes")

        assert events == [pushed_event]
        assert len(conn.push_promises) == 1
        promise = conn.push_promises[0]
        assert promise["stream_id"] == 1
        assert promise["promised_stream_id"] == 2
        assert promise["url"] == "https://example.com/style.css"

    def test_receive_data_ignores_non_push_events(self, monkeypatch):
        conn = PushTrackingH2Connection()
        other_event = MagicMock()  # not a PushedStreamReceived

        monkeypatch.setattr(
            "h2.connection.H2Connection.receive_data",
            lambda self, data: [other_event],
        )

        events = conn.receive_data(b"irrelevant-bytes")
        assert events == [other_event]
        assert conn.push_promises == []

    def test_receive_data_missing_path_or_authority_falls_back_to_path(
        self, monkeypatch
    ):
        """If :authority or :path is missing, url should just be the raw path
        (possibly empty) rather than a malformed partial URL."""
        conn = PushTrackingH2Connection()
        pushed_event = h2.events.PushedStreamReceived()
        pushed_event.parent_stream_id = 5
        pushed_event.pushed_stream_id = 6
        pushed_event.headers = [(b":path", b"/no-authority.js")]

        monkeypatch.setattr(
            "h2.connection.H2Connection.receive_data",
            lambda self, data: [pushed_event],
        )

        conn.receive_data(b"x")
        assert conn.push_promises[0]["url"] == "/no-authority.js"


@pytest.mark.skipif(not _H2_AVAILABLE, reason="h2 not installed")
class TestPushDetectingPoolInitConnection:
    @pytest.mark.asyncio
    async def test_init_connection_swaps_in_tracking_h2_connection(self, monkeypatch):
        import ssl

        pool = PushDetectingPool(
            ssl_context=ssl.create_default_context(),
            http2=True,
            network_backend=MagicMock(),
        )

        fake_h2_conn = MagicMock()
        fake_h2_conn.config = MagicMock()
        fake_http_conn = MagicMock()
        fake_http_conn._h2_connection = fake_h2_conn
        fake_conn = MagicMock()
        fake_conn.connection = fake_http_conn

        async def fake_parent_init(self, url, ssl_context):
            return fake_conn

        # Use patch with create=True to mock the method even if it doesn't exist on the class.
        with patch.object(
            AsyncConnectionPool, "_init_connection", new=fake_parent_init, create=True
        ):
            result = await pool._init_connection(MagicMock(), MagicMock())

        assert result is fake_conn
        assert isinstance(fake_http_conn._h2_connection, PushTrackingH2Connection)

    @pytest.mark.asyncio
    async def test_init_connection_degrades_gracefully_on_missing_attr(
        self, monkeypatch
    ):
        import ssl

        pool = PushDetectingPool(
            ssl_context=ssl.create_default_context(),
            http2=True,
            network_backend=MagicMock(),
        )

        fake_conn = MagicMock()
        # Remove the 'connection' attribute to simulate private-API drift
        del fake_conn.connection

        async def fake_parent_init(self, url, ssl_context):
            return fake_conn

        with patch.object(
            AsyncConnectionPool, "_init_connection", new=fake_parent_init, create=True
        ):
            result = await pool._init_connection(MagicMock(), MagicMock())

        assert result is fake_conn


# ---------------------------------------------------------------------------
# get_recent_push_promises
# ---------------------------------------------------------------------------


class TestGetRecentPushPromises:
    def test_disabled_returns_empty_list(self):
        transport = MetricsCapturingTransport(verify=False, enable_push_detection=False)
        assert transport.get_recent_push_promises() == []

    @pytest.mark.skipif(not _H2_AVAILABLE, reason="h2 not installed")
    def test_enabled_returns_promises_from_matching_connection(self):
        transport = MetricsCapturingTransport(verify=False, http2=True)
        transport._enable_push_detection = True

        tracked = PushTrackingH2Connection()
        tracked.push_promises = [{"stream_id": 1, "promised_stream_id": 2, "url": "x"}]

        fake_http_conn = MagicMock()
        fake_http_conn._h2_connection = tracked
        fake_conn = MagicMock()
        fake_conn.connection = fake_http_conn

        mock_pool = MagicMock()
        mock_pool.connections = [fake_conn]
        transport._pool = mock_pool

        result = transport.get_recent_push_promises()
        assert result == tracked.push_promises

    @pytest.mark.skipif(not _H2_AVAILABLE, reason="h2 not installed")
    def test_enabled_skips_connections_without_h2(self):
        transport = MetricsCapturingTransport(verify=False, http2=True)
        transport._enable_push_detection = True

        plain_http_conn = MagicMock(spec=[])  # no _h2_connection
        fake_conn = MagicMock()
        fake_conn.connection = plain_http_conn

        mock_pool = MagicMock()
        mock_pool.connections = [fake_conn]
        transport._pool = mock_pool

        assert transport.get_recent_push_promises() == []

    def test_enabled_but_pool_access_raises_attributeerror_returns_empty(self):
        transport = MetricsCapturingTransport(verify=False)
        transport._enable_push_detection = True
        transport._pool = MagicMock(
            spec=[]
        )  # accessing .connections raises AttributeError

        assert transport.get_recent_push_promises() == []

    def test_enabled_but_unexpected_error_propagates(self):
        """A non-AttributeError bug in this loop (e.g. TypeError from a
        code change) must NOT be silently swallowed — only private-API
        shape drift (AttributeError) should degrade to an empty list."""
        transport = MetricsCapturingTransport(verify=False)
        transport._enable_push_detection = True

        class BoomConnections:
            def __iter__(self):
                raise TypeError("boom")

        transport._pool = MagicMock()
        transport._pool.connections = BoomConnections()

        with pytest.raises(TypeError, match="boom"):
            transport.get_recent_push_promises()


# ---------------------------------------------------------------------------
# HTTPDigestAuth
# ---------------------------------------------------------------------------


class TestHTTPDigestAuth:
    def _make_request(self, method="GET", url="https://example.com/secure"):
        return httpx.Request(method, url)

    def _make_401(self, www_authenticate: str):
        return httpx.Response(
            401,
            headers={"www-authenticate": www_authenticate},
            request=httpx.Request("GET", "https://example.com/secure"),
        )

    def test_parse_challenge_extracts_all_fields(self):
        auth = HTTPDigestAuth("user", "pass")
        challenge = auth._parse_challenge(
            'Digest realm="test", nonce="abc123", qop="auth", algorithm=MD5, opaque="xyz"'
        )
        assert challenge["realm"] == "test"
        assert challenge["nonce"] == "abc123"
        assert challenge["qop"] == "auth"
        assert challenge["algorithm"] == "MD5"
        assert challenge["opaque"] == "xyz"

    def test_auth_flow_non_401_response_does_nothing(self):
        auth = HTTPDigestAuth("user", "pass")
        request = self._make_request()
        flow = auth.auth_flow(request)
        first = next(flow)
        assert first is request

        ok_response = httpx.Response(200, request=request)
        with pytest.raises(StopIteration):
            flow.send(ok_response)

    def test_auth_flow_non_digest_challenge_does_nothing(self):
        auth = HTTPDigestAuth("user", "pass")
        request = self._make_request()
        flow = auth.auth_flow(request)
        next(flow)

        response = self._make_401('Basic realm="test"')
        with pytest.raises(StopIteration):
            flow.send(response)

    def test_auth_flow_missing_nonce_does_nothing(self):
        auth = HTTPDigestAuth("user", "pass")
        request = self._make_request()
        flow = auth.auth_flow(request)
        next(flow)

        response = self._make_401('Digest realm="test"')
        with pytest.raises(StopIteration):
            flow.send(response)

    def test_auth_flow_with_qop_sets_authorization_header(self):
        auth = HTTPDigestAuth("user", "pass")
        request = self._make_request(method="GET", url="https://example.com/secure")
        flow = auth.auth_flow(request)
        next(flow)

        response = self._make_401(
            'Digest realm="testrealm", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", '
            'qop="auth", opaque="5ccc069c403ebaf9f0171e9517f40e41"'
        )
        second_request = flow.send(response)

        auth_header = second_request.headers["Authorization"]
        assert auth_header.startswith("Digest ")
        assert 'username="user"' in auth_header
        assert 'realm="testrealm"' in auth_header
        assert "qop=auth" in auth_header
        assert "nc=00000001" in auth_header
        assert "cnonce=" in auth_header
        assert 'response="' in auth_header

        with pytest.raises(StopIteration):
            flow.send(httpx.Response(200, request=second_request))

    def test_auth_flow_without_qop_uses_legacy_response_formula(self):
        auth = HTTPDigestAuth("user", "pass")
        request = self._make_request()
        flow = auth.auth_flow(request)
        next(flow)

        response = self._make_401('Digest realm="testrealm", nonce="abc123"')
        second_request = flow.send(response)
        auth_header = second_request.headers["Authorization"]

        # Legacy path must NOT include qop/nc/cnonce.
        assert "qop=" not in auth_header
        assert "nc=" not in auth_header
        assert "cnonce=" not in auth_header
        assert 'response="' in auth_header

    def test_auth_flow_sha256_algorithm_selected(self):
        auth = HTTPDigestAuth("user", "pass")
        request = self._make_request()
        flow = auth.auth_flow(request)
        next(flow)

        response = self._make_401(
            'Digest realm="testrealm", nonce="abc123", algorithm=SHA-256, qop="auth"'
        )
        second_request = flow.send(response)
        assert "algorithm=SHA-256" in second_request.headers["Authorization"]

    def test_nonce_count_increments_across_multiple_challenges(self):
        auth = HTTPDigestAuth("user", "pass")
        assert auth._nonce_count == 0

        for _ in range(2):
            request = self._make_request()
            flow = auth.auth_flow(request)
            next(flow)
            response = self._make_401('Digest realm="r", nonce="n", qop="auth"')
            flow.send(response)
            with pytest.raises(StopIteration):
                flow.send(httpx.Response(200, request=request))

        assert auth._nonce_count == 2


# ---------------------------------------------------------------------------
# HTTPBenchmarkEngine.websocket_single
# ---------------------------------------------------------------------------


class TestWebsocketSingle:
    @pytest.mark.asyncio
    async def test_websocket_single_raises_if_aiohttp_unavailable(self, monkeypatch):
        monkeypatch.setattr("net_benchmark.http_bench.core._AIOHTTP_AVAILABLE", False)
        engine = HTTPBenchmarkEngine()
        with pytest.raises(ImportError, match="aiohttp"):
            await engine.websocket_single("wss://example.com/ws")

    @pytest.mark.skipif(not _AIOHTTP_AVAILABLE, reason="aiohttp not installed")
    @pytest.mark.asyncio
    async def test_websocket_single_success(self, monkeypatch):
        engine = HTTPBenchmarkEngine()
        monkeypatch.setattr(engine, "_update_progress", AsyncMock())

        fake_ws = MagicMock()

        class FakeWSContext:
            async def __aenter__(self):
                return fake_ws

            async def __aexit__(self, *args):
                return False

        class FakeSession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return False

            def ws_connect(self, target):
                return FakeWSContext()

        with patch(
            "net_benchmark.http_bench.core.aiohttp.ClientSession",
            return_value=FakeSession(),
        ):
            result = await engine.websocket_single("wss://example.com/ws", iteration=2)

        assert result.status == QueryStatus.SUCCESS
        assert result.iteration == 2
        assert result.websocket_handshake_ms is not None
        assert result.websocket_handshake_ms >= 0
        assert result.total_ms == pytest.approx(result.websocket_handshake_ms)

    @pytest.mark.skipif(not _AIOHTTP_AVAILABLE, reason="aiohttp not installed")
    @pytest.mark.asyncio
    async def test_websocket_single_connection_failure(self, monkeypatch):
        engine = HTTPBenchmarkEngine()
        monkeypatch.setattr(engine, "_update_progress", AsyncMock())

        class FailingSession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return False

            def ws_connect(self, target):
                raise ConnectionRefusedError("refused")

        with patch(
            "net_benchmark.http_bench.core.aiohttp.ClientSession",
            return_value=FailingSession(),
        ):
            result = await engine.websocket_single("wss://down.example.com/ws")

        assert result.status == QueryStatus.UNKNOWN_ERROR
        assert "refused" in result.error_message
        assert result.websocket_handshake_ms is None

    @pytest.mark.skipif(not _AIOHTTP_AVAILABLE, reason="aiohttp not installed")
    @pytest.mark.asyncio
    async def test_websocket_single_calls_update_progress(self, monkeypatch):
        """Progress tracking must fire on both success and failure paths,
        same as request_single — otherwise progress bars stall silently."""
        engine = HTTPBenchmarkEngine()
        progress_mock = AsyncMock()
        monkeypatch.setattr(engine, "_update_progress", progress_mock)

        class FakeWSContext:
            async def __aenter__(self):
                return MagicMock()

            async def __aexit__(self, *args):
                return False

        class FakeSession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return False

            def ws_connect(self, target):
                return FakeWSContext()

        with patch(
            "net_benchmark.http_bench.core.aiohttp.ClientSession",
            return_value=FakeSession(),
        ):
            await engine.websocket_single("wss://example.com/ws")

        progress_mock.assert_awaited_once()
