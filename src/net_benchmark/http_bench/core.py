"""Core HTTP benchmarking functionality."""

import asyncio
import ipaddress
import ssl
import time
import uuid
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple, Union
from urllib.parse import urlparse

import httpcore
import httpx
from cryptography import x509
from cryptography.x509.oid import NameOID
from httpcore._backends.auto import AutoBackend
from httpcore._backends.base import (
    SOCKET_OPTION,
    AsyncNetworkBackend,
    AsyncNetworkStream,
)

from net_benchmark.dns_benchmark.core import QueryStatus
from net_benchmark.utils.messages import warning

# ---------------------------------------------------------------------------
# Timing wrappers — correct httpcore async ABC signatures
# ---------------------------------------------------------------------------


class TimingNetworkStream(AsyncNetworkStream):
    """Wraps an AsyncNetworkStream to capture TCP-connect and TLS-handshake times.

    The metrics dict is shared with TimingNetworkBackend so writes made inside
    start_tls() are immediately visible there without any extra plumbing.
    """

    def __init__(self, stream: AsyncNetworkStream, metrics: Dict[str, Any]) -> None:
        self._stream = stream
        self._metrics = metrics  # shared reference — intentional

    async def read(self, max_bytes: int, timeout: Optional[float] = None) -> bytes:
        return await self._stream.read(max_bytes, timeout)

    async def write(self, buffer: bytes, timeout: Optional[float] = None) -> None:
        await self._stream.write(buffer, timeout)

    async def aclose(self) -> None:
        await self._stream.aclose()

    async def start_tls(
        self,
        ssl_context: ssl.SSLContext,
        server_hostname: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> AsyncNetworkStream:
        tls_start = time.perf_counter()
        tls_stream = await self._stream.start_tls(ssl_context, server_hostname, timeout)
        self._metrics["tls_handshake_ms"] = (time.perf_counter() - tls_start) * 1000
        try:
            ssl_obj = tls_stream.get_extra_info("ssl_object")
            if ssl_obj is not None:
                self._metrics["cert_der"] = ssl_obj.getpeercert(binary_form=True)
        except Exception:
            pass
        # Wrap the TLS stream so further calls keep the same metrics reference
        return TimingNetworkStream(tls_stream, self._metrics)

    def get_extra_info(self, info: str) -> Any:
        return self._stream.get_extra_info(info)


class TimingNetworkBackend(AsyncNetworkBackend):
    """Wraps AutoBackend to inject per-connection TCP and TLS timing.

    One backend instance per origin so metrics are not clobbered across origins.
    """

    def __init__(self, local_address: Optional[str] = None) -> None:
        self._backend = AutoBackend()
        self.local_address = local_address
        # Overwritten on every new connection — safe: asyncio is single-threaded.
        self.metrics: Dict[str, Any] = {}

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: Optional[float] = None,
        local_address: Optional[str] = None,
        socket_options: Optional[Iterable[SOCKET_OPTION]] = None,
    ) -> AsyncNetworkStream:

        if local_address is None:
            local_address = self.local_address

        tcp_start = time.perf_counter()
        stream = await self._backend.connect_tcp(
            host,
            port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )
        self.metrics = {
            "tcp_connect_ms": (time.perf_counter() - tcp_start) * 1000,
            "tls_handshake_ms": None,
            "cert_der": None,
            "ip_version": None,
        }
        try:
            server_addr = stream.get_extra_info("server_addr")
            if isinstance(server_addr, tuple) and server_addr:
                self.metrics["ip_version"] = (
                    f"IPv{ipaddress.ip_address(server_addr[0]).version}"
                )
        except Exception:
            pass
        return TimingNetworkStream(stream, self.metrics)

    async def connect_unix_socket(
        self,
        path: str,
        timeout: Optional[float] = None,
        socket_options: Optional[Iterable[SOCKET_OPTION]] = None,
    ) -> AsyncNetworkStream:
        return await self._backend.connect_unix_socket(
            path, timeout=timeout, socket_options=socket_options
        )

    async def sleep(self, seconds: float) -> None:
        await self._backend.sleep(seconds)


# ---------------------------------------------------------------------------
# Transport — build httpcore pool directly to avoid overriding _init_pool
# ---------------------------------------------------------------------------


class MetricsCapturingTransport(httpx.AsyncHTTPTransport):
    """AsyncHTTPTransport that captures per-connection timing and TLS metrics.

    Rather than overriding the non-existent _init_pool hook, we build the
    httpcore.AsyncConnectionPool ourselves and pass the custom TimingNetworkBackend
    directly.
    """

    def __init__(
        self,
        verify: bool = True,
        cert: Optional[Tuple[str, str]] = None,
        http2: bool = False,
        sni_hostname: Optional[str] = None,
        mtls_cert: Optional[str] = None,
        mtls_key: Optional[str] = None,
        local_address: Optional[str] = None,
    ) -> None:
        # Build SSL context manually so we control mTLS and verification.
        ssl_context = ssl.create_default_context()
        if not verify:
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
        if mtls_cert:
            ssl_context.load_cert_chain(mtls_cert, mtls_key)
        elif cert:
            ssl_context.load_cert_chain(*cert)

        self._timing_backend = TimingNetworkBackend(local_address=local_address)
        self._sni_hostname = sni_hostname

        # Inject our backend directly into httpcore's pool.  httpx's
        # handle_async_request delegates to self._pool, so this is sufficient.
        self._pool = httpcore.AsyncConnectionPool(
            ssl_context=ssl_context,
            http2=http2,
            network_backend=self._timing_backend,
        )

    def get_connection_metrics(self) -> Dict[str, Any]:
        """Return a snapshot of metrics from the most recently established connection."""
        return dict(self._timing_backend.metrics)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_cert_der(
    cert_der: bytes,
) -> Tuple[Optional[int], Optional[str], Optional[str], List[str], bool]:
    """Parse DER cert bytes with the cryptography library.

    Returns (days_remaining, subject_cn, issuer_cn, sans, wildcard).
    Uses cryptography (explicit dep) not ssl.getpeercert() dict, so all
    fields are available consistently across Python versions.
    """
    try:
        cert = x509.load_der_x509_certificate(cert_der)
        # subject CN
        try:
            raw_cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            cn: Optional[str] = (
                raw_cn.decode("utf-8") if isinstance(raw_cn, bytes) else raw_cn
            )
        except IndexError:
            cn = None
        # issuer CN
        try:
            raw_issuer = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[
                0
            ].value
            issuer_cn: Optional[str] = (
                raw_issuer.decode("utf-8")
                if isinstance(raw_issuer, bytes)
                else raw_issuer
            )
        except IndexError:
            issuer_cn = None
        # SANs
        try:
            san_ext = cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            )
            sans: List[str] = san_ext.value.get_values_for_type(x509.DNSName)
        except Exception:
            sans = []
        wildcard = any(s.startswith("*.") for s in sans)
        # expiry
        try:
            expiry = cert.not_valid_after_utc
        except AttributeError:
            expiry = cert.not_valid_after.replace(tzinfo=timezone.utc)
        days = (expiry - datetime.now(tz=timezone.utc)).days
        return days, cn, issuer_cn, sans, wildcard
    except Exception:
        return None, None, None, [], False


# ---------------------------------------------------------------------------
# Protocol enum
# ---------------------------------------------------------------------------


class HTTPProtocol(str, Enum):
    """Negotiated application protocol — captured from the live connection."""

    HTTP1 = "HTTP/1.1"
    HTTP2 = "HTTP/2"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

# Security headers audited on every HTTPS response.
# Stored as Optional[str] — None means header absent, value means present.
SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]

# Response headers that reveal CDN identity.
CDN_HEADER_MAP: Dict[str, str] = {
    "cf-ray": "Cloudflare",
    "x-amz-cf-id": "CloudFront",
    "fastly-restarts": "Fastly",
    "x-served-by": "Fastly",
    "x-azure-ref": "Azure CDN",
    "x-cdn": "CDN",
}

# Headers requiring value inspection
CDN_VALUE_PATTERNS: Dict[str, Dict[str, str]] = {
    "server": {
        "gws": "Google",
        "googfe": "Google",
        "cloudflare": "Cloudflare",
        "akamai": "Akamai",
        "nginx": "Nginx",
        "AmazonS3": "CloudFront",
        "ECS": "Akamai",
        "ECAcc": "Akamai",
    },
    "via": {
        "cloudflare": "Cloudflare",
        "varnish": "Fastly/Varnish",
        "akamai": "Akamai",
        "google": "Google",
    },
    "x-cache": {
        "cloudfront": "CloudFront",
        "fastly": "Fastly",
    },
}


@dataclass
class HTTPResult:
    """Result of a single HTTP request"""

    # --- identity ---
    target: str  # full URL
    method: str  # HTTP verb
    start_time: float
    end_time: float
    total_ms: float  # wall-clock latency — primary metric
    status: QueryStatus
    iteration: int = 1  # 0 = warmup
    attempt_number: int = 1
    query_id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    # --- HTTP response ---
    http_status_code: Optional[int] = None
    error_message: Optional[str] = None
    redirect_count: int = 0
    final_url: str = ""  # URL after following redirects
    # --- timing breakdown (best-effort; None if not measurable) ---
    ttfb_ms: Optional[float] = None  # time to first byte
    ttlb_ms: Optional[float] = None  # time to last byte
    # --- protocol ---
    protocol: HTTPProtocol = HTTPProtocol.UNKNOWN
    alpn_negotiated: Optional[str] = None  # "h2", "http/1.1", None for plain
    # --- response metadata ---
    response_size_bytes: Optional[int] = None
    compressed: bool = False
    content_encoding: Optional[str] = None
    content_type: Optional[str] = None
    # --- security signals (0.5.0 spike) ---
    security_headers: Dict[str, Optional[str]] = field(default_factory=dict)
    cdn_fingerprint: Optional[str] = None  # detected CDN name
    server_header: Optional[str] = None  # server software/version leak
    cert_expiry_days: Optional[int] = None  # from inline TLS cert capture
    cert_cn: Optional[str] = None
    alt_svc: Optional[str] = None
    ip_version: Optional[str] = None  # "IPv4" or "IPv6"
    cert_issuer_cn: Optional[str] = None
    cert_sans: List[str] = field(default_factory=list)
    cert_wildcard: bool = False
    downgrade_detected: bool = False
    redirect_urls: List[str] = field(default_factory=list)  # full hop list
    tls_handshake_ms: Optional[float] = None
    tcp_connect_ms: Optional[float] = None
    dns_resolve_ms: Optional[float] = None
    dns_resolver_ip: Optional[str] = None
    compressed_size_bytes: Optional[int] = None
    http2_expected: bool = False
    http2_downgraded: bool = False
    redirect_timings: List[Dict[str, Any]] = field(default_factory=list)
    query_params: Dict[str, str] = field(default_factory=dict)
    # cache headers
    cache_control: Optional[str] = None
    etag: Optional[str] = None
    last_modified: Optional[str] = None
    age: Optional[str] = None
    # auth / request tracking
    request_id: Optional[str] = None
    # assertions
    assertion_results: Dict[str, bool] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        d["protocol"] = self.protocol.value
        return d


# ---------------------------------------------------------------------------
# Target manager  (mirrors ResolverManager + DomainManager combined)
# ---------------------------------------------------------------------------


class TargetManager:
    """Parse and validate HTTP target URLs."""

    DEFAULT_TARGETS: List[str] = [
        "https://www.cloudflare.com",
        "https://www.google.com",
        "https://www.github.com",
        "https://www.wikipedia.org",
        "https://www.apple.com",
    ]

    def __init__(self, targets: List[str]) -> None:
        self._targets = targets

    @property
    def targets(self) -> List[str]:
        return self._targets

    @classmethod
    def get_default_targets(cls) -> List[str]:
        return cls.DEFAULT_TARGETS

    @classmethod
    def parse_targets_input(cls, input_value: Optional[str]) -> "TargetManager":
        if not input_value:
            raise ValueError("Target input cannot be empty")

        input_value = input_value.strip()

        # Explicit URL with scheme → definitely not a file
        if input_value.startswith(("http://", "https://")):
            if "," in input_value:
                return cls(cls._parse_inline(input_value))
            return cls([input_value])

        # Heuristic: if it contains a path separator or a common text‑file extension,
        # treat it as a file path.  Otherwise it's probably an inline URL.
        likely_file = (
            "/" in input_value
            or "\\" in input_value
            or Path(input_value).suffix
            in (".txt", ".csv", ".list", ".conf", ".yaml", ".yml")
        )

        if likely_file:
            path = Path(input_value)
            if not path.exists() or not path.is_file():
                raise FileNotFoundError(f"Target file not found: {input_value}")
            return cls(cls._load_from_file(str(path)))

        # Inline list or single URL (could be a bare domain)
        if "," in input_value:
            return cls(cls._parse_inline(input_value))
        return cls([input_value])

    @staticmethod
    def _load_from_file(file_path: str) -> List[str]:
        with open(file_path) as f:
            return [
                line.strip() for line in f if line.strip() and not line.startswith("#")
            ]

    @staticmethod
    def _parse_inline(targets_str: str) -> List[str]:
        seen: Set[str] = set()
        result = []
        for part in targets_str.split(","):
            url = part.strip()
            if url and url not in seen:
                seen.add(url)
                result.append(url)
        return result


# ---------------------------------------------------------------------------
# HTTP benchmark engine  (mirrors DNSQueryEngine)
# ---------------------------------------------------------------------------


class HTTPBenchmarkEngine:
    def __init__(
        self,
        max_concurrent: int = 50,
        timeout: float = 10.0,
        connect_timeout: Optional[float] = None,
        read_timeout: Optional[float] = None,
        write_timeout: Optional[float] = None,
        max_retries: int = 2,
        retry_backoff_multiplier: float = 0.1,
        retry_backoff_base: float = 2.0,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        follow_redirects: bool = True,
        verify_ssl: bool = True,
        http2: bool = True,
        auth: Optional[Any] = None,
        cookies: Optional[Dict[str, str]] = None,
        proxy: Optional[str] = None,
        sni_hostname: Optional[str] = None,
        mtls_cert: Optional[str] = None,
        mtls_key: Optional[str] = None,
        inject_request_id: bool = False,
        assertions: Optional[Dict[str, Any]] = None,
        query_params: Optional[Dict[str, str]] = None,
        body: Optional[bytes] = None,
        local_address: Optional[str] = None,
    ) -> None:
        self.max_concurrent = max_concurrent
        self.max_retries = max_retries
        self.retry_backoff_multiplier = retry_backoff_multiplier
        self.retry_backoff_base = retry_backoff_base
        self.method = method.upper()
        self.extra_headers = headers or {}
        self.follow_redirects = follow_redirects
        self.verify_ssl = verify_ssl
        self.http2 = http2
        self.auth = auth
        self.cookies = cookies or {}
        self.proxy = proxy
        self.sni_hostname = sni_hostname
        self.mtls_cert = mtls_cert
        self.mtls_key = mtls_key
        self.inject_request_id = inject_request_id
        self.assertions = assertions or {}
        self.body = body
        self.local_address = local_address
        self.semaphore: Optional[asyncio.Semaphore] = None
        self._lock: Optional[asyncio.Lock] = None
        self.progress_callback: Optional[Callable[[int, int], None]] = None
        self.query_counter = 0
        self.total_queries = 0
        self.failed_targets: Dict[str, int] = defaultdict(int)
        self._clients: Dict[str, httpx.AsyncClient] = {}
        self._transports: Dict[str, MetricsCapturingTransport] = {}
        self._dns_cache: Dict[str, Tuple[float, str]] = {}
        self.dns_resolver_ip = self._detect_dns_resolver()

        # Build timeout object — may be a plain float or an httpx.Timeout
        if connect_timeout or read_timeout or write_timeout:
            self._timeout: Union[float, httpx.Timeout] = httpx.Timeout(
                connect=connect_timeout or timeout,
                read=read_timeout or timeout,
                write=write_timeout or timeout,
                pool=connect_timeout or timeout,
            )
        else:
            self._timeout = timeout

        self.query_params = query_params or {}

    def set_progress_callback(self, callback: Callable[[int, int], None]) -> None:
        self.progress_callback = callback

    async def _ensure_async_primitives(self) -> None:
        if self.semaphore is None:
            self.semaphore = asyncio.Semaphore(self.max_concurrent)
        if self._lock is None:
            self._lock = asyncio.Lock()

    async def _update_progress(self) -> None:
        await self._ensure_async_primitives()
        assert self._lock is not None
        async with self._lock:
            self.query_counter += 1
            if self.progress_callback:
                self.progress_callback(self.query_counter, self.total_queries)

    def _origin(self, url: str) -> str:
        """Extract scheme+host+port as pool key."""
        p = urlparse(url)
        return f"{p.scheme}://{p.netloc}"

    def _get_transport(self, url: str) -> MetricsCapturingTransport:
        origin = self._origin(url)
        if origin not in self._transports:
            cert: Optional[Tuple[str, str]] = None
            if self.mtls_cert and self.mtls_key:
                cert = (self.mtls_cert, self.mtls_key)
            self._transports[origin] = MetricsCapturingTransport(
                verify=self.verify_ssl,
                cert=cert,
                http2=self.http2,
                sni_hostname=self.sni_hostname,
                mtls_cert=self.mtls_cert,
                mtls_key=self.mtls_key,
                local_address=self.local_address,
            )
        return self._transports[origin]

    async def _get_client(
        self, url: str
    ) -> Tuple[httpx.AsyncClient, MetricsCapturingTransport]:
        """Return or create a shared (AsyncClient, transport) pair for this origin."""
        origin = self._origin(url)

        if origin not in self._clients:
            transport = self._get_transport(url)
            client_kwargs: Dict[str, Any] = dict(
                transport=transport,
                http2=self.http2,
                verify=self.verify_ssl,
                follow_redirects=self.follow_redirects,
                timeout=httpx.Timeout(self._timeout),
                headers=self.extra_headers,
                cookies=self.cookies or None,
            )
            if self.auth:
                client_kwargs["auth"] = self.auth
            if self.proxy:
                client_kwargs["proxy"] = self.proxy
            self._clients[origin] = httpx.AsyncClient(**client_kwargs)

        transport = self._transports[origin]
        return self._clients[origin], transport

    async def close(self) -> None:
        """Close all pooled clients. Must be awaited after run_benchmark."""
        for client in self._clients.values():
            await client.aclose()
        self._clients.clear()
        self._transports.clear()

    def get_failed_targets(self) -> Dict[str, int]:
        return dict(self.failed_targets)

    def _run_assertions(self, response: httpx.Response, body: bytes) -> Dict[str, bool]:
        results: Dict[str, bool] = {}
        for name, config in self.assertions.items():
            if name == "status_code":
                results[name] = response.status_code == config
            elif name == "body_contains":
                results[name] = config in body.decode("utf-8", errors="ignore")
            elif name == "header_exists":
                results[name] = config in response.headers
            elif name == "header_value":
                header = config["header"]
                value = config["value"]
                results[name] = response.headers.get(header) == value
            elif name == "content_type":
                ct = response.headers.get("content-type", "")
                results[name] = config in ct
            elif name == "response_size_min":
                results[name] = len(body) >= config
            elif name == "response_size_max":
                results[name] = len(body) <= config

        return results

    async def _resolve_host(self, host: str) -> Tuple[float, Optional[str]]:
        """Resolve *host* (using the event loop) and return (ms, error_str)."""
        start = time.perf_counter()
        try:
            loop = asyncio.get_running_loop()
            await loop.getaddrinfo(host, None)
            elapsed = (time.perf_counter() - start) * 1000
            return elapsed, None
        except Exception as e:
            elapsed = (time.perf_counter() - start) * 1000
            return elapsed, str(e)

    @staticmethod
    def _detect_dns_resolver() -> Optional[str]:
        """Return the primary system DNS resolver IP, or None."""
        try:
            import dns.resolver

            resolvers = dns.resolver.Resolver().nameservers
            if resolvers:
                return str(resolvers[0])
        except Exception:
            pass
        return None

    # ------------------------------------------------------------------
    # Security signal extraction helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_security_headers(
        headers: httpx.Headers,
    ) -> Dict[str, Optional[str]]:
        return {h: headers.get(h) for h in SECURITY_HEADERS}

    @staticmethod
    def _detect_cdn(headers: httpx.Headers) -> Optional[str]:
        for header, cdn_name in CDN_HEADER_MAP.items():
            if header in headers:
                return cdn_name
        for header, patterns in CDN_VALUE_PATTERNS.items():
            value = headers.get(header, "").lower()
            if not value:
                continue
            for pattern, cdn_name in patterns.items():
                if pattern.lower() in value:
                    return cdn_name
        return None

    @staticmethod
    def _detect_protocol(
        response: httpx.Response,
    ) -> Tuple[HTTPProtocol, Optional[str]]:
        http_ver = getattr(response, "http_version", None)
        if http_ver == "HTTP/2":
            return HTTPProtocol.HTTP2, "h2"
        elif http_ver == "HTTP/1.1":
            return HTTPProtocol.HTTP1, "http/1.1"
        return HTTPProtocol.UNKNOWN, None

    # ------------------------------------------------------------------
    # Single request
    # ------------------------------------------------------------------

    async def request_single(
        self,
        target: str,
        iteration: int = 1,
    ) -> HTTPResult:
        """Execute a single HTTP request with retry logic."""
        await self._ensure_async_primitives()
        assert self.semaphore is not None

        start_time = time.time()
        client, transport = await self._get_client(target)

        for attempt in range(self.max_retries + 1):
            try:
                async with self.semaphore:
                    start_time = time.perf_counter()

                    # DNS resolution (timed)
                    parsed = urlparse(target)
                    hostname = parsed.hostname
                    dns_ms = 0.0
                    dns_error = None
                    if hostname:
                        if hostname not in self._dns_cache:
                            dns_ms, dns_error = await self._resolve_host(hostname)
                            if dns_error is None:
                                self._dns_cache[hostname] = (dns_ms, "ok")
                        else:
                            dns_ms = 0.0

                    # Append query parameters if any
                    if self.query_params:
                        qs = "&".join(f"{k}={v}" for k, v in self.query_params.items())
                        target = target + ("&" if "?" in target else "?") + qs

                    ttfb_ms: Optional[float] = None

                    req_headers = dict(self.extra_headers)
                    request_id: Optional[str] = None
                    if self.inject_request_id:
                        request_id = uuid.uuid4().hex[:8]
                        req_headers["X-Request-ID"] = request_id

                    async with client.stream(
                        method=self.method,
                        url=target,
                        headers=req_headers,
                        content=self.body,
                    ) as response:
                        headers_received = time.perf_counter()
                        ttfb_ms = (headers_received - start_time) * 1000
                        body = await response.aread()
                        assertion_results = self._run_assertions(response, body)

                    end_time = time.perf_counter()
                    total_ms = (end_time - start_time) * 1000

                    # Check max_latency assertion if defined
                    if "max_latency" in self.assertions:
                        assertion_results["max_latency"] = (
                            total_ms <= self.assertions["max_latency"]
                        )

                    protocol, alpn = self._detect_protocol(response)

                    content_encoding = response.headers.get("content-encoding")
                    content_type = response.headers.get("content-type")
                    compressed = content_encoding in ("gzip", "br", "zstd", "deflate")
                    response_size = len(body)

                    sec_headers = self._extract_security_headers(response.headers)
                    cdn = self._detect_cdn(response.headers)
                    alt_svc = response.headers.get("alt-svc")
                    server = response.headers.get("server")

                    redirect_count = len(response.history)
                    final_url = str(response.url)

                    # Walk history to get full hop list and detect downgrades
                    redirect_urls = [str(r.url) for r in response.history]
                    downgrade_detected = target.startswith("https://") and any(
                        str(r.url).startswith("http://") for r in response.history
                    )

                    # Compressed size from Content-Length header
                    cl = response.headers.get("content-length")
                    compressed_size = int(cl) if cl else None

                    # Redirect per-hop timings
                    redirect_timings = []
                    for prev_resp in response.history:
                        redirect_timings.append(
                            {
                                "url": str(prev_resp.url),
                                "status_code": prev_resp.status_code,
                                "duration_ms": prev_resp.elapsed.total_seconds() * 1000,
                            }
                        )

                    # HTTP/2 downgrade detection
                    http2_expected = self.http2
                    http2_downgraded = http2_expected and protocol != HTTPProtocol.HTTP2

                    # Cache headers
                    cache_control = response.headers.get("cache-control")
                    etag = response.headers.get("etag")
                    last_modified = response.headers.get("last-modified")
                    age = response.headers.get("age")

                    if response.is_success or response.is_redirect:
                        status = QueryStatus.SUCCESS
                    else:
                        status = QueryStatus.UNKNOWN_ERROR

                    result = HTTPResult(
                        target=target,
                        method=self.method,
                        start_time=start_time,
                        end_time=end_time,
                        total_ms=total_ms,
                        status=status,
                        iteration=iteration,
                        attempt_number=attempt + 1,
                        http_status_code=response.status_code,
                        redirect_count=redirect_count,
                        final_url=final_url,
                        redirect_urls=redirect_urls,
                        downgrade_detected=downgrade_detected,
                        ttfb_ms=ttfb_ms,
                        ttlb_ms=total_ms,
                        protocol=protocol,
                        alpn_negotiated=alpn,
                        response_size_bytes=response_size,
                        compressed=compressed,
                        content_encoding=content_encoding,
                        content_type=content_type,
                        security_headers=sec_headers,
                        cdn_fingerprint=cdn,
                        server_header=server,
                        alt_svc=alt_svc,
                        cache_control=cache_control,
                        etag=etag,
                        last_modified=last_modified,
                        age=age,
                        request_id=request_id,
                        assertion_results=assertion_results,
                        dns_resolve_ms=dns_ms if dns_error is None else None,
                        dns_resolver_ip=self.dns_resolver_ip,
                        compressed_size_bytes=compressed_size,
                        redirect_timings=redirect_timings,
                        http2_expected=http2_expected,
                        http2_downgraded=http2_downgraded,
                        query_params=self.query_params,
                    )

                    # Populate connection-level metrics from the timing backend
                    metrics = transport.get_connection_metrics()
                    result.tcp_connect_ms = metrics.get("tcp_connect_ms")
                    result.tls_handshake_ms = metrics.get("tls_handshake_ms")
                    result.ip_version = metrics.get("ip_version")
                    cert_der: Optional[bytes] = metrics.get("cert_der")
                    if cert_der:
                        (
                            cert_days,
                            cert_cn,
                            issuer_cn,
                            sans,
                            wildcard,
                        ) = _parse_cert_der(cert_der)
                        result.cert_expiry_days = cert_days
                        result.cert_cn = cert_cn
                        result.cert_issuer_cn = issuer_cn
                        result.cert_sans = sans
                        result.cert_wildcard = wildcard

                    await self._update_progress()
                    return result

            except httpx.TimeoutException:
                if attempt == self.max_retries:
                    end_time = time.time()
                    assert self._lock is not None
                    async with self._lock:
                        self.failed_targets[target] += 1
                    result = HTTPResult(
                        target=target,
                        method=self.method,
                        start_time=start_time,
                        end_time=end_time,
                        total_ms=(end_time - start_time) * 1000,
                        status=QueryStatus.TIMEOUT,
                        iteration=iteration,
                        attempt_number=attempt + 1,
                        error_message="Request timeout",
                        dns_resolve_ms=dns_ms if dns_error is None else None,
                        dns_resolver_ip=self.dns_resolver_ip,
                    )
                    await self._update_progress()
                    return result
                await asyncio.sleep(
                    self.retry_backoff_base**attempt * self.retry_backoff_multiplier
                )

            except ssl.SSLError as e:
                end_time = time.time()
                assert self._lock is not None
                async with self._lock:
                    self.failed_targets[target] += 1
                result = HTTPResult(
                    target=target,
                    method=self.method,
                    start_time=start_time,
                    end_time=end_time,
                    total_ms=(end_time - start_time) * 1000,
                    status=QueryStatus.TLS_ERROR,
                    iteration=iteration,
                    attempt_number=attempt + 1,
                    error_message=f"TLS error: {e}",
                    dns_resolve_ms=dns_ms if dns_error is None else None,
                    dns_resolver_ip=self.dns_resolver_ip,
                )
                await self._update_progress()
                return result

            except httpx.ConnectError as e:
                end_time = time.time()
                assert self._lock is not None
                async with self._lock:
                    self.failed_targets[target] += 1
                result = HTTPResult(
                    target=target,
                    method=self.method,
                    start_time=start_time,
                    end_time=end_time,
                    total_ms=(end_time - start_time) * 1000,
                    status=QueryStatus.CONNECTION_REFUSED,
                    iteration=iteration,
                    attempt_number=attempt + 1,
                    error_message=str(e),
                    dns_resolve_ms=dns_ms if dns_error is None else None,
                    dns_resolver_ip=self.dns_resolver_ip,
                )
                await self._update_progress()
                return result

            except Exception as e:
                if attempt == self.max_retries:
                    end_time = time.time()
                    assert self._lock is not None
                    async with self._lock:
                        self.failed_targets[target] += 1
                    result = HTTPResult(
                        target=target,
                        method=self.method,
                        start_time=start_time,
                        end_time=end_time,
                        total_ms=(end_time - start_time) * 1000,
                        status=QueryStatus.UNKNOWN_ERROR,
                        iteration=iteration,
                        attempt_number=attempt + 1,
                        error_message=str(e),
                        dns_resolve_ms=dns_ms if dns_error is None else None,
                        dns_resolver_ip=self.dns_resolver_ip,
                    )
                    await self._update_progress()
                    return result
                await asyncio.sleep(
                    self.retry_backoff_base**attempt * self.retry_backoff_multiplier
                )

        # Unreachable fallback
        return HTTPResult(
            target=target,
            method=self.method,
            start_time=start_time,
            end_time=time.time(),
            total_ms=0.0,
            status=QueryStatus.UNKNOWN_ERROR,
            iteration=iteration,
            error_message="Exhausted retries",
            dns_resolve_ms=dns_ms if dns_error is None else None,
            dns_resolver_ip=self.dns_resolver_ip,
        )

    # ------------------------------------------------------------------
    # Warmup
    # ------------------------------------------------------------------

    async def _run_warmup(self, targets: List[str]) -> List[HTTPResult]:
        tasks = [self.request_single(t, iteration=0) for t in targets]
        return list(await asyncio.gather(*tasks))

    async def _run_fast_warmup(self, targets: List[str]) -> List[HTTPResult]:
        original_method = self.method
        self.method = "HEAD"
        try:
            tasks = [self.request_single(t, iteration=0) for t in targets]
            results = list(await asyncio.gather(*tasks))
        finally:
            self.method = original_method
        return results

    # ------------------------------------------------------------------
    # run_benchmark
    # ------------------------------------------------------------------

    async def run_benchmark(
        self,
        targets: List[str],
        iterations: int = 1,
        warmup: bool = False,
        warmup_fast: bool = False,
    ) -> List[HTTPResult]:
        """Run benchmark across all targets for N iterations."""
        if warmup_fast:
            warmup_results = await self._run_fast_warmup(targets)
        elif warmup:
            warmup_results = await self._run_warmup(targets)
        else:
            warmup_results = []

        for r in warmup_results:
            if r.status != QueryStatus.SUCCESS:
                import click

                click.echo(warning(f"Warmup failed: {r.target} → {r.status.value}"))

        self.query_counter = 0
        self.total_queries = len(targets) * iterations

        tasks = [
            self.request_single(target, iteration=i + 1)
            for i in range(iterations)
            for target in targets
        ]

        results = await asyncio.gather(*tasks)
        return list(results)
