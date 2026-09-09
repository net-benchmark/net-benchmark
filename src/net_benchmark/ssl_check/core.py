"""Core SSL/TLS checking functionality.

net-benchmark 0.6.0 — SSL items 1, 2, 3, 4, 5, 33, 34, 35, 38, 40, 41, 54, 57.

Mirrors `dns_benchmark/core.py` and `http_bench/core.py`: a result dataclass, a
target manager, and an async engine with bounded concurrency, retry/backoff and
a progress callback.

Unit of measurement
-------------------
DNS produces one `DNSQueryResult` per query; HTTP one `HTTPResult` per request.
SSL produces one `SSLResult` per **host:port**, not per handshake.

That difference is deliberate. A certificate is a property of the endpoint, not
of an individual handshake, so a row-per-handshake layout would repeat the
whole parsed certificate — SANs, chain, fingerprints — N times in the raw
export for a single scan. Handshake timing, the one thing that genuinely varies
across repetitions, is carried inside the result as a sample list plus a
`LatencyHistogram`, which is also what makes it mergeable across runs.

`measured` and `compliant`
--------------------------
The `responded` / `completed` split that HTTP 0.5.2 introduced applies here
with different names and the same rule:

* **`measured`** — the handshake completed, so timing, version, cipher and
  certificate fields are real. This is what latency aggregates filter on.
* **`compliant`** — the endpoint passed policy. This is what outcome
  aggregates filter on.

Conflating them produces the same class of self-contradictory summary that HTTP
hit: an expired, self-signed certificate on a server that handshakes perfectly
is fully *measured* and not *compliant*, and its handshake latency belongs in
the percentiles. Excluding it because it failed policy would make a badly
configured server look faster than a healthy one.

`compliant` is `Optional[bool]` and is `None` until policy is evaluated.
`None` is not `False`: an unevaluated endpoint has not failed.
"""

from __future__ import annotations

import asyncio
import ssl
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    List,
    Optional,
    Sequence,
    Set,
    Tuple,
)
from urllib.parse import urlparse

# Foundation item 8 relocates LatencyHistogram to a module-neutral package.
# Imported from its current home rather than reimplemented — a second
# histogram would be a second set of merge semantics, and the whole point of
# the primitive is that there is exactly one.
from net_benchmark.http_bench.analysis import LatencyHistogram
from net_benchmark.ssl_check.certificate import (
    CertificateInfo,
    ExpiryAlert,
    HostnameMatch,
    expiry_alert,
    match_hostname,
    parse_certificate,
)
from net_benchmark.ssl_check.handshake import (
    HandshakeResult,
    HandshakeStatus,
    ProbeConfig,
    StartTLSProtocol,
    TLSVersion,
    build_client_context,
    probe_tls,
    starttls_for_port,
)

# ---------------------------------------------------------------------------
# Ports (item 41)
# ---------------------------------------------------------------------------

DEFAULT_SCAN_PORTS: Tuple[int, ...] = (443, 8443, 465, 993, 995, 587, 636)

# Timeouts that indicate the path is being filtered or rate-limited, as opposed
# to a port simply being closed. Only these drive backoff — see
# `SSLCheckEngine._backoff_delay`.
_BACKOFF_STATUSES = frozenset(
    {
        HandshakeStatus.TCP_TIMEOUT,
        HandshakeStatus.HANDSHAKE_TIMEOUT,
        HandshakeStatus.HANDSHAKE_ABANDONED,
    }
)


# ---------------------------------------------------------------------------
# Target
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SSLTarget:
    """One host:port to check, with its TLS entry mode.

    Frozen so it can key the per-host lock and failure maps without a caller
    mutating a live key out from under them.
    """

    host: str
    port: int = 443
    starttls: StartTLSProtocol = StartTLSProtocol.NONE
    # Item 3 — `--resolve host:port:ip`. Pins this target to one address.
    pinned_ip: Optional[str] = None

    def __str__(self) -> str:
        return f"{self.host}:{self.port}"

    @property
    def key(self) -> str:
        return f"{self.host}:{self.port}"


class TargetManager:
    """Parse and validate SSL scan targets.

    Mirrors `http_bench.core.TargetManager` and the DNS
    `ResolverManager`/`DomainManager` pair: accepts an inline comma-separated
    list or a file path, and normalises each entry.
    """

    DEFAULT_TARGETS: List[str] = [
        "www.cloudflare.com",
        "www.google.com",
        "github.com",
        "www.wikipedia.org",
        "www.apple.com",
    ]

    _FILE_SUFFIXES = (".txt", ".csv", ".list", ".conf", ".yaml", ".yml")

    def __init__(self, targets: List[SSLTarget]) -> None:
        self._targets = targets

    @property
    def targets(self) -> List[SSLTarget]:
        return self._targets

    def __len__(self) -> int:
        return len(self._targets)

    @classmethod
    def get_default_targets(cls) -> List[str]:
        return list(cls.DEFAULT_TARGETS)

    @classmethod
    def parse_targets_input(
        cls,
        input_value: Optional[str],
        ports: Optional[Sequence[int]] = None,
        resolve_map: Optional[Dict[str, str]] = None,
    ) -> "TargetManager":
        """Build the host x port matrix from user input.

        `ports` applies only to entries that did not carry an explicit port. A
        target written as `mail.example.com:587` means that one port; expanding
        it across the whole scan list as well would silently multiply the scan
        the user asked for.
        """
        if not input_value:
            raise ValueError("Target input cannot be empty")

        raw = input_value.strip()

        # A comma decides it: this is an inline list, not a path. The
        # file heuristic below tests for "/" anywhere in the string, so a
        # mixed list such as "example.com,https://a.io/x" would otherwise be
        # read as a filename because of the slash inside a later entry.
        # `http_bench.core.TargetManager` still has that defect and raises
        # FileNotFoundError on exactly that input.
        if "," in raw:
            entries = cls._parse_inline(raw)
        elif raw.startswith(("http://", "https://")):
            entries = cls._parse_inline(raw)
        else:
            likely_file = (
                "/" in raw or "\\" in raw or Path(raw).suffix in cls._FILE_SUFFIXES
            )
            if likely_file:
                path = Path(raw)
                if not path.exists() or not path.is_file():
                    raise FileNotFoundError(f"Target file not found: {raw}")
                entries = cls._load_from_file(str(path))
            else:
                entries = cls._parse_inline(raw)

        scan_ports = tuple(ports) if ports else (443,)
        resolve_map = resolve_map or {}

        targets: List[SSLTarget] = []
        seen: Set[Tuple[str, int]] = set()

        for entry in entries:
            host, explicit_port = cls._split_host_port(entry)
            entry_ports = (explicit_port,) if explicit_port is not None else scan_ports
            for port in entry_ports:
                if (host, port) in seen:
                    continue
                seen.add((host, port))
                targets.append(
                    SSLTarget(
                        host=host,
                        port=port,
                        starttls=starttls_for_port(port),
                        pinned_ip=resolve_map.get(f"{host}:{port}")
                        or resolve_map.get(host),
                    )
                )

        if not targets:
            raise ValueError("No usable targets parsed from input")
        return cls(targets)

    @staticmethod
    def _split_host_port(entry: str) -> Tuple[str, Optional[int]]:
        """Normalise one entry to (host, port or None).

        Accepts `example.com`, `example.com:8443`, `https://example.com/path`
        and `[2001:db8::1]:443`. A URL is reduced to its authority: the path is
        meaningless for a TLS handshake, and keeping it would produce a target
        key that never matches the same host reached another way.
        """
        value = entry.strip()
        if not value:
            raise ValueError("Empty target entry")

        if "://" in value:
            parsed = urlparse(value)
            host = parsed.hostname or ""
            if not host:
                raise ValueError(f"Cannot extract host from {entry!r}")
            port = parsed.port
            if port is None and parsed.scheme == "https":
                # Left as None so the caller's --ports still applies; only an
                # explicitly written port pins the target.
                return host, None
            return host, port

        # Bracketed IPv6 literal, optionally with a port.
        if value.startswith("["):
            close = value.find("]")
            if close == -1:
                raise ValueError(f"Unterminated IPv6 literal in {entry!r}")
            host = value[1:close]
            remainder = value[close + 1 :]
            if remainder.startswith(":"):
                return host, int(remainder[1:])
            return host, None

        # A bare IPv6 literal has multiple colons and no port.
        if value.count(":") > 1:
            return value, None

        if ":" in value:
            host, _, port_text = value.partition(":")
            if not port_text.isdigit():
                raise ValueError(f"Invalid port in {entry!r}")
            return host, int(port_text)

        return value, None

    @staticmethod
    def _load_from_file(file_path: str) -> List[str]:
        with open(file_path, encoding="utf-8") as handle:
            return [
                line.strip()
                for line in handle
                if line.strip() and not line.startswith("#")
            ]

    @staticmethod
    def _parse_inline(targets_str: str) -> List[str]:
        seen: Set[str] = set()
        result: List[str] = []
        for part in targets_str.split(","):
            value = part.strip()
            if value and value not in seen:
                seen.add(value)
                result.append(value)
        return result


def parse_resolve_flags(values: Iterable[str]) -> Dict[str, str]:
    """Parse `--resolve host:port:ip` values into a lookup map (item 3).

    Both `host:port` and bare `host` keys are produced, so a single
    `--resolve example.com:443:192.0.2.1` also pins a scan of that host on
    other ports unless a more specific entry overrides it.
    """
    resolve_map: Dict[str, str] = {}
    for value in values:
        parts = value.split(":")
        if len(parts) < 3:
            raise ValueError(f"invalid --resolve {value!r}; expected 'host:port:ip'")
        host = parts[0]
        port = parts[1]
        ip = ":".join(parts[2:])  # IPv6 literals contain colons
        if not port.isdigit():
            raise ValueError(f"invalid port in --resolve {value!r}")
        resolve_map[f"{host}:{port}"] = ip
        resolve_map.setdefault(host, ip)
    return resolve_map


# ---------------------------------------------------------------------------
# Result
# ---------------------------------------------------------------------------


@dataclass
class SSLResult:
    """Result of checking one host:port.

    Field layout mirrors `HTTPResult` and `DNSQueryResult`: identity, then
    timing, then protocol facts, then verdicts. Verdicts are held apart from
    the facts that produced them so a consumer can re-derive a verdict under
    different policy without re-running the scan.
    """

    # --- identity ---
    host: str
    port: int
    starttls: StartTLSProtocol
    status: HandshakeStatus
    start_time: float
    end_time: float
    check_id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    resolved_ip: Optional[str] = None
    ip_version: Optional[int] = None
    error_message: Optional[str] = None
    attempt_number: int = 1

    # --- gates (see module docstring) ---
    # Handshake completed; timing/protocol/certificate fields are real.
    measured: bool = False
    # Policy verdict. None until evaluated — never defaulted to False.
    compliant: Optional[bool] = None
    policy_failures: List[str] = field(default_factory=list)

    # --- timing (ms) ---
    dns_ms: Optional[float] = None
    tcp_connect_ms: Optional[float] = None
    starttls_ms: Optional[float] = None
    # First (or only) handshake. Kept separate from the aggregate below so a
    # single-sample scan still reports something meaningful.
    handshake_ms: Optional[float] = None
    total_ms: Optional[float] = None

    # --- handshake timing distribution (items 38, 57) ---
    handshake_samples_ms: List[float] = field(default_factory=list)
    handshake_histogram: Optional[LatencyHistogram] = None
    # Percentiles are None, not 0.0, when there are too few samples to report
    # them. Same rule as foundation item 15: a percentile over three samples
    # printed identically to one over three hundred is the failure class the
    # 0.5.2 threshold work removed.
    handshake_min_ms: Optional[float] = None
    handshake_mean_ms: Optional[float] = None
    handshake_median_ms: Optional[float] = None
    handshake_p95_ms: Optional[float] = None
    handshake_p99_ms: Optional[float] = None
    handshake_samples_refused: bool = False

    # --- negotiated (items 33, 34, 35) ---
    tls_version: TLSVersion = TLSVersion.UNKNOWN
    tls_version_deprecated: bool = False
    cipher_name: Optional[str] = None
    cipher_protocol: Optional[str] = None
    cipher_bits: Optional[int] = None
    # IANA code point for the negotiated suite (item 34).
    cipher_id: Optional[int] = None
    alpn_protocol: Optional[str] = None
    forward_secrecy: Optional[bool] = None

    # --- session (items 4, 47) ---
    session_reused: Optional[bool] = None
    session_id: Optional[str] = None
    # Set only when a deliberate resumption probe ran. None means not tested,
    # which is distinct from "does not resume".
    resumption_supported: Optional[bool] = None

    # --- bytes on the wire (item 54) ---
    handshake_bytes_sent: int = 0
    handshake_bytes_received: int = 0
    starttls_bytes_sent: int = 0
    starttls_bytes_received: int = 0
    # Total DER size of every certificate the peer sent. None when the chain
    # is not observable — see handshake.py on the 3.13 requirement.
    chain_bytes: Optional[int] = None

    # --- certificate ---
    certificate: Optional[CertificateInfo] = None
    hostname_match: HostnameMatch = HostnameMatch.NOT_CHECKED
    # Item 42. UNKNOWN when no certificate was observed — never EXPIRED.
    expiry_alert: ExpiryAlert = ExpiryAlert.UNKNOWN
    peer_offered_no_certificate: bool = False

    # --- chain (items 19-26 consume this; 0.6.0 only observes it) ---
    chain_observed: bool = False
    chain_length: Optional[int] = None
    chain_unavailable_reason: Optional[str] = None
    chain_certificates: List[CertificateInfo] = field(default_factory=list)

    @property
    def target(self) -> str:
        return f"{self.host}:{self.port}"

    @property
    def days_remaining(self) -> Optional[int]:
        if self.certificate is None or self.certificate.lifetime is None:
            return None
        return self.certificate.lifetime.days_remaining

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "host": self.host,
            "port": self.port,
            "starttls": self.starttls.value,
            "status": self.status.value,
            "check_id": self.check_id,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "resolved_ip": self.resolved_ip,
            "ip_version": self.ip_version,
            "error_message": self.error_message,
            "attempt_number": self.attempt_number,
            "measured": self.measured,
            "compliant": self.compliant,
            "policy_failures": list(self.policy_failures),
            "dns_ms": self.dns_ms,
            "tcp_connect_ms": self.tcp_connect_ms,
            "starttls_ms": self.starttls_ms,
            "handshake_ms": self.handshake_ms,
            "total_ms": self.total_ms,
            "handshake_sample_count": len(self.handshake_samples_ms),
            "handshake_min_ms": self.handshake_min_ms,
            "handshake_mean_ms": self.handshake_mean_ms,
            "handshake_median_ms": self.handshake_median_ms,
            "handshake_p95_ms": self.handshake_p95_ms,
            "handshake_p99_ms": self.handshake_p99_ms,
            "handshake_samples_refused": self.handshake_samples_refused,
            "handshake_histogram": (
                self.handshake_histogram.to_dict()
                if self.handshake_histogram is not None
                else None
            ),
            "tls_version": self.tls_version.value,
            "tls_version_deprecated": self.tls_version_deprecated,
            "cipher_name": self.cipher_name,
            "cipher_protocol": self.cipher_protocol,
            "cipher_bits": self.cipher_bits,
            "cipher_id": self.cipher_id,
            "cipher_iana_hex": (
                f"0x{self.cipher_id:04x}" if self.cipher_id is not None else None
            ),
            "alpn_protocol": self.alpn_protocol,
            "forward_secrecy": self.forward_secrecy,
            "session_reused": self.session_reused,
            "session_id": self.session_id,
            "resumption_supported": self.resumption_supported,
            "handshake_bytes_sent": self.handshake_bytes_sent,
            "handshake_bytes_received": self.handshake_bytes_received,
            "handshake_bytes_total": (
                self.handshake_bytes_sent + self.handshake_bytes_received
            ),
            "starttls_bytes_sent": self.starttls_bytes_sent,
            "starttls_bytes_received": self.starttls_bytes_received,
            "chain_bytes": self.chain_bytes,
            "hostname_match": self.hostname_match.value,
            "expiry_alert": self.expiry_alert.value,
            "peer_offered_no_certificate": self.peer_offered_no_certificate,
            "chain_observed": self.chain_observed,
            "chain_length": self.chain_length,
            "chain_unavailable_reason": self.chain_unavailable_reason,
            "certificate": (
                self.certificate.to_dict() if self.certificate is not None else None
            ),
            "chain_certificates": [c.to_dict() for c in self.chain_certificates],
        }


def detect_forward_secrecy(
    version: TLSVersion,
    cipher_name: Optional[str],
) -> Optional[bool]:
    """Infer forward secrecy from the negotiated suite (item 35).

    Every TLS 1.3 cipher suite uses an ephemeral key exchange, and the TLS 1.3
    suite names (`TLS_AES_256_GCM_SHA384`) deliberately carry no key-exchange
    component. So the suite name cannot be inspected for `ECDHE` under TLS 1.3;
    the version itself is the answer. Reading the name alone would report every
    TLS 1.3 server as lacking forward secrecy — the strongest configurations in
    the tool flagged as the weakest.

    Returns None when the version is unknown or no cipher was negotiated,
    because an inference from missing data is a guess, not a measurement.
    """
    if version is TLSVersion.TLSV1_3:
        return True
    if cipher_name is None or version is TLSVersion.UNKNOWN:
        return None
    upper = cipher_name.upper()
    return "ECDHE" in upper or "DHE" in upper


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class SSLCheckEngine:
    """Async TLS checking engine with bounded fan-out and backoff.

    Mirrors `DNSQueryEngine` and `HTTPBenchmarkEngine`: lazily created asyncio
    primitives, a semaphore, retry with exponential backoff, and a progress
    callback isolated from consumer exceptions.
    """

    def __init__(
        self,
        max_concurrent: int = 20,
        connect_timeout: float = 10.0,
        handshake_timeout: float = 15.0,
        starttls_timeout: float = 15.0,
        max_retries: int = 1,
        retry_backoff_multiplier: float = 0.5,
        retry_backoff_base: float = 2.0,
        # Item 38 — handshakes per target for the timing distribution.
        handshake_samples: int = 1,
        # Item 4 — discarded handshakes before measurement begins.
        warmup_handshakes: int = 1,
        # Item 57 — refuse percentiles below this many samples.
        min_samples: int = 5,
        # Item 2 — serialise all ports of one host instead of fanning out
        # across them. Halves throughput; the correct default for scanning
        # someone else's infrastructure, which is why it is offered at all.
        per_host_serial: bool = False,
        # Item 2 — pause before re-probing a host that has timed out.
        backoff_on_timeout: bool = True,
        # Item 4/47 — run a dedicated pair of handshakes to test resumption.
        check_resumption: bool = False,
        # Window spent reading after the session-capture handshake. Under TLS
        # 1.3 the NewSessionTicket is a post-handshake message, so a session
        # captured without this drain is not resumable and the probe would
        # report every TLS 1.3 server as not resuming.
        resumption_drain_s: float = 0.5,
        # Foundation item 9. Raise PermissionError to block an address.
        address_policy: Optional[Callable[[str], None]] = None,
        alpn_protocols: Optional[List[str]] = None,
        min_version: Optional[ssl.TLSVersion] = None,
        max_version: Optional[ssl.TLSVersion] = None,
        cipher_string: Optional[str] = None,
        send_sni: bool = True,
        server_hostname: Optional[str] = None,
        # Item 55 — --as-of. A fixed evaluation instant for every lifetime and
        # expiry-alert verdict in the run, rather than each call reading
        # wall-clock time independently.
        #
        # Independent reads is not a hypothetical: a scan spanning several
        # minutes across many targets would otherwise judge earlier targets
        # against an earlier "now" than later ones, so the SAME certificate
        # could report a different days_remaining depending only on where it
        # fell in the run — and a threshold gate evaluated after the run
        # completes would be checking a lifetime that has already drifted out
        # from under it by the run's own duration.
        #
        # None means "now, read once at construction" — not "read live on
        # every call" — for exactly that reason: a `None` sentinel threaded
        # through per-call would still leave every call reading the clock
        # independently, reintroducing the drift this parameter exists to
        # remove.
        as_of: Optional[datetime] = None,
    ) -> None:
        self.max_concurrent = max_concurrent
        self.connect_timeout = connect_timeout
        self.handshake_timeout = handshake_timeout
        self.starttls_timeout = starttls_timeout
        self.max_retries = max_retries
        self.retry_backoff_multiplier = retry_backoff_multiplier
        self.retry_backoff_base = retry_backoff_base
        self.handshake_samples = max(1, handshake_samples)
        self.warmup_handshakes = max(0, warmup_handshakes)
        self.min_samples = max(1, min_samples)
        self.per_host_serial = per_host_serial
        self.backoff_on_timeout = backoff_on_timeout
        self.check_resumption = check_resumption
        self.resumption_drain_s = resumption_drain_s
        self.address_policy = address_policy
        self.alpn_protocols = alpn_protocols
        self.min_version = min_version
        self.max_version = max_version
        self.cipher_string = cipher_string
        self.send_sni = send_sni
        self.server_hostname = server_hostname
        # Resolved once here — see the as_of parameter docstring above for
        # why a live default computed per-call would defeat the point.
        self.as_of: datetime = (
            as_of if as_of is not None else datetime.now(tz=timezone.utc)
        )

        # Lazily created inside a running loop, matching DNSQueryEngine — an
        # asyncio.Semaphore constructed at import time binds to whichever loop
        # happens to be current, which is the wrong one under `asyncio.run`.
        self.semaphore: Optional[asyncio.Semaphore] = None
        self._lock: Optional[asyncio.Lock] = None
        self._host_locks: Dict[str, asyncio.Lock] = {}

        self.progress_callback: Optional[Callable[[int, int], None]] = None
        self.check_counter = 0
        self.total_checks = 0
        # Progress ticks dropped because the consumer callback raised. Exposed
        # for the same reason DNSQueryEngine.progress_errors is: a silently
        # broken consumer should be visible after the run rather than never.
        self.progress_errors = 0

        # Consecutive timeout-class failures per host, driving backoff.
        self.failed_hosts: Dict[str, int] = defaultdict(int)

    # -- plumbing ---------------------------------------------------------

    def set_progress_callback(self, callback: Callable[[int, int], None]) -> None:
        self.progress_callback = callback

    async def _ensure_async_primitives(self) -> None:
        if self.semaphore is None:
            self.semaphore = asyncio.Semaphore(self.max_concurrent)
        if self._lock is None:
            self._lock = asyncio.Lock()

    def _host_lock(self, host: str) -> asyncio.Lock:
        """Per-host lock for `per_host_serial`.

        Created without awaiting between the membership test and the insert.
        That is what makes the check-then-create safe here: asyncio will not
        preempt a coroutine except at an await point, so no second task can
        observe the gap. Adding an await inside this method would introduce a
        race in which two tasks each create a lock and neither excludes the
        other.
        """
        lock = self._host_locks.get(host)
        if lock is None:
            lock = asyncio.Lock()
            self._host_locks[host] = lock
        return lock

    async def _update_progress(self) -> None:
        """Advance the progress counter and notify the consumer.

        The callback is invoked OUTSIDE the lock and guarded against
        exceptions, following `DNSQueryEngine._update_progress`. The HTTP
        engine still calls it inside the lock and unguarded; that is the older
        shape and is not the one to copy — a consumer doing real work in the
        callback would otherwise serialise every completion in the run behind
        it, and a raising callback would kill the check.
        """
        await self._ensure_async_primitives()
        assert self._lock is not None
        async with self._lock:
            self.check_counter += 1
            completed = self.check_counter
            total = self.total_checks
            callback = self.progress_callback

        if callback is None:
            return
        try:
            callback(completed, total)
        except Exception:  # noqa: BLE001
            self.progress_errors += 1

    def _probe_config(
        self,
        target: SSLTarget,
        *,
        session: Optional[ssl.SSLSession] = None,
        drain: float = 0.0,
    ) -> ProbeConfig:
        return ProbeConfig(
            connect_timeout=self.connect_timeout,
            handshake_timeout=self.handshake_timeout,
            starttls_timeout=self.starttls_timeout,
            server_hostname=self.server_hostname,
            send_sni=self.send_sni,
            min_version=self.min_version,
            max_version=self.max_version,
            cipher_string=self.cipher_string,
            alpn_protocols=self.alpn_protocols,
            pinned_ip=target.pinned_ip,
            post_handshake_drain_s=drain,
            session=session,
            address_policy=self.address_policy,
        )

    async def _backoff_delay(self, host: str) -> None:
        """Sleep before re-probing a host that has been timing out (item 2).

        Only timeout-class failures count. A refused connection is fast,
        informative and entirely normal during a multi-port scan — most hosts
        have most of the scan ports closed — so backing off on it would make
        every scan crawl for no reason. A timeout is the signal that the path
        is filtered or the target is shedding load, and that is the case worth
        slowing down for.
        """
        if not self.backoff_on_timeout:
            return
        failures = self.failed_hosts.get(host, 0)
        if failures <= 0:
            return
        delay = self.retry_backoff_multiplier * (
            self.retry_backoff_base ** min(failures - 1, 6)
        )
        await asyncio.sleep(delay)

    def _record_outcome(self, host: str, status: HandshakeStatus) -> None:
        if status in _BACKOFF_STATUSES:
            self.failed_hosts[host] += 1
        elif status is HandshakeStatus.OK:
            self.failed_hosts.pop(host, None)

    # -- single target ----------------------------------------------------

    async def check_target(self, target: SSLTarget) -> SSLResult:
        """Check one host:port, including warm-up and timing samples.

        Concurrency is bounded here rather than by the caller so that every
        entry point — CLI, SaaS, a future monitoring loop — inherits the same
        limit without restating it.
        """
        await self._ensure_async_primitives()
        assert self.semaphore is not None

        if self.per_host_serial:
            async with self._host_lock(target.host):
                async with self.semaphore:
                    return await self._check_locked(target)
        async with self.semaphore:
            return await self._check_locked(target)

    async def _check_locked(self, target: SSLTarget) -> SSLResult:
        start_wall = time.time()
        start = time.perf_counter()

        await self._backoff_delay(target.host)

        # A single SSLContext is reused across every sample for this target.
        # That does NOT cause resumption: an OpenSSL client only resumes when a
        # session is explicitly handed to `wrap_bio(session=...)`, which the
        # timing samples never do. Verified — without an explicit session,
        # `session_reused` is False on every repeat. So all samples below are
        # full handshakes, which is the whole point of item 38.
        context = build_client_context(self._probe_config(target))

        # --- warm-up (item 4) ---------------------------------------------
        # Discarded. Its purpose is route cache, ARP, server-side accept path
        # and any first-connection cost on the target, none of which should
        # land in a percentile that is meant to describe steady state.
        for _ in range(self.warmup_handshakes):
            try:
                await probe_tls(
                    target.host,
                    target.port,
                    starttls=target.starttls,
                    config=self._probe_config(target),
                    context=context,
                )
            except Exception:  # noqa: BLE001 — a failed warm-up is not a result
                break

        # --- measured handshakes (item 38) --------------------------------
        samples: List[float] = []
        last: Optional[HandshakeResult] = None
        attempt = 1

        for index in range(self.handshake_samples):
            probe = await self._probe_with_retry(target, context)
            attempt = max(attempt, probe[1])
            handshake = probe[0]
            last = handshake
            if handshake.status is HandshakeStatus.OK and (
                handshake.handshake_ms is not None
            ):
                samples.append(handshake.handshake_ms)
            elif index == 0:
                # First sample failed: the endpoint is not measurable, and
                # repeating the same failure N times only multiplies the load
                # on a target that already is not answering.
                break

        assert last is not None
        self._record_outcome(target.host, last.status)

        result = self._build_result(target, last, samples, start_wall, start, attempt)

        # --- resumption probe (items 4, 47) -------------------------------
        if self.check_resumption and result.measured:
            result.resumption_supported = await self._probe_resumption(target, context)

        await self._update_progress()
        return result

    async def _probe_with_retry(
        self,
        target: SSLTarget,
        context: ssl.SSLContext,
    ) -> Tuple[HandshakeResult, int]:
        """Probe with bounded retry, returning (result, attempts_used).

        Only timeout-class failures are retried. Retrying a refused connection
        or a TLS version rejection just repeats a deterministic answer, and a
        `STARTTLS_UNSUPPORTED` verdict is a finding about the target that will
        not change on the second try.
        """
        attempt = 1
        while True:
            handshake = await probe_tls(
                target.host,
                target.port,
                starttls=target.starttls,
                config=self._probe_config(target),
                context=context,
            )
            if handshake.status not in _BACKOFF_STATUSES:
                return handshake, attempt
            if attempt > self.max_retries:
                return handshake, attempt
            delay = self.retry_backoff_multiplier * (
                self.retry_backoff_base ** (attempt - 1)
            )
            await asyncio.sleep(delay)
            attempt += 1

    async def _probe_resumption(
        self,
        target: SSLTarget,
        context: ssl.SSLContext,
    ) -> Optional[bool]:
        """Capture a resumable session, then offer it back (items 4, 47).

        Owns BOTH handshakes rather than reusing a session from the timing
        samples. Those run with no post-handshake drain, so under TLS 1.3 the
        session they capture predates the NewSessionTicket and is not
        resumable — offering it back reports `session_reused=False` for a
        server that resumes perfectly well.

        That is not hypothetical: an earlier version of this method took the
        last timing sample's session and returned False for every TLS 1.3
        target. Owning the capture is what makes the drain impossible to
        forget, rather than a precondition stated in a docstring elsewhere.

        Returns None whenever either handshake fails to complete. A connection
        that did not finish has established nothing about resumption support,
        and False would assert the server refused to resume.
        """
        try:
            first = await probe_tls(
                target.host,
                target.port,
                starttls=target.starttls,
                config=self._probe_config(target, drain=self.resumption_drain_s),
                context=context,
            )
        except Exception:  # noqa: BLE001
            return None
        if first.status is not HandshakeStatus.OK or first.session is None:
            return None

        try:
            second = await probe_tls(
                target.host,
                target.port,
                starttls=target.starttls,
                config=self._probe_config(target, session=first.session),
                context=context,
            )
        except Exception:  # noqa: BLE001
            return None
        if second.status is not HandshakeStatus.OK:
            return None
        return bool(second.session_reused)

    # -- result assembly --------------------------------------------------

    def _build_result(
        self,
        target: SSLTarget,
        handshake: HandshakeResult,
        samples: List[float],
        start_wall: float,
        start_perf: float,
        attempt: int,
    ) -> SSLResult:
        result = SSLResult(
            host=target.host,
            port=target.port,
            starttls=target.starttls,
            status=handshake.status,
            start_time=start_wall,
            end_time=time.time(),
            resolved_ip=handshake.resolved_ip,
            ip_version=handshake.ip_version,
            error_message=handshake.error_message,
            attempt_number=attempt,
            measured=handshake.status is HandshakeStatus.OK,
            dns_ms=handshake.dns_ms,
            tcp_connect_ms=handshake.tcp_connect_ms,
            starttls_ms=handshake.starttls_ms,
            handshake_ms=handshake.handshake_ms,
            total_ms=(time.perf_counter() - start_perf) * 1000.0,
            tls_version=handshake.tls_version,
            tls_version_deprecated=handshake.tls_version.is_deprecated,
            cipher_name=handshake.cipher_name,
            cipher_protocol=handshake.cipher_protocol,
            cipher_bits=handshake.cipher_bits,
            cipher_id=handshake.cipher_id,
            alpn_protocol=handshake.alpn_protocol,
            session_reused=handshake.session_reused,
            session_id=handshake.session_id,
            handshake_bytes_sent=handshake.handshake_bytes_sent,
            handshake_bytes_received=handshake.handshake_bytes_received,
            starttls_bytes_sent=handshake.starttls_bytes_sent,
            starttls_bytes_received=handshake.starttls_bytes_received,
            peer_offered_no_certificate=handshake.peer_offered_no_certificate,
            chain_unavailable_reason=handshake.chain_unavailable_reason,
        )

        result.forward_secrecy = detect_forward_secrecy(
            handshake.tls_version, handshake.cipher_name
        )

        self._apply_samples(result, samples)
        self._apply_certificates(result, target, handshake)
        return result

    def _apply_samples(self, result: SSLResult, samples: List[float]) -> None:
        """Populate the handshake timing distribution (items 38, 57)."""
        result.handshake_samples_ms = list(samples)
        if not samples:
            return

        histogram = LatencyHistogram.from_values(samples)
        result.handshake_histogram = histogram
        result.handshake_min_ms = min(samples)
        result.handshake_mean_ms = histogram.mean

        if len(samples) < self.min_samples:
            # Item 57. Mean and min stay: both are exact at any sample count.
            # Percentiles do not, so they are left None rather than computed
            # from too few observations and printed indistinguishably from a
            # percentile over thousands.
            result.handshake_samples_refused = True
            return

        result.handshake_median_ms = histogram.quantile(0.50)
        result.handshake_p95_ms = histogram.quantile(0.95)
        result.handshake_p99_ms = histogram.quantile(0.99)

    def _apply_certificates(
        self,
        result: SSLResult,
        target: SSLTarget,
        handshake: HandshakeResult,
    ) -> None:
        """Parse the leaf and any observable chain onto the result.

        Every parse in this method is evaluated against `self.as_of`, not
        wall-clock time read independently per call — see item 55 and the
        as_of parameter docstring on __init__.
        """
        if handshake.leaf_der is not None:
            try:
                result.certificate = parse_certificate(
                    handshake.leaf_der, now=self.as_of
                )
            except ValueError as exc:
                result.error_message = (
                    f"{result.error_message + '; ' if result.error_message else ''}"
                    f"leaf certificate unparseable: {exc}"
                )

        if result.certificate is not None:
            hostname = self.server_hostname or target.host
            result.hostname_match = match_hostname(result.certificate, hostname)
            result.expiry_alert = expiry_alert(result.certificate.lifetime)

        chain = handshake.peer_chain_der
        if chain is None:
            result.chain_observed = False
            # chain_bytes stays None. Reporting 0 would say the server sent no
            # certificate bytes, which is a measurement it did not make.
            return

        result.chain_observed = True
        result.chain_length = len(chain)
        result.chain_bytes = sum(len(entry) for entry in chain)
        for der in chain:
            try:
                result.chain_certificates.append(parse_certificate(der, now=self.as_of))
            except ValueError:
                # A malformed intermediate is itself a finding; the position is
                # preserved by continuing rather than aborting the chain.
                continue

    # -- batch ------------------------------------------------------------

    async def check_targets(self, targets: Sequence[SSLTarget]) -> List[SSLResult]:
        """Check every target, bounded by the semaphore.

        The semaphore bounds the host x port **product**, not the host list.
        A 50-host scan across 7 ports is 350 connections; bounding by host
        would let 50 hosts x 7 ports run at once and turn the scanner into the
        thing being measured (item 2).
        """
        await self._ensure_async_primitives()
        self.total_checks = len(targets)
        self.check_counter = 0

        tasks = [asyncio.create_task(self.check_target(t)) for t in targets]
        gathered = await asyncio.gather(*tasks, return_exceptions=True)

        results: List[SSLResult] = []
        for target, outcome in zip(targets, gathered):
            if isinstance(outcome, BaseException):
                # An engine bug, not a target failure. Surfaced as a result
                # rather than swallowed so a partial scan is still usable and
                # the failure is attributable to a specific target.
                now = time.time()
                results.append(
                    SSLResult(
                        host=target.host,
                        port=target.port,
                        starttls=target.starttls,
                        status=HandshakeStatus.TCP_ERROR,
                        start_time=now,
                        end_time=now,
                        error_message=f"{type(outcome).__name__}: {outcome}",
                    )
                )
            else:
                results.append(outcome)
        return results

    def get_failed_hosts(self) -> Dict[str, int]:
        """Hosts with outstanding timeout-class failures, and their counts."""
        return dict(self.failed_hosts)


# ---------------------------------------------------------------------------
# Policy evaluation
# ---------------------------------------------------------------------------


@dataclass
class PolicyConfig:
    """Thresholds applied to decide `SSLResult.compliant` (item 50).

    Deliberately separate from `SSLCheckEngine`: the engine measures, this
    decides. Keeping them apart is what lets a stored raw result be re-judged
    under different policy without re-scanning, which the baseline store
    (foundation item 7) needs.
    """

    min_days_remaining: Optional[int] = None
    max_cert_lifetime_days: Optional[int] = None
    min_tls_version: Optional[TLSVersion] = None
    expected_issuer: Optional[str] = None
    expected_fingerprint: Optional[str] = None
    require_hostname_match: bool = True
    require_forward_secrecy: bool = False
    reject_weak_key: bool = True
    reject_weak_signature: bool = True
    reject_deprecated_tls: bool = True
    require_revocation_source: bool = False


# Ordering for --min-tls-version comparisons. UNKNOWN is absent on purpose:
# an unknown version cannot be ordered against a floor, and forcing it into
# the ordering would make it either always pass or always fail.
_TLS_ORDER: Dict[TLSVersion, int] = {
    TLSVersion.SSLV3: 0,
    TLSVersion.TLSV1_0: 1,
    TLSVersion.TLSV1_1: 2,
    TLSVersion.TLSV1_2: 3,
    TLSVersion.TLSV1_3: 4,
}


def evaluate_policy(result: SSLResult, policy: PolicyConfig) -> SSLResult:
    """Set `compliant` and `policy_failures` on `result`, in place.

    Leaves `compliant` as None when the endpoint was never measured. A target
    that did not answer has not failed policy — it has not been assessed, and
    reporting it as non-compliant would put an unreachable host and an expired
    certificate in the same bucket.
    """
    if not result.measured:
        return result

    failures: List[str] = []

    if policy.reject_deprecated_tls and result.tls_version_deprecated:
        failures.append(f"deprecated TLS version {result.tls_version.value}")

    if policy.min_tls_version is not None:
        floor = _TLS_ORDER.get(policy.min_tls_version)
        actual = _TLS_ORDER.get(result.tls_version)
        if floor is not None and actual is not None and actual < floor:
            failures.append(
                f"TLS {result.tls_version.value} below floor "
                f"{policy.min_tls_version.value}"
            )

    if policy.require_forward_secrecy and result.forward_secrecy is False:
        failures.append("no forward secrecy in negotiated cipher suite")

    if policy.require_hostname_match and result.hostname_match not in (
        HostnameMatch.MATCH,
        HostnameMatch.NOT_CHECKED,
    ):
        failures.append(f"hostname {result.hostname_match.value}")

    certificate = result.certificate
    if certificate is None:
        if result.peer_offered_no_certificate:
            failures.append("peer offered no certificate")
        result.policy_failures = failures
        result.compliant = not failures
        return result

    if policy.reject_weak_key and certificate.public_key.weak:
        failures.append(certificate.public_key.weak_reason or "weak public key")

    if policy.reject_weak_signature and certificate.signature_weak:
        failures.append(certificate.signature_weak_reason or "weak signature algorithm")

    lifetime = certificate.lifetime
    if lifetime is not None:
        if lifetime.expired:
            failures.append("certificate expired")
        if lifetime.not_yet_valid:
            failures.append("certificate not yet valid")
        if (
            policy.min_days_remaining is not None
            and lifetime.days_remaining < policy.min_days_remaining
        ):
            failures.append(
                f"{lifetime.days_remaining} days remaining, below "
                f"{policy.min_days_remaining}"
            )
        if (
            policy.max_cert_lifetime_days is not None
            and lifetime.lifetime_days > policy.max_cert_lifetime_days
        ):
            failures.append(
                f"certificate lifetime {lifetime.lifetime_days} days exceeds "
                f"{policy.max_cert_lifetime_days}"
            )

    if policy.expected_issuer is not None:
        haystack = (certificate.issuer_dn or "").lower()
        if policy.expected_issuer.lower() not in haystack:
            failures.append(
                f"issuer {certificate.issuer_cn or certificate.issuer_dn!r} does "
                f"not match expected {policy.expected_issuer!r}"
            )

    if policy.expected_fingerprint is not None and certificate.fingerprints:
        expected = policy.expected_fingerprint.strip().lower().replace(":", "")
        actual_values = {
            certificate.fingerprints.cert_sha256.lower(),
            certificate.fingerprints.spki_sha256.lower(),
            certificate.fingerprints.spki_sha256_b64,
        }
        if expected not in {v.lower() for v in actual_values}:
            failures.append("certificate fingerprint does not match expected value")

    if policy.require_revocation_source and not certificate.revocation.has_any_source:
        # Short-lived certificates are exempt under the CA/B Baseline
        # Requirements, so demanding a revocation source from one would report
        # a correctly issued modern certificate as a finding. That is exactly
        # the mistake item 30 exists to prevent.
        if not (lifetime is not None and lifetime.short_lived):
            failures.append("no OCSP or CRL revocation source in certificate")

    result.policy_failures = failures
    result.compliant = not failures
    return result


def iso_timestamp(epoch: float) -> str:
    """Render a wall-clock epoch for export."""
    return datetime.fromtimestamp(epoch).isoformat()


__all__ = [
    "DEFAULT_SCAN_PORTS",
    "PolicyConfig",
    "SSLCheckEngine",
    "SSLResult",
    "SSLTarget",
    "TargetManager",
    "detect_forward_secrecy",
    "evaluate_policy",
    "iso_timestamp",
    "parse_resolve_flags",
]
