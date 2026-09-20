"""TLS deep introspection via CryptoLyzer, behind the `[crypto]` extra.

net-benchmark 0.6.2 -- ROADMAP.md items 1-9 ("Handshake internals ... this
is why the extra exists"): negotiable named groups, DH parameters and
ephemeral key reuse, renegotiation and protocol extensions, signature
algorithm probing, TLS 1.3 cipher suite enumeration, and version/draft
detection.

Why CryptoLyzer, and what "behind `[crypto]`" means
-------------------------------------------------------
Everything here reaches past what stdlib `ssl` (OpenSSL-bound) can ever
observe. OpenSSL only ever negotiates what OpenSSL itself supports;
CryptoLyzer implements the TLS wire protocol independently, so it can probe
named groups, DH parameters, extensions and cipher suites OpenSSL's client
API has no way to individually request at all -- including deliberately
obsolete or experimental ones. (See CryptoLyzer's own "what is it and what
is it not" documentation: it is an *analyzer*, not a secure client, by
design.) This module is never imported at the top of an always-loaded
file; every entry point here imports `cryptolyzer` lazily and reports
`DeepIntrospectionAvailability.NOT_INSTALLED` when it's absent -- same
pattern as `lint.py` and pkilint.

Dependency audit (0.6.2 item 0) -- done, not assumed
---------------------------------------------------------
Checked before writing this module, not taken on faith:

- Full resolved dependency tree (`attrs`, `beautifulsoup4`, `certvalidator`,
  `colorama`, `cryptoparser`, `dnspython`, `oscrypto`, `pycryptodome`,
  `pyfakefs`, `python-dateutil`, `requests`, `urllib3`, `asn1crypto`) is
  entirely MIT/BSD/Apache-2.0/ISC/MPL-2.0 -- confirmed via `pip-licenses`
  against the actual resolved tree, not the roadmap's own (now slightly
  stale -- it doesn't name `pycryptodome`/`beautifulsoup4`/`attrs`/
  `urllib3`) list.
- The roadmap's own named risk is real, and was reproduced and root-caused
  rather than taken on faith: `oscrypto`'s libcrypto version-detection
  regex (`\\d\\.\\d\\.\\d[a-z]*`, written for OpenSSL's old `1.1.1k`-style
  versioning) does not match OpenSSL 3.0.13's multi-digit patch number, so
  `cryptolyzer.tls.pubkeys` / `cryptolyzer.tls.pubkeyreq` (which pull in
  `certvalidator` -> `oscrypto.asymmetric`) fail to import at all on a
  current, ordinary Debian/Ubuntu OpenSSL 3.0.x build. Not fixed in any
  released `oscrypto` version as of this check (1.3.0 is latest).
- That failure is isolated and does not block this module: every other TLS
  submodule this module uses (`ciphers`, `versions`, `curves`, `dhparams`,
  `extensions`, `sigalgos`) imports and runs cleanly -- confirmed with real
  handshakes against a live target and a local test server, not just an
  import check. net-benchmark does not need CryptoLyzer's own
  certificate/pubkey analysis regardless -- `certificate.py`/`chain.py` are
  already this project's single certificate parser, by its own stated
  0.6.0 design -- so the one broken import path was never going to be used
  here. `pubkeys`/`pubkeyreq` are never imported by this module for that
  reason. Still open: verifying the same tree against OpenSSL 3.5+ and
  Python 3.14, which this environment doesn't have to test against.

Scope note: implicit TLS only, for now
-------------------------------------------
CryptoLyzer has its own STARTTLS-capable client classes
(`L7ClientSMTPS`/`L7ClientIMAPS`/`L7ClientPOP3S`/`L7ClientFTPS`/
`L7ClientLDAPS`), separate from `handshake.py`'s. Only `L7ClientTls`
(implicit TLS) is wired in this pass; mapping `StartTLSProtocol` to the
matching CryptoLyzer client class is a small, contained follow-up, not
attempted here to keep this pass reviewable.

Concurrency: a synchronous library behind an executor
-----------------------------------------------------------
CryptoLyzer's analyzers block on real socket I/O; the rest of this engine
is asyncio-based. Each analyzer call runs via
`loop.run_in_executor(executor, ...)`, against a `ThreadPoolExecutor`
shared across the whole engine (see `SSLCheckEngine._crypto_executor`) --
one pool for however many targets/checks run concurrently, not one pool
per call. The engine's own concurrency model (the semaphore bounding
target fan-out) is unaffected; this only bridges the blocking calls that
happen inside it.

Provenance
------------
Every result carries `cryptolyzer_version`, per dependency policy item 4 --
a finding here is CryptoLyzer's verdict, not net-benchmark's own.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, TypeVar


class DeepIntrospectionAvailability(str, Enum):
    AVAILABLE = "available"
    NOT_INSTALLED = "not_installed"


def deep_introspection_availability() -> DeepIntrospectionAvailability:
    try:
        import cryptolyzer  # noqa: F401
    except ImportError:
        return DeepIntrospectionAvailability.NOT_INSTALLED
    return DeepIntrospectionAvailability.AVAILABLE


def _cryptolyzer_version() -> Optional[str]:
    try:
        import importlib.metadata

        return importlib.metadata.version("CryptoLyzer")
    except Exception:  # pragma: no cover — defensive
        return None


# ---------------------------------------------------------------------------
# Result dataclasses — clean, stable, JSON-serialisable fields extracted
# from CryptoLyzer's own (much richer, internal, non-serialisable) result
# objects. Never expose CryptoLyzer's own classes in net-benchmark's own
# dataclasses — that would couple this project's export format to a
# third-party library's internal object graph.
# ---------------------------------------------------------------------------


@dataclass
class NamedGroupsResult:
    """Item 1: negotiable named groups, including post-quantum hybrids
    where the server offers one — CryptoLyzer's own protocol stack
    recognises ML-KEM hybrids that OpenSSL versions predating 3.5 have no
    client API to even ask for.
    """

    attempted: bool = False
    groups: List[str] = field(default_factory=list)
    extension_supported: Optional[bool] = None
    error: Optional[str] = None

    @property
    def post_quantum_groups(self) -> List[str]:
        """Items 10, 12: which of the negotiable groups are post-quantum
        (hybrid or pure). Name-pattern matched against every PQ family
        `cryptoparser`'s own `TlsNamedCurve` enum currently recognises
        (ML-KEM, Kyber, BIKE, FrodoKEM, HQC, CECPQ2) -- confirmed present
        in the installed library before relying on it, including
        `X25519_ML_KEM_768`, the hybrid actually deployed in practice
        (OpenSSL negotiates it by default from 3.5). Item 13 (ClientHello
        size impact) and item 14 (capability gating) are not this
        property's job — 14 is just `error` being set rather than an
        empty list on failure, same as every other probe here.
        """
        pq_tokens = ("MLKEM", "ML_KEM", "KYBER", "BIKE", "FRODO", "HQC", "CECPQ")
        return [
            g for g in self.groups if any(token in g.upper() for token in pq_tokens)
        ]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "attempted": self.attempted,
            "groups": list(self.groups),
            "post_quantum_groups": self.post_quantum_groups,
            "extension_supported": self.extension_supported,
            "error": self.error,
        }


@dataclass
class DHParamsResult:
    """Items 2-3: ephemeral key exchange parameters beyond what 0.6.0 item
    35's forward-secrecy inference can see. `key_reuse` is item 3's
    ephemeral-key-reuse detection directly — CryptoLyzer determines it by
    comparing DH public values across repeated connections itself.
    """

    attempted: bool = False
    rfc7919_groups: List[str] = field(default_factory=list)
    classic_dhe_key_size: Optional[int] = None
    classic_dhe_well_known_group: Optional[str] = None
    classic_dhe_is_prime: Optional[bool] = None
    classic_dhe_is_safe_prime: Optional[bool] = None
    # True: same ephemeral public value seen across independent
    # connections — not actually ephemeral, defeats forward secrecy
    # regardless of the key-exchange algorithm negotiated.
    key_reuse: Optional[bool] = None
    error: Optional[str] = None

    @property
    def weak(self) -> Optional[bool]:
        """True if a classic DHE parameter was observed and it's either
        undersized (<2048 bit) or not a safe prime. None when no classic
        DHE parameter was observed at all (an RFC 7919-only or ECDHE-only
        server has nothing here to rate).
        """
        if self.classic_dhe_key_size is None:
            return None
        if self.classic_dhe_key_size < 2048:
            return True
        if self.classic_dhe_is_safe_prime is False:
            return True
        return False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "attempted": self.attempted,
            "rfc7919_groups": list(self.rfc7919_groups),
            "classic_dhe_key_size": self.classic_dhe_key_size,
            "classic_dhe_well_known_group": self.classic_dhe_well_known_group,
            "classic_dhe_is_prime": self.classic_dhe_is_prime,
            "classic_dhe_is_safe_prime": self.classic_dhe_is_safe_prime,
            "key_reuse": self.key_reuse,
            "weak": self.weak,
            "error": self.error,
        }


@dataclass
class ExtensionsResult:
    """Items 5-6: renegotiation posture and protocol extension audit in
    one probe — CryptoLyzer's own `AnalyzerExtensions` covers both in a
    single result object, so this wrapper does too rather than splitting
    it into two round trips for no reason.
    """

    attempted: bool = False
    renegotiation_supported: Optional[bool] = None
    extended_master_secret_supported: Optional[bool] = None
    encrypt_then_mac_supported: Optional[bool] = None
    session_cache_supported: Optional[bool] = None
    session_ticket_supported: Optional[bool] = None
    compression_methods: List[str] = field(default_factory=list)
    application_layer_protocols: List[str] = field(default_factory=list)
    next_protocols: List[str] = field(default_factory=list)
    record_size_limit_handled: Optional[bool] = None
    error: Optional[str] = None

    @property
    def compression_enabled(self) -> Optional[bool]:
        """Item 28's precondition: TLS compression is the measurable
        precondition CRIME's verdict rests on. True when anything besides
        "no compression" was offered.
        """
        if not self.compression_methods:
            return None
        return any(
            m.lower() not in ("null", "no compression")
            for m in self.compression_methods
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "attempted": self.attempted,
            "renegotiation_supported": self.renegotiation_supported,
            "extended_master_secret_supported": self.extended_master_secret_supported,
            "encrypt_then_mac_supported": self.encrypt_then_mac_supported,
            "session_cache_supported": self.session_cache_supported,
            "session_ticket_supported": self.session_ticket_supported,
            "compression_methods": list(self.compression_methods),
            "compression_enabled": self.compression_enabled,
            "application_layer_protocols": list(self.application_layer_protocols),
            "next_protocols": list(self.next_protocols),
            "record_size_limit_handled": self.record_size_limit_handled,
            "error": self.error,
        }


@dataclass
class SignatureAlgorithmsResult:
    """Item 7: which signature/hash algorithm combinations the server will
    actually accept, as distinct from what the certificate happens to use
    (that's `certificate.py`'s job, on the certificate already in hand).
    """

    attempted: bool = False
    algorithms: List[str] = field(default_factory=list)
    weak_algorithms: List[str] = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "attempted": self.attempted,
            "algorithms": list(self.algorithms),
            "weak_algorithms": list(self.weak_algorithms),
            "error": self.error,
        }


@dataclass
class TLS13CipherResult:
    """Item 8, deferred from 0.6.1 item 2 for exactly the reason stated
    there: stdlib `ssl` cannot individually disable TLS 1.3 suites via
    `set_ciphers()`, so per-suite probing (0.6.1's approach for TLS 1.2 and
    below) is unreliable for TLS 1.3 by design. CryptoLyzer's own protocol
    stack determines the full supported set directly, no per-suite probing
    needed.
    """

    attempted: bool = False
    suites: List[str] = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "attempted": self.attempted,
            "suites": list(self.suites),
            "error": self.error,
        }


@dataclass
class VersionProbeResult:
    """Item 9: protocol versions CryptoLyzer's independent stack can probe
    that stdlib `ssl` cannot request at all — SSLv2, and TLS 1.3 draft
    versions a legacy or embedded stack might still speak. Distinct from
    (and a superset of what) `enumeration.py`'s stdlib-based version probe
    already covers for the versions OpenSSL itself can still negotiate.

    Item 11 (TLS 1.3 draft version detection) needed no separate code:
    confirmed by reading `AnalyzerVersions.analyze()`'s own source that it
    already runs a dedicated `_analyze_supported_tls_1_3_versions` probe
    internally, so any draft version a target still speaks shows up in
    `versions` here directly.
    """

    attempted: bool = False
    versions: List[str] = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "attempted": self.attempted,
            "versions": list(self.versions),
            "error": self.error,
        }


@dataclass
class VulnerabilitiesResult:
    """Items 15-19: configuration-surface vulnerability flags.

    Every flag below is derived, passively, from protocol/cipher/DH-
    parameter data an ordinary handshake or two already reveals — this is
    what CryptoLyzer's own `AnalyzerVulnerabilities` computes internally
    (confirmed by reading its source before wrapping it, not assumed): it
    calls `AnalyzerVersions`/`AnalyzerCipherSuites`/`AnalyzerDHParams` and
    derives every flag from *that* data via simple, static lookups (e.g.
    `freak = any(cipher_suite.value.freak for cipher_suite in
    negotiable_suites)`). No flag here reflects an active exploit attempt
    (no crafted padding-oracle queries, no Bleichenbacher probing, no
    malformed-message injection) — that distinction is exactly why this
    module is comfortable wrapping it and would not be comfortable writing
    the alternative.

    Items 15-16 name more attacks than this delivers, and that gap is
    verified, not assumed: this module's own dependency audit searched the
    entire installed `cryptolyzer` and `cryptoparser` source for "robot",
    "poodle", "heartbleed", "beast", "ticketbleed", "bleichenbacher" and
    found none of them anywhere, despite CryptoLyzer's own PyPI summary
    listing ROBOT detection. `poodle`/`beast` below are this module's own
    addition, computed the same passive way CryptoLyzer computes
    everything else here (SSLv3-or-TLS1.0 negotiable AND a CBC-mode cipher
    negotiable at that specific version — the precondition both attacks
    need, not a working exploit). Heartbleed, CCS injection, Ticketbleed,
    ROBOT and BREACH are not implemented anywhere in this module and are
    not planned to be: each needs sending a deliberately malformed or
    oversized protocol message and inspecting the response for a memory
    disclosure or timing oracle, which is a fundamentally different kind
    of check than everything else here, and one this project does not do
    regardless of source.
    """

    attempted: bool = False
    sweet32: Optional[bool] = None
    anonymous_dh: Optional[bool] = None
    rc4: Optional[bool] = None
    non_forward_secret: Optional[bool] = None
    null_encryption: Optional[bool] = None
    lucky13: Optional[bool] = None
    freak: Optional[bool] = None
    logjam: Optional[bool] = None
    export_grade: Optional[bool] = None
    weak_dh: Optional[bool] = None
    dheat: Optional[bool] = None
    drown: Optional[bool] = None
    early_tls_version: Optional[bool] = None
    insecure_ssl_version: Optional[bool] = None
    # Item 19's own name — available directly from CryptoLyzer's versions
    # probe (TLS's own downgrade-protection signal, TLS_FALLBACK_SCSV) but
    # missed in the first pass of this wrapper; caught while confirming
    # item 11 was already covered elsewhere, not by a dedicated review of
    # this field list.
    inappropriate_version_fallback: Optional[bool] = None
    # This module's own additions — see the class docstring.
    poodle: Optional[bool] = None
    beast: Optional[bool] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "attempted": self.attempted,
            "sweet32": self.sweet32,
            "anonymous_dh": self.anonymous_dh,
            "rc4": self.rc4,
            "non_forward_secret": self.non_forward_secret,
            "null_encryption": self.null_encryption,
            "lucky13": self.lucky13,
            "freak": self.freak,
            "logjam": self.logjam,
            "export_grade": self.export_grade,
            "weak_dh": self.weak_dh,
            "dheat": self.dheat,
            "drown": self.drown,
            "early_tls_version": self.early_tls_version,
            "insecure_ssl_version": self.insecure_ssl_version,
            "inappropriate_version_fallback": self.inappropriate_version_fallback,
            "poodle": self.poodle,
            "beast": self.beast,
            "error": self.error,
        }


@dataclass
class DeepIntrospectionResult:
    """All seven handshake-internals/vulnerability checks for one target."""

    attempted: bool = False
    availability: DeepIntrospectionAvailability = (
        DeepIntrospectionAvailability.NOT_INSTALLED
    )
    cryptolyzer_version: Optional[str] = None
    named_groups: Optional[NamedGroupsResult] = None
    dh_params: Optional[DHParamsResult] = None
    extensions: Optional[ExtensionsResult] = None
    signature_algorithms: Optional[SignatureAlgorithmsResult] = None
    tls13_ciphers: Optional[TLS13CipherResult] = None
    versions: Optional[VersionProbeResult] = None
    vulnerabilities: Optional[VulnerabilitiesResult] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "attempted": self.attempted,
            "availability": self.availability.value,
            "cryptolyzer_version": self.cryptolyzer_version,
            "named_groups": self.named_groups.to_dict() if self.named_groups else None,
            "dh_params": self.dh_params.to_dict() if self.dh_params else None,
            "extensions": self.extensions.to_dict() if self.extensions else None,
            "signature_algorithms": (
                self.signature_algorithms.to_dict()
                if self.signature_algorithms
                else None
            ),
            "tls13_ciphers": (
                self.tls13_ciphers.to_dict() if self.tls13_ciphers else None
            ),
            "versions": self.versions.to_dict() if self.versions else None,
            "vulnerabilities": (
                self.vulnerabilities.to_dict() if self.vulnerabilities else None
            ),
            "error": self.error,
        }


# ---------------------------------------------------------------------------
# Executor adapter
# ---------------------------------------------------------------------------


def default_crypto_executor(max_workers: int = 10) -> ThreadPoolExecutor:
    return ThreadPoolExecutor(
        max_workers=max_workers, thread_name_prefix="crypto-introspect"
    )


_T = TypeVar("_T")


async def _run(executor: ThreadPoolExecutor, func: Callable[..., _T], *args: Any) -> _T:
    import asyncio

    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(executor, func, *args)


def _make_client(host: str, port: int) -> Any:
    from cryptolyzer.tls.client import L7ClientTls

    return L7ClientTls(host, port)


def _check_reachable(host: str, port: int, timeout: float = 5.0) -> Optional[str]:
    """A plain TCP connect check, run before every probe below.

    Not redundant with CryptoLyzer's own error handling: confirmed directly
    that `AnalyzerExtensions.analyze()` does *not* raise when the target is
    unreachable — it silently returns a result with every field defaulted
    to "not offered" (`renegotiation_supported=False`,
    `extended_master_secret_supported=False`, ...), indistinguishable from
    a real, feature-poor server without this check. The other five probes
    were confirmed to raise correctly on the same failure — but that was
    only checked against one failure mode (connection refused), and
    silently trusting the rest not to share this same defaulting behaviour
    under some other failure mode is exactly the kind of assumption this
    module doesn't make elsewhere. Cheap enough to run unconditionally.
    """
    import socket

    try:
        with socket.create_connection((host, port), timeout=timeout):
            return None
    except OSError as exc:
        return f"{host}:{port} unreachable: {exc}"


def _protocol_version(name: str = "tls1_2") -> Any:
    from cryptoparser.tls.version import TlsProtocolVersion, TlsVersion

    return TlsProtocolVersion(getattr(TlsVersion, name.upper()))


# ---------------------------------------------------------------------------
# Individual probes — each is a plain, synchronous function (safe to hand
# to the executor directly) plus an async wrapper that runs it there.
# ---------------------------------------------------------------------------


def _probe_named_groups_sync(host: str, port: int) -> NamedGroupsResult:
    from cryptolyzer.tls.curves import AnalyzerCurves

    result = NamedGroupsResult(attempted=True)
    unreachable = _check_reachable(host, port)
    if unreachable is not None:
        result.error = unreachable
        return result
    try:
        client = _make_client(host, port)
        analysis = AnalyzerCurves().analyze(client, _protocol_version())
        result.groups = [str(c).rsplit(".", 1)[-1] for c in analysis.curves]
        result.extension_supported = analysis.extension_supported
    except Exception as exc:  # noqa: BLE001 — third-party analyzer, arbitrary targets
        result.error = f"{type(exc).__name__}: {exc}"
    return result


async def probe_named_groups(
    host: str, port: int, *, executor: ThreadPoolExecutor
) -> NamedGroupsResult:
    return await _run(executor, _probe_named_groups_sync, host, port)


def _probe_dh_params_sync(host: str, port: int) -> DHParamsResult:
    from cryptolyzer.tls.dhparams import AnalyzerDHParams

    result = DHParamsResult(attempted=True)
    unreachable = _check_reachable(host, port)
    if unreachable is not None:
        result.error = unreachable
        return result
    try:
        client = _make_client(host, port)
        analysis = AnalyzerDHParams().analyze(client, _protocol_version())
        result.rfc7919_groups = [str(g).rsplit(".", 1)[-1] for g in analysis.groups]
        result.key_reuse = analysis.key_reuse
        if analysis.dhparam is not None:
            result.classic_dhe_key_size = int(analysis.dhparam.key_size)
            result.classic_dhe_is_prime = bool(analysis.dhparam.prime)
            result.classic_dhe_is_safe_prime = bool(analysis.dhparam.safe_prime)
            if analysis.dhparam.well_known is not None:
                result.classic_dhe_well_known_group = str(
                    analysis.dhparam.well_known
                ).rsplit(".", 1)[-1]
    except Exception as exc:  # noqa: BLE001
        result.error = f"{type(exc).__name__}: {exc}"
    return result


async def probe_dh_params(
    host: str, port: int, *, executor: ThreadPoolExecutor
) -> DHParamsResult:
    return await _run(executor, _probe_dh_params_sync, host, port)


def _probe_extensions_sync(host: str, port: int) -> ExtensionsResult:
    from cryptolyzer.tls.extensions import AnalyzerExtensions

    result = ExtensionsResult(attempted=True)
    unreachable = _check_reachable(host, port)
    if unreachable is not None:
        result.error = unreachable
        return result
    try:
        client = _make_client(host, port)
        analysis = AnalyzerExtensions().analyze(client, _protocol_version())
        result.renegotiation_supported = analysis.renegotiation_supported
        result.extended_master_secret_supported = (
            analysis.extended_master_secret_supported
        )
        result.encrypt_then_mac_supported = analysis.encrypt_then_mac_supported
        result.session_cache_supported = analysis.session_cache_supported
        result.session_ticket_supported = analysis.session_ticket_supported
        result.compression_methods = [
            str(m).rsplit(".", 1)[-1] for m in analysis.compression_methods
        ]
        result.application_layer_protocols = [
            str(p).rsplit(".", 1)[-1] for p in analysis.application_layer_protocols
        ]
        result.next_protocols = [str(p) for p in analysis.next_protocols]
        result.record_size_limit_handled = analysis.record_size_limit_handled
    except Exception as exc:  # noqa: BLE001
        result.error = f"{type(exc).__name__}: {exc}"
    return result


async def probe_extensions(
    host: str, port: int, *, executor: ThreadPoolExecutor
) -> ExtensionsResult:
    return await _run(executor, _probe_extensions_sync, host, port)


# Same weak-hash names certificate.py's own audit_signature uses, so a
# "weak" verdict means the same thing whether it came from the certificate
# or from what the server is willing to sign with here.
_WEAK_SIGNATURE_HASH_TOKENS = ("SHA1", "MD5", "MD2", "MD4")


def _probe_signature_algorithms_sync(host: str, port: int) -> SignatureAlgorithmsResult:
    from cryptolyzer.tls.sigalgos import AnalyzerSigAlgos

    result = SignatureAlgorithmsResult(attempted=True)
    unreachable = _check_reachable(host, port)
    if unreachable is not None:
        result.error = unreachable
        return result
    try:
        client = _make_client(host, port)
        analysis = AnalyzerSigAlgos().analyze(client, _protocol_version())
        names = [str(a).rsplit(".", 1)[-1] for a in analysis.sig_algos]
        result.algorithms = names
        result.weak_algorithms = [
            name
            for name in names
            if any(token in name.upper() for token in _WEAK_SIGNATURE_HASH_TOKENS)
        ]
    except Exception as exc:  # noqa: BLE001
        result.error = f"{type(exc).__name__}: {exc}"
    return result


async def probe_signature_algorithms(
    host: str, port: int, *, executor: ThreadPoolExecutor
) -> SignatureAlgorithmsResult:
    return await _run(executor, _probe_signature_algorithms_sync, host, port)


def _probe_tls13_ciphers_sync(host: str, port: int) -> TLS13CipherResult:
    from cryptolyzer.tls.ciphers import AnalyzerCipherSuites

    result = TLS13CipherResult(attempted=True)
    unreachable = _check_reachable(host, port)
    if unreachable is not None:
        result.error = unreachable
        return result
    try:
        client = _make_client(host, port)
        analysis = AnalyzerCipherSuites().analyze(client, _protocol_version("tls1_3"))
        result.suites = [
            (
                getattr(c, "value", c).iana_name
                if hasattr(getattr(c, "value", c), "iana_name")
                else str(c).rsplit(".", 1)[-1]
            )
            for c in analysis.cipher_suites
        ]
    except Exception as exc:  # noqa: BLE001
        result.error = f"{type(exc).__name__}: {exc}"
    return result


async def probe_tls13_ciphers(
    host: str, port: int, *, executor: ThreadPoolExecutor
) -> TLS13CipherResult:
    return await _run(executor, _probe_tls13_ciphers_sync, host, port)


def _probe_versions_sync(host: str, port: int) -> VersionProbeResult:
    from cryptolyzer.tls.versions import AnalyzerVersions

    result = VersionProbeResult(attempted=True)
    unreachable = _check_reachable(host, port)
    if unreachable is not None:
        result.error = unreachable
        return result
    try:
        client = _make_client(host, port)
        analysis = AnalyzerVersions().analyze(client, None)
        # TlsProtocolVersion.__str__() is already human-readable ("TLS
        # 1.2", "SSL 2.0") unlike the enum-style objects the other probes
        # extract from — no rsplit needed, and using the same rsplit
        # heuristic here was a real bug: "TLS 1.2".rsplit(".", 1)[-1]
        # produces "2", not "TLS 1.2". Caught by testing this against a
        # real target rather than assuming the pattern generalised.
        result.versions = [str(v) for v in analysis.versions]
    except Exception as exc:  # noqa: BLE001
        result.error = f"{type(exc).__name__}: {exc}"
    return result


async def probe_versions(
    host: str, port: int, *, executor: ThreadPoolExecutor
) -> VersionProbeResult:
    return await _run(executor, _probe_versions_sync, host, port)


def _cbc_negotiable_at(host: str, port: int, version_name: str) -> Optional[bool]:
    """Precondition helper for POODLE/BEAST: is any CBC-mode cipher suite
    negotiable at exactly this protocol version? Returns None (not False)
    when the version itself isn't negotiable at all, since "no CBC cipher"
    and "this version isn't even reachable" are different findings.
    """
    from cryptolyzer.tls.ciphers import AnalyzerCipherSuites

    try:
        client = _make_client(host, port)
        pv = _protocol_version(version_name)
        analysis = AnalyzerCipherSuites().analyze(client, pv)
    except Exception:  # noqa: BLE001 — version not negotiable at all
        return None
    suites = analysis.cipher_suites
    if not suites:
        return None
    return any(
        getattr(getattr(suite, "value", suite), "block_cipher_mode", None) is not None
        and str(getattr(suite, "value", suite).block_cipher_mode).rsplit(".", 1)[-1]
        == "CBC"
        for suite in suites
    )


def _probe_vulnerabilities_sync(host: str, port: int) -> VulnerabilitiesResult:
    from cryptolyzer.tls.vulnerabilities import AnalyzerVulnerabilities

    result = VulnerabilitiesResult(attempted=True)
    unreachable = _check_reachable(host, port)
    if unreachable is not None:
        result.error = unreachable
        return result
    try:
        client = _make_client(host, port)
        analysis = AnalyzerVulnerabilities().analyze(client, _protocol_version())
        result.sweet32 = analysis.ciphers.sweet32.value
        result.anonymous_dh = analysis.ciphers.anonymous_dh.value
        result.rc4 = analysis.ciphers.rc4.value
        result.non_forward_secret = analysis.ciphers.non_forward_secret.value
        result.null_encryption = analysis.ciphers.null_encryption.value
        result.lucky13 = analysis.ciphers.lucky13.value
        result.freak = analysis.ciphers.freak.value
        result.logjam = analysis.ciphers.logjam.value
        result.export_grade = analysis.ciphers.export_grade.value
        result.weak_dh = analysis.dhparams.weak_dh.value
        result.dheat = analysis.dhparams.dheat.value
        result.drown = analysis.versions.drown.value
        result.early_tls_version = analysis.versions.early_tls_version.value
        result.insecure_ssl_version = analysis.versions.ssl_version.value
        if analysis.versions.inappropriate_version_fallback is not None:
            result.inappropriate_version_fallback = (
                analysis.versions.inappropriate_version_fallback.value
            )

        # This module's own additions — see VulnerabilitiesResult's
        # docstring. Only probed when the version itself is negotiable at
        # all (ssl_version/early_tls_version already establish that), to
        # avoid two extra, almost-always-pointless connection attempts
        # against the large majority of targets that don't speak SSLv3 or
        # TLS 1.0 at all.
        if result.insecure_ssl_version:
            cbc = _cbc_negotiable_at(host, port, "ssl3")
            result.poodle = cbc if cbc is not None else None
        else:
            result.poodle = False
        if result.early_tls_version:
            cbc = _cbc_negotiable_at(host, port, "tls1")
            result.beast = cbc if cbc is not None else None
        else:
            result.beast = False
    except Exception as exc:  # noqa: BLE001
        result.error = f"{type(exc).__name__}: {exc}"
    return result


async def probe_vulnerabilities(
    host: str, port: int, *, executor: ThreadPoolExecutor
) -> VulnerabilitiesResult:
    return await _run(executor, _probe_vulnerabilities_sync, host, port)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


async def probe_deep_introspection(
    host: str,
    port: int,
    *,
    executor: ThreadPoolExecutor,
) -> DeepIntrospectionResult:
    """Run all six handshake-internals probes (items 1, 2-3, 5-6, 7, 8, 9)
    against one target. Each is independent — one probe's failure never
    blocks the others; a target that can't do TLS 1.3 at all just gets an
    empty `tls13_ciphers.suites`, not a whole-result failure.
    """
    result = DeepIntrospectionResult(attempted=True)
    result.availability = deep_introspection_availability()
    if result.availability is not DeepIntrospectionAvailability.AVAILABLE:
        result.error = (
            "CryptoLyzer is not installed. TLS deep introspection requires "
            "the [crypto] extra: pip install 'net-benchmark[crypto]'"
        )
        return result

    result.cryptolyzer_version = _cryptolyzer_version()
    result.named_groups = await probe_named_groups(host, port, executor=executor)
    result.dh_params = await probe_dh_params(host, port, executor=executor)
    result.extensions = await probe_extensions(host, port, executor=executor)
    result.signature_algorithms = await probe_signature_algorithms(
        host, port, executor=executor
    )
    result.tls13_ciphers = await probe_tls13_ciphers(host, port, executor=executor)
    result.versions = await probe_versions(host, port, executor=executor)
    result.vulnerabilities = await probe_vulnerabilities(host, port, executor=executor)
    return result


# ---------------------------------------------------------------------------
# Client simulation (0.6.2 item 23)
# ---------------------------------------------------------------------------
#
# Deliberately NOT part of probe_deep_introspection's bundle above: this is
# a different order of magnitude of cost. Confirmed empirically before
# wiring it in — a single run against a real target made on the order of 70
# individual real handshake attempts (one per simulated browser/version
# range CryptoLyzer knows about), several seconds of wall-clock time even
# against a fast, nearby target. Bundling that into every
# --deep-introspection run by default would make the common case far
# slower for a check most callers will not want every time. It gets its
# own opt-in flag instead.
#
# Also worth recording since it cost real debugging time: CryptoLyzer's
# simulation analyzer only recognises clients for the "https" scheme
# (`_CLIENT_TYPE_SCHEME_MAP = {'https': (ClientType.WEB_BROWSER,)}`) — the
# plain `L7ClientTls` this module uses everywhere else reports scheme
# "tls", not "https", and silently produces zero succeeded and zero failed
# clients with no error at all when used here. `L7ClientHTTPS` is required
# specifically for this one probe.


@dataclass
class ClientSimulationEntry:
    client_name: str
    succeeded: bool
    version: Optional[str] = None
    cipher_suite: Optional[str] = None
    named_group: Optional[str] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "client_name": self.client_name,
            "succeeded": self.succeeded,
            "version": self.version,
            "cipher_suite": self.cipher_suite,
            "named_group": self.named_group,
            "error": self.error,
        }


@dataclass
class ClientSimulationResult:
    attempted: bool = False
    entries: List[ClientSimulationEntry] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def incompatible_clients(self) -> List[str]:
        return [e.client_name for e in self.entries if not e.succeeded]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "attempted": self.attempted,
            "entries": [e.to_dict() for e in self.entries],
            "incompatible_clients": self.incompatible_clients,
            "error": self.error,
        }


def _probe_client_simulation_sync(host: str, port: int) -> ClientSimulationResult:
    from cryptolyzer.tls.client import L7ClientHTTPS
    from cryptolyzer.tls.simulations import AnalyzerSimulations

    result = ClientSimulationResult(attempted=True)
    unreachable = _check_reachable(host, port)
    if unreachable is not None:
        result.error = unreachable
        return result
    try:
        client = L7ClientHTTPS(host, port)
        analysis = AnalyzerSimulations().analyze(client, _protocol_version())

        for client_key, sim_value in (analysis.succeeded_clients or {}).items():
            result.entries.append(
                ClientSimulationEntry(
                    client_name=str(client_key),
                    succeeded=True,
                    version=str(getattr(sim_value, "version", None)) or None,
                    cipher_suite=(
                        str(getattr(sim_value, "cipher_suite", None)).rsplit(".", 1)[-1]
                        if getattr(sim_value, "cipher_suite", None) is not None
                        else None
                    ),
                    named_group=(
                        str(getattr(sim_value, "named_group", None)).rsplit(".", 1)[-1]
                        if getattr(sim_value, "named_group", None) is not None
                        else None
                    ),
                )
            )
        for client_key, error_params in (analysis.failed_clients or {}).items():
            result.entries.append(
                ClientSimulationEntry(
                    client_name=str(client_key),
                    succeeded=False,
                    error=getattr(error_params, "long_description", str(error_params)),
                )
            )
    except Exception as exc:  # noqa: BLE001
        result.error = f"{type(exc).__name__}: {exc}"
    return result


async def probe_client_simulation(
    host: str, port: int, *, executor: ThreadPoolExecutor
) -> ClientSimulationResult:
    """Item 23: which real browser/library versions can actually complete
    a handshake with this target, per CryptoLyzer's own maintained
    per-client TLS capability data. Expensive — see the section docstring
    above; call only when explicitly requested, not as part of every scan.
    """
    return await _run(executor, _probe_client_simulation_sync, host, port)


__all__ = [
    "DeepIntrospectionAvailability",
    "NamedGroupsResult",
    "DHParamsResult",
    "ExtensionsResult",
    "SignatureAlgorithmsResult",
    "TLS13CipherResult",
    "VersionProbeResult",
    "VulnerabilitiesResult",
    "DeepIntrospectionResult",
    "deep_introspection_availability",
    "default_crypto_executor",
    "probe_named_groups",
    "probe_dh_params",
    "probe_extensions",
    "probe_signature_algorithms",
    "probe_tls13_ciphers",
    "probe_versions",
    "probe_vulnerabilities",
    "probe_deep_introspection",
    "ClientSimulationEntry",
    "ClientSimulationResult",
    "probe_client_simulation",
]
