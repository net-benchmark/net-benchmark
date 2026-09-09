"""Async TLS handshake transport for the SSL/TLS module.

net-benchmark 0.6.0 — SSL items 1, 3, 4, 5, 33, 34, 38, 39, 40, 41, 54.

This module owns exactly one thing: getting a TLS handshake to happen against a
`host:port` and reporting, precisely, what happened on the wire. It performs no
interpretation. Certificate parsing, trust validation, grading and policy all
live above it — see `ssl_check/certificate.py` and `ssl_check/core.py`.

Why `SSLContext.wrap_bio()` and a hand-driven handshake pump, rather than the
obvious `asyncio.open_connection(ssl=ctx)`
----------------------------------------------------------------------------
Four roadmap items are not implementable through the transport-integrated path:

* **Item 54** — chain byte size and total handshake bytes on the wire.
  `open_connection(ssl=...)` performs the handshake inside the transport and
  never exposes the byte stream. With a memory BIO every byte in each direction
  passes through this module and is counted exactly.

* **Item 39** — STARTTLS. TLS has to begin on an already-open plaintext
  connection after a protocol-specific negotiation. `StreamWriter.start_tls()`
  is 3.11+; `loop.start_tls()` exists earlier but requires reaching past the
  streams API for the transport and protocol objects. A memory BIO makes
  STARTTLS and direct TLS literally the same code path on every supported
  Python.

* **Items 4 and 47** — resumption warm-up and `session_reused` drift.
  `loop.create_connection()` has no `session=` parameter. There is no way to
  drive TLS session resumption through the transport-integrated path at all.
  `SSLContext.wrap_bio()` accepts `session=` directly.

* **Item 38** — handshake timing percentiles. TCP connect and TLS handshake are
  measured as separate spans here rather than inferred from one combined
  number.

Why `verify_mode = CERT_NONE`, always
-------------------------------------
Trust validation is done afterwards, over the parsed certificates, by
`cryptography.x509.verification` (item 20). It is deliberately NOT delegated to
OpenSSL during the handshake.

A scanner whose handshake aborts on an untrusted certificate can report nothing
at all about that certificate — no subject, no expiry, no key size, no chain.
That is precisely the target you most want data on. Failing the handshake would
convert a rich finding ("expired, self-signed, RSA-1024") into a bare
`TLS_ERROR`. So this layer always completes the handshake if the peer will let
it, and the verdict is computed separately from the evidence.

Consequence, stated so it is not rediscovered as a bug: a `HandshakeResult` with
`status == HandshakeStatus.OK` means *the handshake completed*, not *the peer is
trustworthy*. Callers must not treat OK as a trust signal.

Chain observability
-------------------
`SSLObject.get_verified_chain()` and `get_unverified_chain()` are **Python
3.13+**. Below that the stdlib exposes the leaf certificate and nothing else,
at any `verify_mode`.

This is not a degradation that AIA fetching repairs. An AIA-assembled chain is
complete and correctly ordered *by construction*, so it cannot answer item 23
(completeness) or item 24 (ordering) — both are properties of the bytes the
server actually sent. Nor does parsing the wire help: the Certificate handshake
message is plaintext under TLS 1.2 but **encrypted under TLS 1.3**.

So `peer_chain_der` is `None`, with `chain_unavailable_reason` set, rather than
an empty list. `None` means "not observable here"; `[]` would mean "the server
sent no intermediates", which is a real and different finding.
"""

from __future__ import annotations

import asyncio
import socket
import ssl
import time
from dataclasses import dataclass
from enum import Enum
from typing import (
    Any,
    Awaitable,
    Callable,
    Dict,
    List,
    Optional,
    Tuple,
    cast,
)

# ---------------------------------------------------------------------------
# Tunables
# ---------------------------------------------------------------------------

# Ceiling on bytes exchanged during the handshake itself (STARTTLS negotiation
# is counted separately and does not draw against this).
#
# This is a liveness guard, not a size limit derived from any protocol maximum.
# A peer that dribbles one byte per read keeps `do_handshake()` raising
# SSLWantReadError forever, and neither a wall-clock deadline nor a read
# timeout catches it on its own: each individual read succeeds, promptly, and
# the loop never terminates. For scale, a large chain with an ML-KEM key share
# is single-digit KiB, so 256 KiB is far above any legitimate handshake.
DEFAULT_MAX_HANDSHAKE_BYTES = 256 * 1024

# Consecutive pump iterations that move zero bytes in either direction before
# the handshake is abandoned. Complements the byte cap above: the cap catches
# slow progress, this catches no progress.
DEFAULT_MAX_IDLE_ITERATIONS = 8

DEFAULT_CONNECT_TIMEOUT = 10.0
DEFAULT_HANDSHAKE_TIMEOUT = 15.0
DEFAULT_STARTTLS_TIMEOUT = 15.0

# Read chunk for both plaintext negotiation and handshake records.
_READ_CHUNK = 65536

# Longest single line accepted during a line-oriented STARTTLS negotiation.
# Guards the same class of failure as DEFAULT_MAX_HANDSHAKE_BYTES: a peer that
# never sends a newline would otherwise buffer without bound.
_MAX_NEGOTIATION_LINE = 8192


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class HandshakeStatus(str, Enum):
    """Transport-level outcome of a single probe.

    Deliberately a separate enum from `dns_benchmark.core.QueryStatus`. The
    HTTP module reuses `QueryStatus`, and the 0.5.3 internal notes already
    record that as a wart to undo (item 11, "HTTP error taxonomy enum
    mirroring DNSQueryStatus"). Repeating it here would be a third module
    borrowing DNS's vocabulary — NXDOMAIN and SERVFAIL mean nothing to a TLS
    probe, and TLS_ERROR alone cannot distinguish the six failure modes below
    that a caller genuinely needs to tell apart.
    """

    OK = "ok"
    # Target address rejected by the address-range policy (foundation item 9).
    # Never attempted, so no timing is reported.
    BLOCKED = "blocked"
    DNS_FAILURE = "dns_failure"
    TCP_REFUSED = "tcp_refused"
    TCP_TIMEOUT = "tcp_timeout"
    TCP_ERROR = "tcp_error"
    # Peer closed or errored during the plaintext STARTTLS exchange.
    STARTTLS_FAILED = "starttls_failed"
    # Peer completed the plaintext exchange but does not offer STARTTLS. A
    # configuration finding, not a transport error — reported distinctly so it
    # is not counted as a failed scan.
    STARTTLS_UNSUPPORTED = "starttls_unsupported"
    # Peer spoke TLS but the handshake was rejected (protocol version floor,
    # no shared cipher, malformed records). Note CERT_NONE means certificate
    # problems do NOT land here.
    TLS_ERROR = "tls_error"
    HANDSHAKE_TIMEOUT = "handshake_timeout"
    # Byte cap or idle-iteration guard tripped.
    HANDSHAKE_ABANDONED = "handshake_abandoned"
    # Peer closed the connection mid-handshake.
    PEER_CLOSED = "peer_closed"


class StartTLSProtocol(str, Enum):
    """Application protocol spoken in plaintext before upgrading to TLS.

    `NONE` means implicit TLS: the handshake begins immediately on connect.
    """

    NONE = "none"
    SMTP = "smtp"
    IMAP = "imap"
    POP3 = "pop3"
    FTP = "ftp"
    LDAP = "ldap"


class TLSVersion(str, Enum):
    """Negotiated protocol version, normalised from `SSLObject.version()`.

    Kept as an enum rather than the raw string so the deprecation verdict
    (item 12) has a closed set to switch on, and so exports carry a stable
    vocabulary independent of what a given OpenSSL build spells things.
    """

    SSLV3 = "SSLv3"
    TLSV1_0 = "TLSv1"
    TLSV1_1 = "TLSv1.1"
    TLSV1_2 = "TLSv1.2"
    TLSV1_3 = "TLSv1.3"
    UNKNOWN = "unknown"

    @classmethod
    def from_openssl(cls, value: Optional[str]) -> "TLSVersion":
        if value is None:
            return cls.UNKNOWN
        for member in cls:
            if member.value == value:
                return member
        return cls.UNKNOWN

    @property
    def is_deprecated(self) -> bool:
        """SSL item 12 — TLS 1.0 and 1.1 are deprecated (RFC 8996), SSLv3 broken.

        A property rather than a set membership test at the call site so the
        rule is stated once. `UNKNOWN` is deliberately not deprecated: an
        unrecognised version is an unknown, and reporting an unknown as a
        deprecation finding would be a fabricated verdict.
        """
        return self in (TLSVersion.SSLV3, TLSVersion.TLSV1_0, TLSVersion.TLSV1_1)


# Default TLS mode per port for the multi-port scan (item 41).
#
# Note that most of the ports named in item 41 are *implicit* TLS, not STARTTLS:
# 465 (SMTPS), 993 (IMAPS), 995 (POP3S) and 636 (LDAPS) all begin the handshake
# on connect. 587 is the only STARTTLS port in that list. The plaintext ports
# are included because a multi-port scan that only probes the implicit ones
# misses the STARTTLS surface entirely.
DEFAULT_PORT_STARTTLS: Dict[int, StartTLSProtocol] = {
    443: StartTLSProtocol.NONE,
    8443: StartTLSProtocol.NONE,
    465: StartTLSProtocol.NONE,
    993: StartTLSProtocol.NONE,
    995: StartTLSProtocol.NONE,
    636: StartTLSProtocol.NONE,
    587: StartTLSProtocol.SMTP,
    25: StartTLSProtocol.SMTP,
    143: StartTLSProtocol.IMAP,
    110: StartTLSProtocol.POP3,
    389: StartTLSProtocol.LDAP,
    21: StartTLSProtocol.FTP,
}


# --- IANA cipher suite codes (item 34) -------------------------------------
#
# The roadmap says "negotiated cipher suite (name + IANA code)" and cites
# SSLSocket.version()/cipher() as the source. cipher() returns only
# (name, protocol, secret_bits) — there is no IANA code in it, and OpenSSL's
# suite names ("ECDHE-RSA-AES128-GCM-SHA256") are not IANA's
# ("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"), so the name cannot be translated
# by string manipulation either.
#
# SSLContext.get_ciphers() does carry it: each entry's "id" is the OpenSSL
# cipher id whose low 16 bits are the IANA code point. Verified —
# ECDHE-RSA-AES128-GCM-SHA256 resolves to 0xc02f and the TLS 1.3 suites to
# 0x1301-0x1303, matching the IANA registry.
#
# The table is built from a deliberately permissive context, because
# get_ciphers() lists only what the calling context has ENABLED. Building it
# from the probe's own context would leave a suite unresolvable exactly when
# --ciphers had been narrowed, which is when the code is most wanted.
_CIPHER_ID_CACHE: Optional[Dict[str, int]] = None


def _cipher_id_table() -> Dict[str, int]:
    global _CIPHER_ID_CACHE
    if _CIPHER_ID_CACHE is not None:
        return _CIPHER_ID_CACHE
    table: Dict[str, int] = {}
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        context.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
        context.set_ciphers("ALL:COMPLEMENTOFALL:@SECLEVEL=0")
    except (ssl.SSLError, ValueError):
        # A hardened OpenSSL build may refuse the permissive selection. The
        # default list still resolves every suite such a build can negotiate.
        pass
    for entry in context.get_ciphers():
        name = entry.get("name")
        raw = entry.get("id")
        if isinstance(name, str) and isinstance(raw, int):
            table[name] = raw & 0xFFFF
    _CIPHER_ID_CACHE = table
    return table


def iana_cipher_code(name: Optional[str]) -> Optional[int]:
    """IANA code point for an OpenSSL cipher suite name (item 34).

    None when the local OpenSSL does not know the suite, which is the honest
    answer — inventing a code point for an unrecognised name would put a wrong
    number into an export that a reader would have no way to distinguish from
    a right one.
    """
    if name is None:
        return None
    return _cipher_id_table().get(name)


def starttls_for_port(port: int) -> StartTLSProtocol:
    """Best-guess STARTTLS mode for a port, defaulting to implicit TLS.

    Defaulting to `NONE` for unknown ports is the safe direction: an implicit
    handshake against a plaintext service fails cleanly and quickly, whereas
    sending `EHLO` at a service that is already expecting TLS records injects
    plaintext into a TLS stream and produces a confusing error.
    """
    return DEFAULT_PORT_STARTTLS.get(port, StartTLSProtocol.NONE)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@dataclass
class ProbeConfig:
    """Per-probe transport settings.

    A dataclass rather than a long keyword list because the engine, the CLI and
    the SaaS layer all construct these, and a positional-argument drift between
    the three is exactly the duplication the project avoids.
    """

    connect_timeout: float = DEFAULT_CONNECT_TIMEOUT
    handshake_timeout: float = DEFAULT_HANDSHAKE_TIMEOUT
    starttls_timeout: float = DEFAULT_STARTTLS_TIMEOUT
    max_handshake_bytes: int = DEFAULT_MAX_HANDSHAKE_BYTES
    max_idle_iterations: int = DEFAULT_MAX_IDLE_ITERATIONS

    # SNI value. None means "use the target hostname"; explicit empty string
    # means "send no SNI at all", which is itself a probe worth running.
    server_hostname: Optional[str] = None
    send_sni: bool = True

    # Version floor/ceiling for the probe. None leaves the OpenSSL default.
    # Used by 0.6.1 version enumeration, which drives the same probe repeatedly
    # with a pinned version rather than reimplementing the handshake.
    min_version: Optional[ssl.TLSVersion] = None
    max_version: Optional[ssl.TLSVersion] = None

    # OpenSSL cipher string for TLS 1.2 and below. TLS 1.3 suites cannot be
    # selected individually through `set_ciphers()` — see ROADMAP 0.6.1 item 2.
    cipher_string: Optional[str] = None

    alpn_protocols: Optional[List[str]] = None

    # Pin the connection to a specific address (item 3, `--resolve`). When set,
    # no name resolution is performed.
    pinned_ip: Optional[str] = None

    # TLS 1.3 delivers NewSessionTicket as a post-handshake message, so a
    # session captured the instant `do_handshake()` returns is frequently not
    # yet resumable. Draining briefly picks it up.
    #
    # Off by default: it costs a round trip's worth of waiting on every probe,
    # and only the resumption path (items 4 and 47) needs it. Leaving it off
    # for those items would silently report "never resumes" for every TLS 1.3
    # server, which is why this is called out rather than left implicit.
    post_handshake_drain_s: float = 0.0

    # Session offered for resumption. Requires the *same* SSLContext that
    # produced it; the engine owns that pairing.
    session: Optional[ssl.SSLSession] = None

    # Foundation item 9. Called with the resolved IP before connecting; raises
    # to block. Injected rather than imported so this module stays free of a
    # dependency on the foundation package, and so tests can probe loopback.
    address_policy: Optional[Callable[[str], None]] = None


# ---------------------------------------------------------------------------
# Result
# ---------------------------------------------------------------------------


@dataclass
class HandshakeResult:
    """What happened on the wire for one `host:port` probe.

    Every timing field is `Optional` and is `None` when that phase was not
    reached, never `0.0`. A zero is a measurement; `None` is the absence of
    one, and collapsing the two is the failure class that produced the
    0.0 ms-latency-with-100%-coverage summaries in HTTP 0.5.2.
    """

    # --- identity ---
    host: str
    port: int
    starttls: StartTLSProtocol
    status: HandshakeStatus
    start_time: float  # wall clock, time.time()
    resolved_ip: Optional[str] = None
    ip_version: Optional[int] = None  # 4 or 6
    error_message: Optional[str] = None

    # --- timing (perf_counter spans, ms) ---
    dns_ms: Optional[float] = None
    tcp_connect_ms: Optional[float] = None
    starttls_ms: Optional[float] = None
    handshake_ms: Optional[float] = None
    total_ms: Optional[float] = None

    # --- bytes on the wire (item 54) ---
    # Handshake only. STARTTLS plaintext is counted separately so that
    # comparing handshake cost across ports is not skewed by how chatty a
    # given application protocol's greeting happens to be.
    handshake_bytes_sent: int = 0
    handshake_bytes_received: int = 0
    starttls_bytes_sent: int = 0
    starttls_bytes_received: int = 0
    # Bytes read during the optional post-handshake drain (NewSessionTicket).
    # Held apart from handshake_bytes_received so item 54's figure does not
    # change depending on whether the resumption drain was enabled.
    post_handshake_bytes_received: int = 0

    # --- negotiated parameters (items 33, 34) ---
    tls_version: TLSVersion = TLSVersion.UNKNOWN
    cipher_name: Optional[str] = None
    cipher_protocol: Optional[str] = None
    cipher_bits: Optional[int] = None
    # IANA code point, e.g. 0xc02f. See iana_cipher_code().
    cipher_id: Optional[int] = None
    alpn_protocol: Optional[str] = None
    compression: Optional[str] = None

    # --- session (items 4, 47) ---
    session_reused: Optional[bool] = None
    session_id: Optional[str] = None  # hex
    session: Optional[ssl.SSLSession] = None  # not exported; for a resume probe

    # --- certificates ---
    # Leaf in DER. Parsing belongs to certificate.py, not here.
    leaf_der: Optional[bytes] = None
    # Peer-supplied chain in DER, leaf first, exactly as sent. `None` means not
    # observable on this interpreter — see the module docstring. `[]` would
    # mean the server sent no intermediates, which is a genuine finding.
    peer_chain_der: Optional[List[bytes]] = None
    chain_unavailable_reason: Optional[str] = None

    # Set when the peer offered no certificate at all (anonymous or PSK-only
    # suites). Distinct from a parse failure.
    peer_offered_no_certificate: bool = False

    @property
    def handshake_bytes_total(self) -> int:
        return self.handshake_bytes_sent + self.handshake_bytes_received

    @property
    def succeeded(self) -> bool:
        """True when the handshake completed.

        Explicitly NOT a trust verdict — see the module docstring. Named
        `succeeded` rather than `secure` or `valid` for that reason.
        """
        return self.status is HandshakeStatus.OK

    def to_dict(self) -> Dict[str, Any]:
        """Export-safe projection.

        Hand-written rather than `asdict()`: `session` is an `ssl.SSLSession`
        and `leaf_der`/`peer_chain_der` are raw DER, none of which belong in a
        JSON export. Certificate content is exported by certificate.py in
        parsed form.
        """
        return {
            "host": self.host,
            "port": self.port,
            "starttls": self.starttls.value,
            "status": self.status.value,
            "start_time": self.start_time,
            "resolved_ip": self.resolved_ip,
            "ip_version": self.ip_version,
            "error_message": self.error_message,
            "dns_ms": self.dns_ms,
            "tcp_connect_ms": self.tcp_connect_ms,
            "starttls_ms": self.starttls_ms,
            "handshake_ms": self.handshake_ms,
            "total_ms": self.total_ms,
            "handshake_bytes_sent": self.handshake_bytes_sent,
            "handshake_bytes_received": self.handshake_bytes_received,
            "handshake_bytes_total": self.handshake_bytes_total,
            "starttls_bytes_sent": self.starttls_bytes_sent,
            "starttls_bytes_received": self.starttls_bytes_received,
            "post_handshake_bytes_received": self.post_handshake_bytes_received,
            "tls_version": self.tls_version.value,
            "tls_version_deprecated": self.tls_version.is_deprecated,
            "cipher_name": self.cipher_name,
            "cipher_protocol": self.cipher_protocol,
            "cipher_bits": self.cipher_bits,
            "cipher_id": self.cipher_id,
            "cipher_iana_hex": (
                f"0x{self.cipher_id:04x}" if self.cipher_id is not None else None
            ),
            "alpn_protocol": self.alpn_protocol,
            "compression": self.compression,
            "session_reused": self.session_reused,
            "session_id": self.session_id,
            "chain_observed": self.peer_chain_der is not None,
            "chain_length": (
                len(self.peer_chain_der) if self.peer_chain_der is not None else None
            ),
            "chain_unavailable_reason": self.chain_unavailable_reason,
            "peer_offered_no_certificate": self.peer_offered_no_certificate,
        }


# ---------------------------------------------------------------------------
# Context construction
# ---------------------------------------------------------------------------


def build_client_context(config: ProbeConfig) -> ssl.SSLContext:
    """Build the client context for a probe.

    Verification is disabled deliberately and unconditionally — see the module
    docstring. This function is the single place that decision is made, so it
    cannot be partially undone somewhere downstream.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    if config.min_version is not None:
        context.minimum_version = config.min_version
    if config.max_version is not None:
        context.maximum_version = config.max_version

    if config.cipher_string is not None:
        # Raises ssl.SSLError on an empty or unparseable selection. Allowed to
        # propagate: a cipher string the local OpenSSL rejects is a caller
        # error, and silently probing with the default set instead would
        # produce a result attributed to a cipher list that was never used.
        context.set_ciphers(config.cipher_string)

    if config.alpn_protocols:
        context.set_alpn_protocols(config.alpn_protocols)

    return context


# ---------------------------------------------------------------------------
# Deadline-bounded line reader (shared by the STARTTLS negotiators)
# ---------------------------------------------------------------------------


async def _read_line(
    reader: asyncio.StreamReader,
    deadline: float,
) -> bytes:
    """Read one CRLF-terminated line, bounded by both length and deadline.

    `readuntil` is used rather than `readline` so that an over-long line raises
    `LimitOverrunError` instead of being silently returned in fragments — a
    fragment would be parsed as a complete protocol response.
    """
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise asyncio.TimeoutError("deadline exceeded before read")
    try:
        line = await asyncio.wait_for(reader.readuntil(b"\n"), timeout=remaining)
    except (asyncio.LimitOverrunError, ValueError) as exc:
        raise ConnectionError(f"negotiation line exceeded buffer: {exc}") from exc
    if len(line) > _MAX_NEGOTIATION_LINE:
        raise ConnectionError("negotiation line too long")
    return line


async def _write_line(
    writer: asyncio.StreamWriter,
    payload: bytes,
    deadline: float,
) -> int:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise asyncio.TimeoutError("deadline exceeded before write")
    writer.write(payload)
    await asyncio.wait_for(writer.drain(), timeout=remaining)
    return len(payload)


# ---------------------------------------------------------------------------
# STARTTLS negotiators (item 39)
# ---------------------------------------------------------------------------
#
# Each negotiator returns (bytes_sent, bytes_received) for the plaintext phase
# and raises on failure:
#
#   * StartTLSUnsupported  — the peer answered, and does not offer STARTTLS.
#     A configuration finding about the target.
#   * ConnectionError      — the peer misbehaved or closed. A transport fault.
#
# Keeping those apart matters: "this SMTP server has no STARTTLS" and "this SMTP
# server hung up" are different findings, and collapsing them into one error
# would make an unencrypted mail server indistinguishable from an unreachable
# one.


class StartTLSUnsupported(Exception):
    """The peer completed its greeting but does not advertise STARTTLS."""


async def _negotiate_smtp(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    deadline: float,
    host: str,
) -> Tuple[int, int]:
    sent = received = 0

    # Greeting. May be multiline (220-...) before the final 220 line.
    while True:
        line = await _read_line(reader, deadline)
        received += len(line)
        if not line.startswith(b"220"):
            raise ConnectionError(f"unexpected SMTP greeting: {line[:80]!r}")
        # A hyphen in the fourth byte marks a continuation line.
        if len(line) < 4 or line[3:4] != b"-":
            break

    sent += await _write_line(writer, b"EHLO net-benchmark\r\n", deadline)

    advertised = False
    while True:
        line = await _read_line(reader, deadline)
        received += len(line)
        if b"STARTTLS" in line.upper():
            advertised = True
        if len(line) < 4 or line[3:4] != b"-":
            break

    if not advertised:
        raise StartTLSUnsupported("SMTP server did not advertise STARTTLS in EHLO")

    sent += await _write_line(writer, b"STARTTLS\r\n", deadline)
    line = await _read_line(reader, deadline)
    received += len(line)
    if not line.startswith(b"220"):
        raise ConnectionError(f"SMTP STARTTLS refused: {line[:80]!r}")

    return sent, received


async def _negotiate_imap(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    deadline: float,
    host: str,
) -> Tuple[int, int]:
    sent = received = 0

    line = await _read_line(reader, deadline)
    received += len(line)
    if not line.startswith(b"* OK"):
        raise ConnectionError(f"unexpected IMAP greeting: {line[:80]!r}")

    # CAPABILITY is queried explicitly rather than trusting the greeting: the
    # capability list in an untagged greeting is optional, and a server may
    # advertise STARTTLS only on request.
    sent += await _write_line(writer, b"A001 CAPABILITY\r\n", deadline)
    advertised = False
    while True:
        line = await _read_line(reader, deadline)
        received += len(line)
        if b"STARTTLS" in line.upper():
            advertised = True
        if line.startswith(b"A001 "):
            break

    if not advertised:
        raise StartTLSUnsupported("IMAP server did not advertise STARTTLS")

    sent += await _write_line(writer, b"A002 STARTTLS\r\n", deadline)
    while True:
        line = await _read_line(reader, deadline)
        received += len(line)
        if line.startswith(b"A002 "):
            if not line.startswith(b"A002 OK"):
                raise ConnectionError(f"IMAP STARTTLS refused: {line[:80]!r}")
            break

    return sent, received


async def _negotiate_pop3(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    deadline: float,
    host: str,
) -> Tuple[int, int]:
    sent = received = 0

    line = await _read_line(reader, deadline)
    received += len(line)
    if not line.startswith(b"+OK"):
        raise ConnectionError(f"unexpected POP3 greeting: {line[:80]!r}")

    sent += await _write_line(writer, b"STLS\r\n", deadline)
    line = await _read_line(reader, deadline)
    received += len(line)
    if not line.startswith(b"+OK"):
        # POP3 answers -ERR for an unimplemented command, so an unsupported
        # STLS is indistinguishable from a refused one at the protocol level.
        # Reported as unsupported, which is the more common cause.
        raise StartTLSUnsupported(f"POP3 STLS refused: {line[:80]!r}")

    return sent, received


async def _negotiate_ftp(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    deadline: float,
    host: str,
) -> Tuple[int, int]:
    sent = received = 0

    while True:
        line = await _read_line(reader, deadline)
        received += len(line)
        if not line.startswith(b"220"):
            raise ConnectionError(f"unexpected FTP greeting: {line[:80]!r}")
        if len(line) < 4 or line[3:4] != b"-":
            break

    sent += await _write_line(writer, b"AUTH TLS\r\n", deadline)
    line = await _read_line(reader, deadline)
    received += len(line)
    if not line.startswith(b"234"):
        raise StartTLSUnsupported(f"FTP AUTH TLS refused: {line[:80]!r}")

    return sent, received


# --- LDAP StartTLS (RFC 4511 §4.14) ----------------------------------------
#
# Unlike the four above, LDAP StartTLS is not line-oriented: it is a BER-encoded
# ExtendedRequest. Only enough BER is implemented here to build one fixed
# request and read a result code out of the reply — this is not, and must not
# become, a general LDAP client.

_LDAP_STARTTLS_OID = b"1.3.6.1.4.1.1466.20.037"


def _ber_length(length: int) -> bytes:
    """Encode a BER definite length.

    Only the short form and one- and two-byte long forms are produced. That
    covers everything this module emits (the request is ~30 bytes); anything
    larger would mean the caller is doing something this helper is not for.
    """
    if length < 0x80:
        return bytes([length])
    if length <= 0xFF:
        return bytes([0x81, length])
    if length <= 0xFFFF:
        return bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])
    raise ValueError("BER length beyond what this minimal encoder supports")


def build_ldap_starttls_request(message_id: int = 1) -> bytes:
    """Build the LDAP StartTLS ExtendedRequest.

    Constructed rather than hard-coded as a magic byte string so the encoding
    is auditable against RFC 4511 without a hex editor.

        LDAPMessage ::= SEQUENCE {
            messageID    INTEGER,
            protocolOp   ExtendedRequest    -- [APPLICATION 23], 0x77
        }
        ExtendedRequest ::= SEQUENCE {
            requestName  [0] LDAPOID        -- context primitive 0, 0x80
        }
    """
    request_name = b"\x80" + _ber_length(len(_LDAP_STARTTLS_OID)) + _LDAP_STARTTLS_OID
    extended_request = b"\x77" + _ber_length(len(request_name)) + request_name
    msg_id = b"\x02" + _ber_length(1) + bytes([message_id])
    body = msg_id + extended_request
    return b"\x30" + _ber_length(len(body)) + body


def parse_ldap_result_code(payload: bytes) -> Optional[int]:
    """Extract resultCode from an LDAP ExtendedResponse, or None if unparseable.

    Scans for the ExtendedResponse tag (0x78) and reads the ENUMERATED that
    opens it. Returning `None` on anything unexpected — rather than guessing a
    code — keeps an unparseable reply reportable as such instead of as a
    specific LDAP error the server never sent.
    """
    index = payload.find(b"\x78")
    if index == -1 or index + 2 >= len(payload):
        return None
    cursor = index + 1
    # Skip the ExtendedResponse length octets.
    first = payload[cursor]
    if first & 0x80:
        cursor += 1 + (first & 0x7F)
    else:
        cursor += 1
    # resultCode is an ENUMERATED (0x0a) of length 1.
    if cursor + 2 >= len(payload) or payload[cursor] != 0x0A:
        return None
    if payload[cursor + 1] != 1:
        return None
    return payload[cursor + 2]


async def _negotiate_ldap(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    deadline: float,
    host: str,
) -> Tuple[int, int]:
    request = build_ldap_starttls_request()
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise asyncio.TimeoutError("deadline exceeded before LDAP StartTLS")

    writer.write(request)
    await asyncio.wait_for(writer.drain(), timeout=remaining)
    sent = len(request)

    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise asyncio.TimeoutError("deadline exceeded awaiting LDAP StartTLS reply")
    payload = await asyncio.wait_for(reader.read(_READ_CHUNK), timeout=remaining)
    if not payload:
        raise ConnectionError("LDAP server closed during StartTLS")
    received = len(payload)

    code = parse_ldap_result_code(payload)
    if code is None:
        raise ConnectionError("unparseable LDAP StartTLS response")
    if code != 0:
        # 2 = protocolError, the usual answer from a server without StartTLS.
        raise StartTLSUnsupported(f"LDAP StartTLS returned resultCode {code}")

    return sent, received


_NEGOTIATORS: Dict[
    StartTLSProtocol,
    Callable[
        [asyncio.StreamReader, asyncio.StreamWriter, float, str],
        Awaitable[Tuple[int, int]],
    ],
] = {
    StartTLSProtocol.SMTP: _negotiate_smtp,
    StartTLSProtocol.IMAP: _negotiate_imap,
    StartTLSProtocol.POP3: _negotiate_pop3,
    StartTLSProtocol.FTP: _negotiate_ftp,
    StartTLSProtocol.LDAP: _negotiate_ldap,
}


# ---------------------------------------------------------------------------
# The handshake pump
# ---------------------------------------------------------------------------


class _HandshakeAbandoned(Exception):
    """Byte cap or idle-iteration guard tripped."""


@dataclass
class _ByteCounter:
    """Mutable byte tally owned by the caller of `_pump_handshake`.

    The pump signals every failure by raising, so a plain return value loses
    the counts on exactly the paths where they are most diagnostic: how far a
    handshake got before it was refused distinguishes "the server rejected our
    version in the ServerHello" from "the server never spoke TLS at all", and
    0.6.1's version and cipher enumeration reads that distinction directly.
    """

    sent: int = 0
    received: int = 0


async def _pump_handshake(
    sslobj: ssl.SSLObject,
    outgoing: ssl.MemoryBIO,
    incoming: ssl.MemoryBIO,
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    deadline: float,
    max_bytes: int,
    max_idle_iterations: int,
    counter: "_ByteCounter",
) -> None:
    """Drive `do_handshake()` to completion, tallying bytes into `counter`.

    Three independent termination guards, because each catches a failure the
    others do not:

    * the **deadline** catches a peer that stalls outright;
    * the **byte cap** catches a peer that makes progress so slowly it would
      outlast any reasonable deadline while every individual read succeeds;
    * the **idle-iteration counter** catches a peer that keeps the socket
      readable while producing nothing the TLS state machine can consume.

    Without all three this loop is unbounded, which is the specific pitfall a
    memory-BIO handshake introduces over the transport-integrated path.
    """
    idle_iterations = 0

    while True:
        try:
            sslobj.do_handshake()
        except ssl.SSLWantReadError:
            pass
        except ssl.SSLWantWriteError:
            # A MemoryBIO never reports full, so this should not occur. Handled
            # rather than asserted: an unexpected raise here would otherwise
            # escape as a bare SSLError and be misreported as a TLS fault.
            pass
        else:
            # Flush whatever the completed handshake still owes the peer (the
            # client Finished, and under TLS 1.3 the client's final flight).
            payload = outgoing.read()
            if payload:
                writer.write(payload)
                counter.sent += len(payload)
                await asyncio.wait_for(
                    writer.drain(),
                    timeout=max(0.001, deadline - time.monotonic()),
                )
            return

        moved = False

        payload = outgoing.read()
        if payload:
            writer.write(payload)
            counter.sent += len(payload)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise asyncio.TimeoutError("handshake deadline exceeded")
            await asyncio.wait_for(writer.drain(), timeout=remaining)
            moved = True

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise asyncio.TimeoutError("handshake deadline exceeded")

        chunk = await asyncio.wait_for(reader.read(_READ_CHUNK), timeout=remaining)
        if not chunk:
            raise ConnectionError("peer closed connection during handshake")

        counter.received += len(chunk)
        incoming.write(chunk)
        moved = True

        if counter.sent + counter.received > max_bytes:
            raise _HandshakeAbandoned(
                f"handshake exceeded {max_bytes} bytes without completing"
            )

        if moved:
            idle_iterations = 0
        else:
            idle_iterations += 1
            if idle_iterations >= max_idle_iterations:
                raise _HandshakeAbandoned(
                    f"handshake made no progress across {max_idle_iterations} "
                    "iterations"
                )


# ---------------------------------------------------------------------------
# Address resolution
# ---------------------------------------------------------------------------


async def _resolve(
    host: str,
    port: int,
    config: ProbeConfig,
) -> Tuple[str, int]:
    """Resolve `host` to a single address, returning (ip, ip_version).

    Resolution is done explicitly rather than left to `open_connection` for
    three reasons, all of which are roadmap requirements: the resolved IP is
    reported (needed by the 0.6.1 multi-cert and IPv4/IPv6 consistency checks),
    `--resolve` pinning (item 3) short-circuits it, and the address-range
    policy (foundation item 9) has to see the address *before* a connection is
    attempted rather than after.
    """
    if config.pinned_ip is not None:
        ip = config.pinned_ip
    else:
        loop = asyncio.get_event_loop()
        infos = await loop.getaddrinfo(
            host, port, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM
        )
        if not infos:
            raise OSError(f"no addresses returned for {host}")
        ip = str(infos[0][4][0])

    version = 6 if ":" in ip else 4

    if config.address_policy is not None:
        # Raises to block. Deliberately after resolution and before connect —
        # a policy applied to the hostname alone is trivially bypassed by a
        # name that resolves to a private address.
        config.address_policy(ip)

    return ip, version


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


async def probe_tls(
    host: str,
    port: int = 443,
    starttls: Optional[StartTLSProtocol] = None,
    config: Optional[ProbeConfig] = None,
    context: Optional[ssl.SSLContext] = None,
) -> HandshakeResult:
    """Probe one `host:port` and report what happened on the wire.

    Never raises for a target-side failure — every such outcome is a
    `HandshakeStatus` on the returned result. Programming errors (a bad cipher
    string, a policy callable that raises something other than the documented
    block) still propagate, because those are caller bugs and swallowing them
    would hide them behind a plausible-looking scan result.

    `context` may be supplied so that a resumption probe reuses the exact
    context that produced the session; `ProbeConfig.session` alone is not
    sufficient, since OpenSSL will not resume a session into a different
    context.
    """
    config = config or ProbeConfig()
    if starttls is None:
        starttls = starttls_for_port(port)

    result = HandshakeResult(
        host=host,
        port=port,
        starttls=starttls,
        status=HandshakeStatus.OK,
        start_time=time.time(),
    )

    overall_start = time.perf_counter()

    # --- resolve -----------------------------------------------------------
    resolve_start = time.perf_counter()
    try:
        ip, ip_version = await _resolve(host, port, config)
    except PermissionError as exc:
        # The documented signal from address_policy.
        result.status = HandshakeStatus.BLOCKED
        result.error_message = str(exc)
        return result
    except (OSError, socket.gaierror) as exc:
        result.status = HandshakeStatus.DNS_FAILURE
        result.error_message = str(exc)
        result.dns_ms = (time.perf_counter() - resolve_start) * 1000.0
        return result

    result.resolved_ip = ip
    result.ip_version = ip_version
    result.dns_ms = (time.perf_counter() - resolve_start) * 1000.0

    # --- TCP connect (item 40) --------------------------------------------
    connect_start = time.perf_counter()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=config.connect_timeout,
        )
    except asyncio.TimeoutError:
        result.status = HandshakeStatus.TCP_TIMEOUT
        result.error_message = f"TCP connect timed out after {config.connect_timeout}s"
        result.tcp_connect_ms = (time.perf_counter() - connect_start) * 1000.0
        result.total_ms = (time.perf_counter() - overall_start) * 1000.0
        return result
    except ConnectionRefusedError as exc:
        result.status = HandshakeStatus.TCP_REFUSED
        result.error_message = str(exc)
        result.tcp_connect_ms = (time.perf_counter() - connect_start) * 1000.0
        result.total_ms = (time.perf_counter() - overall_start) * 1000.0
        return result
    except OSError as exc:
        result.status = HandshakeStatus.TCP_ERROR
        result.error_message = str(exc)
        result.tcp_connect_ms = (time.perf_counter() - connect_start) * 1000.0
        result.total_ms = (time.perf_counter() - overall_start) * 1000.0
        return result

    result.tcp_connect_ms = (time.perf_counter() - connect_start) * 1000.0

    try:
        # --- STARTTLS (item 39) -------------------------------------------
        if starttls is not StartTLSProtocol.NONE:
            negotiator = _NEGOTIATORS[starttls]
            starttls_start = time.perf_counter()
            deadline = starttls_start + config.starttls_timeout
            try:
                sent, received = await negotiator(reader, writer, deadline, host)
            except StartTLSUnsupported as exc:
                result.status = HandshakeStatus.STARTTLS_UNSUPPORTED
                result.error_message = str(exc)
                result.starttls_ms = (time.perf_counter() - starttls_start) * 1000.0
                return result
            except (asyncio.TimeoutError, ConnectionError, OSError) as exc:
                result.status = HandshakeStatus.STARTTLS_FAILED
                result.error_message = str(exc) or type(exc).__name__
                result.starttls_ms = (time.perf_counter() - starttls_start) * 1000.0
                return result
            result.starttls_bytes_sent = sent
            result.starttls_bytes_received = received
            result.starttls_ms = (time.perf_counter() - starttls_start) * 1000.0

        # --- TLS handshake -------------------------------------------------
        ctx = context if context is not None else build_client_context(config)

        if config.send_sni:
            sni: Optional[str] = (
                config.server_hostname if config.server_hostname is not None else host
            )
            # An IP literal is not a valid SNI value; OpenSSL rejects it.
            if sni and _looks_like_ip(sni):
                sni = None
        else:
            sni = None

        incoming = ssl.MemoryBIO()
        outgoing = ssl.MemoryBIO()
        sslobj = ctx.wrap_bio(
            incoming,
            outgoing,
            server_hostname=sni,
            session=config.session,
        )

        handshake_start = time.perf_counter()
        deadline = handshake_start + config.handshake_timeout
        counter = _ByteCounter()
        try:
            await _pump_handshake(
                sslobj,
                outgoing,
                incoming,
                reader,
                writer,
                deadline,
                config.max_handshake_bytes,
                config.max_idle_iterations,
                counter,
            )
        except asyncio.TimeoutError:
            result.status = HandshakeStatus.HANDSHAKE_TIMEOUT
            result.error_message = (
                f"TLS handshake timed out after {config.handshake_timeout}s"
            )
            result.handshake_ms = (time.perf_counter() - handshake_start) * 1000.0
            result.handshake_bytes_sent = counter.sent
            result.handshake_bytes_received = counter.received
            return result
        except _HandshakeAbandoned as exc:
            result.status = HandshakeStatus.HANDSHAKE_ABANDONED
            result.error_message = str(exc)
            result.handshake_ms = (time.perf_counter() - handshake_start) * 1000.0
            result.handshake_bytes_sent = counter.sent
            result.handshake_bytes_received = counter.received
            return result
        except ssl.SSLError as exc:
            result.status = HandshakeStatus.TLS_ERROR
            result.error_message = _format_ssl_error(exc)
            result.handshake_ms = (time.perf_counter() - handshake_start) * 1000.0
            result.handshake_bytes_sent = counter.sent
            result.handshake_bytes_received = counter.received
            return result
        except (ConnectionError, OSError) as exc:
            result.status = HandshakeStatus.PEER_CLOSED
            result.error_message = str(exc) or type(exc).__name__
            result.handshake_ms = (time.perf_counter() - handshake_start) * 1000.0
            result.handshake_bytes_sent = counter.sent
            result.handshake_bytes_received = counter.received
            return result

        result.handshake_ms = (time.perf_counter() - handshake_start) * 1000.0
        result.handshake_bytes_sent = counter.sent
        result.handshake_bytes_received = counter.received

        # --- post-handshake drain (items 4, 47) ----------------------------
        if config.post_handshake_drain_s > 0:
            # Counted separately from the handshake proper: NewSessionTicket
            # arrives after the handshake completes, and folding it into
            # handshake_bytes_received would make item 54's figure depend on
            # whether this drain was enabled.
            result.post_handshake_bytes_received = await _drain_post_handshake(
                sslobj, incoming, reader, config.post_handshake_drain_s
            )

        _capture_negotiated(result, sslobj)

    finally:
        writer.close()
        try:
            # 3.9-compatible; wait_closed on a already-errored transport can
            # itself raise, and a close failure must not mask the probe result.
            await asyncio.wait_for(writer.wait_closed(), timeout=2.0)
        except (asyncio.TimeoutError, OSError, ssl.SSLError):
            pass

    result.total_ms = (time.perf_counter() - overall_start) * 1000.0
    return result


async def _drain_post_handshake(
    sslobj: ssl.SSLObject,
    incoming: ssl.MemoryBIO,
    reader: asyncio.StreamReader,
    window_s: float,
) -> int:
    """Read briefly after the handshake to collect TLS 1.3 NewSessionTicket.

    Under TLS 1.3 the session ticket is a post-handshake message, so
    `sslobj.session` immediately after `do_handshake()` is frequently not yet
    resumable. Without this, items 4 and 47 would report every TLS 1.3 server
    as never resuming — a confident wrong answer rather than a missing one.

    Best-effort by design: a server that sends no ticket is a real finding, so
    the timeout expiring here is not an error.
    """
    received = 0
    deadline = time.monotonic() + window_s
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return received
        try:
            chunk = await asyncio.wait_for(reader.read(_READ_CHUNK), timeout=remaining)
        except asyncio.TimeoutError:
            return received
        except (OSError, ssl.SSLError):
            return received
        if not chunk:
            return received
        received += len(chunk)
        incoming.write(chunk)
        try:
            # Feed the record layer so the ticket is processed. Application
            # data is not expected here; anything returned is discarded.
            sslobj.read(_READ_CHUNK)
        except (ssl.SSLWantReadError, ssl.SSLError, OSError):
            continue


def _capture_negotiated(result: HandshakeResult, sslobj: ssl.SSLObject) -> None:
    """Copy negotiated handshake facts off the SSLObject onto the result."""
    result.tls_version = TLSVersion.from_openssl(sslobj.version())

    cipher = sslobj.cipher()
    if cipher is not None:
        result.cipher_name = cipher[0]
        result.cipher_protocol = cipher[1]
        result.cipher_bits = cipher[2]
        result.cipher_id = iana_cipher_code(cipher[0])

    result.alpn_protocol = sslobj.selected_alpn_protocol()
    result.compression = sslobj.compression()

    session = sslobj.session
    result.session = session
    if session is not None and session.id:
        result.session_id = session.id.hex()
    result.session_reused = sslobj.session_reused

    leaf = sslobj.getpeercert(True)
    if leaf is None:
        # Anonymous or PSK-only suite: a completed handshake with no
        # certificate. A distinct finding, not a parse failure.
        result.peer_offered_no_certificate = True
    else:
        result.leaf_der = leaf

    result.peer_chain_der, result.chain_unavailable_reason = _peer_chain(sslobj)


def _peer_chain(
    sslobj: ssl.SSLObject,
) -> Tuple[Optional[List[bytes]], Optional[str]]:
    """Return the peer-supplied chain in DER, or (None, reason).

    `get_unverified_chain()` is Python 3.13+. It is the *unverified* chain that
    is wanted here, not the verified one: the question items 23 and 24 ask is
    what the server sent, in the order it sent it. The verified chain is
    reordered and completed by OpenSSL, which destroys exactly the evidence
    those items need.

    Accessed via `getattr` rather than a version check so the capability is
    detected rather than assumed — a backport or an alternative interpreter
    that provides it will be used, and one that does not will report a reason.
    """
    getter = getattr(sslobj, "get_unverified_chain", None)
    if getter is None:
        return (
            None,
            "SSLObject.get_unverified_chain() requires Python 3.13+; the "
            "peer-supplied chain is not observable on this interpreter",
        )
    try:
        raw = cast(Any, getter())
    except (ssl.SSLError, ValueError, AttributeError) as exc:
        return None, f"chain retrieval failed: {exc}"

    if raw is None:
        return None, "interpreter returned no chain"

    entries = list(raw)
    chain: List[bytes] = [
        bytes(entry) for entry in entries if isinstance(entry, (bytes, bytearray))
    ]
    if len(chain) != len(entries):
        return None, "chain returned in an unexpected form"
    return chain, None


def _looks_like_ip(value: str) -> bool:
    """True when `value` is an IP literal rather than a hostname."""
    try:
        socket.inet_pton(socket.AF_INET, value)
        return True
    except (OSError, ValueError):
        pass
    try:
        socket.inet_pton(socket.AF_INET6, value)
        return True
    except (OSError, ValueError):
        return False


def _format_ssl_error(exc: ssl.SSLError) -> str:
    """Render an SSLError with its OpenSSL reason code preserved.

    The reason string ("UNSUPPORTED_PROTOCOL", "NO_SHARED_CIPHER",
    "TLSV1_ALERT_PROTOCOL_VERSION") is the part that identifies *which*
    handshake failure occurred, and `str(exc)` alone frequently omits it.
    0.6.1's version and cipher enumeration distinguishes "this version is
    refused" from "this scan is broken" on exactly this field.
    """
    reason = getattr(exc, "reason", None)
    library = getattr(exc, "library", None)
    detail = str(exc)
    parts = [p for p in (library, reason) if p]
    if parts:
        return f"[{':'.join(str(p) for p in parts)}] {detail}"
    return detail


__all__ = [
    "DEFAULT_MAX_HANDSHAKE_BYTES",
    "DEFAULT_PORT_STARTTLS",
    "HandshakeResult",
    "HandshakeStatus",
    "ProbeConfig",
    "StartTLSProtocol",
    "StartTLSUnsupported",
    "TLSVersion",
    "build_client_context",
    "build_ldap_starttls_request",
    "iana_cipher_code",
    "parse_ldap_result_code",
    "probe_tls",
    "starttls_for_port",
]
