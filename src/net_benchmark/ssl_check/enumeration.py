"""TLS version and cipher suite enumeration for the SSL/TLS module.

net-benchmark 0.6.1 -- ROADMAP.md "Protocol & cipher enumeration" items 1-3:
enumerate supported TLS versions, enumerate TLS-1.2-and-below cipher suites,
and rate each suite's strength.

Method
------
Reuses `probe_tls()` / `ProbeConfig` from `handshake.py` exactly as that
module's own comments anticipate: "0.6.1 version enumeration ... drives the
same probe repeatedly with a pinned version rather than reimplementing the
handshake." Each version is probed with `min_version == max_version` pinned
to it; each TLS-1.2-and-below cipher is probed with `cipher_string`
restricted to exactly that one suite via OpenSSL's cipher-string syntax, and
`max_version` pinned to TLS 1.2 so the connection can never actually
negotiate TLS 1.3 regardless of what `SSLContext.get_ciphers()` continues to
list (see below). A version or cipher counts as supported iff the resulting
handshake status is `HandshakeStatus.OK`.

TLS 1.3 is not individually cipher-probed (item 2's own scope note)
----------------------------------------------------------------------
"Stdlib ssl cannot individually disable TLS 1.3 suites via set_ciphers(), so
per-suite TLS 1.3 probing is unreliable here by design; TLS 1.3 enumeration
lands in 0.6.2." Confirmed empirically before writing this: even with
`maximum_version = TLSv1_2`, `SSLContext.get_ciphers()` still lists the three
TLS 1.3 suites (`set_ciphers()` only ever affects TLS-1.2-and-below selection
in OpenSSL) -- they are filtered out of the candidate list here for that
reason, not omitted by oversight. Item 1 (version enumeration) still reports
whether the target supports TLS 1.3 as a *version*; only per-suite probing
within it is out of scope until CryptoLyzer lands in 0.6.2.

Cipher strength rating (item 3)
---------------------------------
`rate_cipher_strength()` follows the general, published categories SSL
Labs' and IANA's own grading use -- no encryption or export-grade is
critical, a weak/broken primitive (RC4, DES, MD5) is next, a lack of
forward secrecy or of an AEAD mode is a step down from the best available,
and a suite with both an AEAD cipher and a forward-secret key exchange is
top-tier. This is not a reimplementation of SSL Labs' own proprietary
rubric -- that distinction matters because net-benchmark's SSL-Labs-style
grade (W2) is a separate, later piece of work that combines this signal
with others, not this function's job.

Cost and default state
------------------------
A full enumeration is five version probes plus one probe per local-OpenSSL
TLS-1.2-and-below cipher -- on the order of 50-70 handshakes against one
target. All of them are capped at TLS 1.2 so each is cheap, but the total is
not free at scale, and probing one target with dozens of sequential
handshakes is already enough load that they are run sequentially against
that target rather than fanned out concurrently -- see *Cross-cutting*
"third-party target etiquette" in the roadmap. Opt-in
(`--enumerate-protocol` / `SSLCheckEngine(enumerate_protocol=True)`), same
reasoning as `verify_chain` and `check_revocation`: default behaviour and
every existing test stay unaffected.
"""

from __future__ import annotations

import ssl
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence, Tuple

from net_benchmark.ssl_check.handshake import (
    HandshakeStatus,
    ProbeConfig,
    StartTLSProtocol,
    TLSVersion,
    iana_cipher_code,
    probe_tls,
)

# (our TLSVersion enum, stdlib ssl.TLSVersion) for every version item 1 asks
# for. SSLv3 is included deliberately -- a target that still speaks it is
# exactly the finding this exists to surface, not a case to skip.
DEFAULT_VERSION_CANDIDATES: Tuple[Tuple[TLSVersion, "ssl.TLSVersion"], ...] = (
    (TLSVersion.SSLV3, ssl.TLSVersion.SSLv3),
    (TLSVersion.TLSV1_0, ssl.TLSVersion.TLSv1),
    (TLSVersion.TLSV1_1, ssl.TLSVersion.TLSv1_1),
    (TLSVersion.TLSV1_2, ssl.TLSVersion.TLSv1_2),
    (TLSVersion.TLSV1_3, ssl.TLSVersion.TLSv1_3),
)


class CipherStrength(str, Enum):
    A = "A"
    B = "B"
    C = "C"
    F = "F"


# Ordered worst to best, so `min(..., key=_STRENGTH_ORDER.index)` finds the
# weakest of a set of ratings.
_STRENGTH_ORDER = [
    CipherStrength.F,
    CipherStrength.C,
    CipherStrength.B,
    CipherStrength.A,
]


def rate_cipher_strength(name: str) -> Tuple[CipherStrength, str]:
    """A/B/C/F rating for one OpenSSL cipher suite name. See the module
    docstring for the categories this follows.
    """
    upper = name.upper()

    if any(
        token in upper for token in ("NULL", "EXPORT", "EXP-", "ADH", "AECDH", "ANON")
    ):
        return (
            CipherStrength.F,
            "no encryption, export-grade, or anonymous key exchange",
        )

    if "RC4" in upper or "MD5" in upper or "DES" in upper:
        # Catches both DES-CBC-SHA and the 3DES suites (DES-CBC3-SHA).
        return CipherStrength.C, "weak or broken primitive (RC4, DES/3DES, or MD5)"

    has_forward_secrecy = "ECDHE" in upper or "DHE" in upper or "EDH" in upper
    is_aead = (
        "GCM" in upper or "CHACHA20" in upper or "POLY1305" in upper or "CCM" in upper
    )

    if has_forward_secrecy and is_aead:
        return CipherStrength.A, "AEAD cipher with forward-secret key exchange"
    if has_forward_secrecy:
        return (
            CipherStrength.B,
            "forward-secret key exchange, but CBC mode rather than AEAD",
        )
    if is_aead:
        return (
            CipherStrength.B,
            "AEAD cipher, but no forward secrecy (static key exchange)",
        )
    return (
        CipherStrength.B,
        "CBC mode and no forward secrecy, but not a broken primitive",
    )


@dataclass
class VersionSupport:
    version: TLSVersion
    supported: bool
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version.value,
            "supported": self.supported,
            "error": self.error,
        }


@dataclass
class CipherSupport:
    name: str
    iana_code: Optional[int]
    supported: bool
    strength: CipherStrength
    strength_reason: str
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "iana_code": self.iana_code,
            "supported": self.supported,
            "strength": self.strength.value,
            "strength_reason": self.strength_reason,
            "error": self.error,
        }


@dataclass
class EnumerationResult:
    attempted: bool = False
    versions: List[VersionSupport] = field(default_factory=list)
    ciphers: List[CipherSupport] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    @property
    def supported_versions(self) -> List[TLSVersion]:
        return [v.version for v in self.versions if v.supported]

    @property
    def supported_ciphers(self) -> List[CipherSupport]:
        return [c for c in self.ciphers if c.supported]

    @property
    def weakest_supported_cipher_strength(self) -> Optional[CipherStrength]:
        """The worst rating among supported ciphers, or `None` when cipher
        enumeration was not run or nothing came back supported.
        """
        strengths = [c.strength for c in self.supported_ciphers]
        if not strengths:
            return None
        return min(strengths, key=_STRENGTH_ORDER.index)

    def to_dict(self) -> Dict[str, Any]:
        weakest = self.weakest_supported_cipher_strength
        return {
            "attempted": self.attempted,
            "versions": [v.to_dict() for v in self.versions],
            "ciphers": [c.to_dict() for c in self.ciphers],
            "weakest_supported_cipher_strength": weakest.value if weakest else None,
            "errors": list(self.errors),
        }


def local_tls12_and_below_ciphers() -> List[Tuple[str, Optional[int]]]:
    """Every TLS-1.2-and-below cipher suite this process's own OpenSSL build
    knows about, as (name, IANA code) pairs -- the candidate list for
    `enumerate_protocol`'s cipher probing. The three TLS 1.3 suites
    `get_ciphers()` always lists are filtered out; see the module docstring.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    result: List[Tuple[str, Optional[int]]] = []
    for entry in ctx.get_ciphers():
        if entry.get("protocol") == "TLSv1.3":
            continue
        name = entry["name"]
        result.append((name, iana_cipher_code(name)))
    return result


async def enumerate_protocol(
    host: str,
    port: int,
    *,
    starttls: Optional[StartTLSProtocol] = None,
    base_config: Optional[ProbeConfig] = None,
    include_ciphers: bool = True,
    cipher_candidates: Optional[Sequence[Tuple[str, Optional[int]]]] = None,
) -> EnumerationResult:
    """Enumerate supported TLS versions (item 1) and, unless disabled,
    TLS-1.2-and-below cipher suites with a strength rating for each (items
    2-3).

    `base_config` supplies everything about the probe unrelated to what this
    function itself controls (timeouts, SNI, `--resolve` pinning, the
    address policy) -- every individual probe is `dataclasses.replace()`
    off of it, never a fresh `ProbeConfig()`, so a caller's settings apply
    uniformly across all 50-70 probes rather than only the first.
    """
    result = EnumerationResult(attempted=True)
    base_config = base_config or ProbeConfig()

    for version_enum, ssl_version in DEFAULT_VERSION_CANDIDATES:
        config = replace(
            base_config,
            min_version=ssl_version,
            max_version=ssl_version,
            cipher_string=None,
        )
        try:
            handshake = await probe_tls(host, port, starttls=starttls, config=config)
        except ssl.SSLError as exc:
            result.versions.append(VersionSupport(version_enum, False, str(exc)))
            continue
        supported = handshake.status == HandshakeStatus.OK
        error = (
            None if supported else (handshake.error_message or handshake.status.value)
        )
        result.versions.append(VersionSupport(version_enum, supported, error))

    if include_ciphers:
        candidates = (
            cipher_candidates
            if cipher_candidates is not None
            else local_tls12_and_below_ciphers()
        )
        for name, code in candidates:
            strength, reason = rate_cipher_strength(name)
            config = replace(
                base_config,
                min_version=None,
                max_version=ssl.TLSVersion.TLSv1_2,
                cipher_string=name,
            )
            try:
                handshake = await probe_tls(
                    host, port, starttls=starttls, config=config
                )
            except ssl.SSLError as exc:
                result.ciphers.append(
                    CipherSupport(name, code, False, strength, reason, str(exc))
                )
                continue
            supported = handshake.status == HandshakeStatus.OK
            error = (
                None
                if supported
                else (handshake.error_message or handshake.status.value)
            )
            result.ciphers.append(
                CipherSupport(name, code, supported, strength, reason, error)
            )

    return result


# ---------------------------------------------------------------------------
# Server cipher-suite preference order (0.6.1 item 21)
# ---------------------------------------------------------------------------

# Two widely-supported TLS 1.2 AEAD suites, both reachable via `set_ciphers`
# individually per this module's own constraint (TLS 1.2 and below only).
# Any two mutually-distinct, commonly-offered suites would do; these are the
# same two most servers already support, keeping the check inconclusive only
# on genuinely unusual configurations rather than on ordinary ones.
DEFAULT_PREFERENCE_CIPHER_A = "ECDHE-RSA-AES128-GCM-SHA256"
DEFAULT_PREFERENCE_CIPHER_B = "ECDHE-RSA-AES256-GCM-SHA384"


@dataclass
class CipherPreferenceResult:
    """Result of item 21: does the server enforce its own cipher order, or
    negotiate whatever the client listed first?
    """

    attempted: bool = False
    # True: same cipher negotiated regardless of client order (server
    # enforces its own list). False: negotiated cipher tracked whichever the
    # client listed first (server has no enforced preference of its own, or
    # its preference happens to match the client's — indistinguishable from
    # outside, and not a distinction the roadmap item asks this to make).
    # None: not determinable (see `error`).
    server_enforces_order: Optional[bool] = None
    negotiated_with_a_first: Optional[str] = None
    negotiated_with_b_first: Optional[str] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "attempted": self.attempted,
            "server_enforces_order": self.server_enforces_order,
            "negotiated_with_a_first": self.negotiated_with_a_first,
            "negotiated_with_b_first": self.negotiated_with_b_first,
            "error": self.error,
        }


async def detect_cipher_preference(
    host: str,
    port: int,
    *,
    starttls: Optional[StartTLSProtocol] = None,
    base_config: Optional[ProbeConfig] = None,
    cipher_a: str = DEFAULT_PREFERENCE_CIPHER_A,
    cipher_b: str = DEFAULT_PREFERENCE_CIPHER_B,
) -> CipherPreferenceResult:
    """Two handshakes offering the same two ciphers in opposite order.

    If the negotiated cipher is the same both times, the server enforced its
    own ordering (`OP_CIPHER_SERVER_PREFERENCE` or equivalent). If it tracks
    whichever cipher was listed first each time, the server has no enforced
    preference. Inconclusive — `server_enforces_order` stays `None`, with
    `error` set — when the target doesn't support both candidate ciphers, in
    which case ordering can't be observed at all.
    """
    result = CipherPreferenceResult(attempted=True)
    base_config = base_config or ProbeConfig()

    config_a_first = replace(
        base_config,
        min_version=None,
        max_version=ssl.TLSVersion.TLSv1_2,
        cipher_string=f"{cipher_a}:{cipher_b}",
    )
    config_b_first = replace(
        base_config,
        min_version=None,
        max_version=ssl.TLSVersion.TLSv1_2,
        cipher_string=f"{cipher_b}:{cipher_a}",
    )

    try:
        handshake_a = await probe_tls(
            host, port, starttls=starttls, config=config_a_first
        )
        handshake_b = await probe_tls(
            host, port, starttls=starttls, config=config_b_first
        )
    except ssl.SSLError as exc:
        result.error = str(exc)
        return result

    if (
        handshake_a.status != HandshakeStatus.OK
        or handshake_b.status != HandshakeStatus.OK
    ):
        result.error = (
            "target does not support both candidate ciphers "
            f"({cipher_a}, {cipher_b}); preference order not determinable"
        )
        return result

    result.negotiated_with_a_first = handshake_a.cipher_name
    result.negotiated_with_b_first = handshake_b.cipher_name

    if handshake_a.cipher_name != handshake_b.cipher_name:
        result.server_enforces_order = False
        return result

    # Same cipher both times -- but that alone doesn't distinguish "the
    # server enforces its own preference between two real options" from
    # "cipher_b was never actually negotiable, so of course cipher_a won
    # both times regardless of order". Confirmed by trying cipher_b alone,
    # with no cipher_a offered at all to compete with it — caught this as a
    # real gap via a test that offered a server with only cipher_a
    # available and got `server_enforces_order=True` back, which would have
    # been a misleading answer to the actual question this item asks.
    config_b_only = replace(
        base_config,
        min_version=None,
        max_version=ssl.TLSVersion.TLSv1_2,
        cipher_string=cipher_b,
    )
    try:
        handshake_b_only = await probe_tls(
            host, port, starttls=starttls, config=config_b_only
        )
    except ssl.SSLError as exc:
        result.error = f"could not confirm {cipher_b} is independently supported: {exc}"
        return result

    if handshake_b_only.status != HandshakeStatus.OK:
        result.error = (
            f"{cipher_b} is not independently negotiable with this target; "
            f"the same {cipher_a} result both times reflects that, not an "
            "enforced preference between two real options"
        )
        return result

    result.server_enforces_order = True
    return result


__all__ = [
    "DEFAULT_VERSION_CANDIDATES",
    "DEFAULT_PREFERENCE_CIPHER_A",
    "DEFAULT_PREFERENCE_CIPHER_B",
    "CipherStrength",
    "VersionSupport",
    "CipherSupport",
    "EnumerationResult",
    "CipherPreferenceResult",
    "rate_cipher_strength",
    "local_tls12_and_below_ciphers",
    "enumerate_protocol",
    "detect_cipher_preference",
]
