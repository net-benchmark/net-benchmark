"""Certificate parsing and per-certificate policy audit for the SSL/TLS module.

net-benchmark 0.6.0 — SSL items 6, 7, 8, 9, 10, 11, 13, 15, 16, 17, 18, 31, 36.

Scope boundary
--------------
This module turns DER bytes into structured facts and audits a *single*
certificate against policy that depends on nothing outside it. It does not
fetch, does not touch the network, and does not build or validate a chain.

Anything requiring more than one certificate — path building, trust store
verdicts, chain ordering, cross-signing, revocation lookups — belongs to
`ssl_check/chain.py` and `ssl_check/revocation.py`. The split is deliberate:
everything here is a pure function of its input, so it is exhaustively testable
from fixture bytes with no server and no clock dependency beyond an injected
`now`.

Item 15: this is the single certificate parser in the tool. The inline
`_parse_cert_der()` in `http_bench/core.py` migrates onto
`parse_cert_der_compat()` below, which returns that function's exact tuple
shape so the migration is a one-line import change rather than a rewrite of
`HTTPResult` population.

`--as-of` (item 55)
-------------------
Every audit takes an explicit `now`. Wall-clock time is never read inside an
audit function. That makes "what breaks at the next renewal" (item 17) a
parameter rather than a separate code path, and makes every test deterministic
without freezing the clock globally.
"""

from __future__ import annotations

import base64
import ipaddress
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence, Tuple

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.oid import (
    AuthorityInformationAccessOID,
    ExtendedKeyUsageOID,
    ExtensionOID,
    NameOID,
)

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class KeyType(str, Enum):
    """Public key algorithm of the certificate's subject key (item 8)."""

    RSA = "rsa"
    ECDSA = "ecdsa"
    ED25519 = "ed25519"
    ED448 = "ed448"
    DSA = "dsa"
    UNKNOWN = "unknown"


class HostnameMatch(str, Enum):
    """Outcome of RFC 6125 name matching (item 11)."""

    MATCH = "match"
    MISMATCH = "mismatch"
    # The certificate carries no subjectAltName at all. Distinct from
    # MISMATCH: a certificate with no SAN is unusable by every modern client
    # regardless of what hostname it is presented for, which is a different
    # finding from one that is simply for the wrong name.
    NO_SAN = "no_san"
    NOT_CHECKED = "not_checked"


class LifetimeVerdict(str, Enum):
    """Certificate lifetime against the CA/Browser Forum cap (items 16, 17)."""

    COMPLIANT = "compliant"
    # Over the cap that was in force on the day it was issued.
    NON_COMPLIANT = "non_compliant"
    # Within the cap it was issued under, but a certificate of this same
    # length issued at the next renewal would exceed the cap in force then.
    # This is item 17, and it is the actionable one: nothing is wrong today
    # and the renewal will fail.
    FAILS_AT_NEXT_RENEWAL = "fails_at_next_renewal"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# CA/Browser Forum lifetime schedule (item 16)
# ---------------------------------------------------------------------------
#
# The roadmap table starts at 15 Mar 2026. That is not sufficient to implement
# the item as written: "the cap in force at the issuance date" requires every
# earlier step too, or a certificate issued in 2025 has no cap to be audited
# against and the audit silently reports UNKNOWN for most of the live web.
# The two earlier steps are added here.
#
# Each entry is (effective_from, max_validity_days). Ordered oldest first.
#
# Note on the roadmap table's second column: DCV (domain control validation)
# reuse periods are NOT auditable from a certificate. Nothing in the encoding
# records when domain control was last validated. That column is context for
# the schedule, not a check this module can implement, and it should not be
# carried into the export as though it were measured.
CAB_LIFETIME_SCHEDULE: Tuple[Tuple[datetime, int], ...] = (
    (datetime(2018, 3, 1, tzinfo=timezone.utc), 825),
    (datetime(2020, 9, 1, tzinfo=timezone.utc), 398),
    (datetime(2026, 3, 15, tzinfo=timezone.utc), 200),
    (datetime(2027, 3, 15, tzinfo=timezone.utc), 100),
    (datetime(2029, 3, 15, tzinfo=timezone.utc), 47),
)

# CA/B "Short-lived Subscriber Certificate" thresholds, by issuance date
# (item 18). Short-lived certificates are exempt from the revocation-source
# requirements, which is why this is not merely descriptive: it feeds item 30's
# decision to report a missing OCSP URL as *not applicable* rather than as a
# finding.
CAB_SHORT_LIVED_SCHEDULE: Tuple[Tuple[datetime, int], ...] = (
    (datetime(2024, 3, 15, tzinfo=timezone.utc), 10),
    (datetime(2026, 3, 15, tzinfo=timezone.utc), 7),
)

# Signature hashes that are broken for certificate signing (item 7).
WEAK_SIGNATURE_HASHES = frozenset({"md5", "sha1", "md2", "md4"})

# Minimum key sizes (item 8). RSA below 2048 and EC below 256 are flagged.
MIN_RSA_BITS = 2048
MIN_EC_BITS = 256

# Named curves considered weak (0.6.1 item 4 grades these fully; the floor
# check here catches the egregious cases at parse time).
WEAK_EC_CURVES = frozenset({"secp192r1", "prime192v1", "secp224r1", "sect233k1"})

# EKUs whose presence on a TLS server certificate is a profile conflict
# (item 36). serverAuth plus clientAuth is normal and not flagged.
CONFLICTING_EKUS: Dict[str, str] = {
    ExtendedKeyUsageOID.CODE_SIGNING.dotted_string: "codeSigning",
    ExtendedKeyUsageOID.EMAIL_PROTECTION.dotted_string: "emailProtection",
    ExtendedKeyUsageOID.TIME_STAMPING.dotted_string: "timeStamping",
    ExtendedKeyUsageOID.OCSP_SIGNING.dotted_string: "OCSPSigning",
}


def cab_lifetime_cap(issued_at: datetime) -> Tuple[Optional[int], Optional[datetime]]:
    """Return (max_days, effective_from) for the cap in force at `issued_at`.

    Returns (None, None) for a certificate issued before the first scheduled
    step. Reporting UNKNOWN there is correct: there was a cap before March
    2018, but a certificate that old is expired by a margin that makes the
    lifetime question moot, and inventing a number for it would be a
    fabricated verdict.
    """
    cap: Optional[int] = None
    effective: Optional[datetime] = None
    for start, days in CAB_LIFETIME_SCHEDULE:
        if issued_at >= start:
            cap, effective = days, start
    return cap, effective


def cab_short_lived_threshold(issued_at: datetime) -> Optional[int]:
    """Max validity in days for `issued_at` to qualify as short-lived."""
    threshold: Optional[int] = None
    for start, days in CAB_SHORT_LIVED_SCHEDULE:
        if issued_at >= start:
            threshold = days
    return threshold


def _next_cap_after(
    moment: datetime,
) -> Tuple[Optional[int], Optional[datetime]]:
    """Return the first scheduled cap that takes effect strictly after `moment`."""
    for start, days in CAB_LIFETIME_SCHEDULE:
        if start > moment:
            return days, start
    return None, None


# ---------------------------------------------------------------------------
# Expiry alert tiers (item 42)
# ---------------------------------------------------------------------------


class ExpiryAlert(str, Enum):
    """Urgency of an approaching expiry."""

    OK = "ok"
    NOTICE = "notice"
    WARNING = "warning"
    CRITICAL = "critical"
    EXPIRED = "expired"
    # No certificate was observed, so there is nothing to count down. Held
    # apart from EXPIRED: an unreachable host is not an expiry emergency.
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ExpiryTier:
    """One alert level, as a fraction of total validity with an absolute floor.

    The threshold in days is:

        min(fixed_days, max(fraction * total_validity, floor_days))

    Each term fixes a different failure of the naive fixed schedule:

    * `fraction` scales the alert to the certificate. A fixed 30/14/7/1
      schedule is meaningless against a 6-day Let's Encrypt certificate — the
      30-day alert fires before the certificate is issued, so every such
      certificate is permanently in alarm and the alert channel gets muted.
    * `floor_days` stops the fraction collapsing to hours on very short
      certificates, where a 10% threshold is 14 hours' notice.
    * `fixed_days` caps it at the top. Without it, 33% of a 398-day
      certificate is a NOTICE 131 days out, which nobody acts on and which
      makes the whole timeline noise.
    """

    level: ExpiryAlert
    fraction: float
    floor_days: int
    fixed_days: int

    def threshold_days(self, total_validity_days: int) -> float:
        return min(
            float(self.fixed_days),
            max(self.fraction * float(total_validity_days), float(self.floor_days)),
        )


# Ordered most urgent first — evaluation stops at the first match.
DEFAULT_EXPIRY_TIERS: Tuple[ExpiryTier, ...] = (
    ExpiryTier(ExpiryAlert.CRITICAL, fraction=1 / 12, floor_days=1, fixed_days=7),
    ExpiryTier(ExpiryAlert.WARNING, fraction=1 / 6, floor_days=1, fixed_days=14),
    ExpiryTier(ExpiryAlert.NOTICE, fraction=1 / 3, floor_days=2, fixed_days=30),
)


def expiry_alert(
    lifetime: Optional["LifetimeAudit"],
    tiers: Sequence[ExpiryTier] = DEFAULT_EXPIRY_TIERS,
) -> ExpiryAlert:
    """Alert level for a certificate's remaining validity (item 42).

    Returns UNKNOWN when no certificate was observed. Treating a missing
    certificate as 0 days remaining would report every unreachable host as an
    expiry emergency, which is the fastest way to get an alerting integration
    switched off.
    """
    if lifetime is None:
        return ExpiryAlert.UNKNOWN
    if lifetime.expired:
        return ExpiryAlert.EXPIRED
    remaining = float(lifetime.days_remaining)
    total = max(1, lifetime.lifetime_days)
    for tier in tiers:
        if remaining <= tier.threshold_days(total):
            return tier.level
    return ExpiryAlert.OK


# ---------------------------------------------------------------------------
# Structured sub-results
# ---------------------------------------------------------------------------


@dataclass
class PublicKeyInfo:
    """Subject public key facts and the weak-key verdict (item 8)."""

    key_type: KeyType
    key_size: Optional[int] = None
    curve_name: Optional[str] = None
    weak: bool = False
    weak_reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "key_type": self.key_type.value,
            "key_size": self.key_size,
            "curve_name": self.curve_name,
            "weak": self.weak,
            "weak_reason": self.weak_reason,
        }


@dataclass
class WildcardAudit:
    """Wildcard presence and scope (item 6).

    `overly_broad` is a heuristic and says so. Authoritatively deciding whether
    `*.co.uk` is a registrable-domain wildcard needs the Public Suffix List,
    which is a runtime dataset under foundation item 19 and is not a base
    dependency. Until that lands, label depth is the available proxy: a
    wildcard at two labels or fewer is either a public-suffix wildcard (which
    no public CA will issue) or a private PKI doing something unusual, and
    both are worth surfacing.
    """

    present: bool = False
    entries: List[str] = field(default_factory=list)
    # Fewest labels seen on any wildcard entry, counting the `*` label.
    min_label_depth: Optional[int] = None
    overly_broad: bool = False
    note: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "present": self.present,
            "entries": list(self.entries),
            "min_label_depth": self.min_label_depth,
            "overly_broad": self.overly_broad,
            "note": self.note,
        }


@dataclass
class LifetimeAudit:
    """Certificate lifetime against the CA/B schedule (items 16, 17, 18)."""

    not_before: datetime
    not_after: datetime
    lifetime_days: int
    days_remaining: int
    verdict: LifetimeVerdict
    cap_days: Optional[int] = None
    cap_effective_from: Optional[datetime] = None
    next_cap_days: Optional[int] = None
    next_cap_effective_from: Optional[datetime] = None
    short_lived: bool = False
    short_lived_threshold_days: Optional[int] = None
    expired: bool = False
    not_yet_valid: bool = False
    detail: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "not_before": self.not_before.isoformat(),
            "not_after": self.not_after.isoformat(),
            "lifetime_days": self.lifetime_days,
            "days_remaining": self.days_remaining,
            "verdict": self.verdict.value,
            "cap_days": self.cap_days,
            "cap_effective_from": (
                self.cap_effective_from.isoformat() if self.cap_effective_from else None
            ),
            "next_cap_days": self.next_cap_days,
            "next_cap_effective_from": (
                self.next_cap_effective_from.isoformat()
                if self.next_cap_effective_from
                else None
            ),
            "short_lived": self.short_lived,
            "short_lived_threshold_days": self.short_lived_threshold_days,
            "expired": self.expired,
            "not_yet_valid": self.not_yet_valid,
            "detail": self.detail,
        }


@dataclass
class RevocationEndpoints:
    """Revocation metadata carried by the certificate (items 13, 31).

    Extraction only. Whether the endpoints answer, and what they say, is
    `revocation.py`'s job.
    """

    ocsp_urls: List[str] = field(default_factory=list)
    crl_urls: List[str] = field(default_factory=list)
    ca_issuer_urls: List[str] = field(default_factory=list)
    # RFC 7633 TLS Feature extension carrying status_request (item 13).
    must_staple: bool = False

    @property
    def has_any_source(self) -> bool:
        return bool(self.ocsp_urls or self.crl_urls)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ocsp_urls": list(self.ocsp_urls),
            "crl_urls": list(self.crl_urls),
            "ca_issuer_urls": list(self.ca_issuer_urls),
            "must_staple": self.must_staple,
            "has_any_source": self.has_any_source,
        }


@dataclass
class UsageAudit:
    """keyUsage and extendedKeyUsage profile audit (item 36)."""

    key_usage: List[str] = field(default_factory=list)
    extended_key_usage: List[str] = field(default_factory=list)
    has_server_auth: bool = False
    conflicting_ekus: List[str] = field(default_factory=list)
    # A leaf asserting keyCertSign is either a CA certificate being served as
    # an end-entity certificate, or a serious misissuance.
    asserts_cert_sign: bool = False
    is_ca: bool = False
    path_length: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "key_usage": list(self.key_usage),
            "extended_key_usage": list(self.extended_key_usage),
            "has_server_auth": self.has_server_auth,
            "conflicting_ekus": list(self.conflicting_ekus),
            "asserts_cert_sign": self.asserts_cert_sign,
            "is_ca": self.is_ca,
            "path_length": self.path_length,
        }


@dataclass
class Fingerprints:
    """Certificate and public-key fingerprints (item 9).

    `spki_sha256_b64` is the SPKI pin format — base64 of the SHA-256 over the
    DER-encoded SubjectPublicKeyInfo. It is the value app-level pinning and
    `--expected-fingerprint` (item 50) compare against, and it is deliberately
    over the *key* rather than the certificate: a routine renewal that reuses
    the key leaves this stable, while the certificate fingerprint changes.
    Pinning the certificate fingerprint breaks on every renewal.
    """

    cert_sha256: str
    cert_sha1: str
    spki_sha256: str
    spki_sha256_b64: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cert_sha256": self.cert_sha256,
            "cert_sha1": self.cert_sha1,
            "spki_sha256": self.spki_sha256,
            "spki_sha256_b64": self.spki_sha256_b64,
        }


# ---------------------------------------------------------------------------
# The parsed certificate
# ---------------------------------------------------------------------------


@dataclass
class CertificateInfo:
    """Everything derivable from one certificate in isolation.

    Field grouping mirrors `HTTPResult` and `DNSQueryResult`: identity first,
    then parsed content, then verdicts. Verdicts are held separately from the
    facts that produced them so an export consumer can re-derive a verdict
    under different policy without reparsing.
    """

    # --- identity ---
    subject_dn: str
    issuer_dn: str
    serial_number: str  # hex, no 0x prefix
    version: str

    # --- names (item 6) ---
    subject_cn: Optional[str] = None
    issuer_cn: Optional[str] = None
    issuer_org: Optional[str] = None
    san_dns: List[str] = field(default_factory=list)
    san_ip: List[str] = field(default_factory=list)
    san_email: List[str] = field(default_factory=list)
    san_uri: List[str] = field(default_factory=list)
    wildcard: WildcardAudit = field(default_factory=WildcardAudit)

    # --- signature (item 7) ---
    signature_algorithm: Optional[str] = None
    signature_hash: Optional[str] = None
    signature_weak: bool = False
    signature_weak_reason: Optional[str] = None

    # --- key (item 8) ---
    public_key: PublicKeyInfo = field(
        default_factory=lambda: PublicKeyInfo(key_type=KeyType.UNKNOWN)
    )

    # --- fingerprints (item 9) ---
    fingerprints: Optional[Fingerprints] = None

    # --- lifetime (items 16-18) ---
    lifetime: Optional[LifetimeAudit] = None

    # --- revocation metadata (items 13, 31) ---
    revocation: RevocationEndpoints = field(default_factory=RevocationEndpoints)

    # --- usage (item 36) ---
    usage: UsageAudit = field(default_factory=UsageAudit)

    # --- self-signed (item 10) ---
    # Issuer DN equals subject DN. Named `self_issued` rather than
    # `self_signed` because a matching DN does NOT prove the certificate signed
    # itself: cross-signed roots and misconfigured private CAs both produce
    # self-issued certificates that were signed by a different key. Proving
    # self-signature requires verifying the signature with the embedded public
    # key, which `self_signed` below does.
    self_issued: bool = False
    self_signed: Optional[bool] = None

    # --- diagnostics ---
    parse_errors: List[str] = field(default_factory=list)

    @property
    def all_san_names(self) -> List[str]:
        return list(self.san_dns) + list(self.san_ip)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "subject_dn": self.subject_dn,
            "issuer_dn": self.issuer_dn,
            "serial_number": self.serial_number,
            "version": self.version,
            "subject_cn": self.subject_cn,
            "issuer_cn": self.issuer_cn,
            "issuer_org": self.issuer_org,
            "san_dns": list(self.san_dns),
            "san_ip": list(self.san_ip),
            "san_email": list(self.san_email),
            "san_uri": list(self.san_uri),
            "san_count": len(self.all_san_names),
            "wildcard": self.wildcard.to_dict(),
            "signature_algorithm": self.signature_algorithm,
            "signature_hash": self.signature_hash,
            "signature_weak": self.signature_weak,
            "signature_weak_reason": self.signature_weak_reason,
            "public_key": self.public_key.to_dict(),
            "fingerprints": (
                self.fingerprints.to_dict() if self.fingerprints else None
            ),
            "lifetime": self.lifetime.to_dict() if self.lifetime else None,
            "revocation": self.revocation.to_dict(),
            "usage": self.usage.to_dict(),
            "self_issued": self.self_issued,
            "self_signed": self.self_signed,
            "parse_errors": list(self.parse_errors),
        }


# ---------------------------------------------------------------------------
# Name helpers
# ---------------------------------------------------------------------------


def _attr_value(name: x509.Name, oid: x509.ObjectIdentifier) -> Optional[str]:
    """First attribute value for `oid`, decoded to str, or None.

    `NameAttribute.value` is `str | bytes` — bytes for the rare
    X520 attributes that carry a raw octet string. Both are handled rather
    than assumed, which is the bug the existing `_parse_cert_der` guards
    against and this must not regress.
    """
    try:
        attributes = name.get_attributes_for_oid(oid)
    except Exception:  # pragma: no cover — defensive
        return None
    if not attributes:
        return None
    raw = attributes[0].value
    if isinstance(raw, bytes):
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            return raw.hex()
    return raw


def _split_san(
    cert: x509.Certificate,
    errors: List[str],
) -> Tuple[List[str], List[str], List[str], List[str]]:
    """Return (dns, ip, email, uri) from subjectAltName (item 6)."""
    try:
        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
    except x509.ExtensionNotFound:
        return [], [], [], []
    except ValueError as exc:
        errors.append(f"subjectAltName unparseable: {exc}")
        return [], [], [], []

    san = ext.value
    if not isinstance(san, x509.SubjectAlternativeName):  # pragma: no cover
        return [], [], [], []

    dns_names = [str(v) for v in san.get_values_for_type(x509.DNSName)]
    ip_names = [str(v) for v in san.get_values_for_type(x509.IPAddress)]
    emails = [str(v) for v in san.get_values_for_type(x509.RFC822Name)]
    uris = [str(v) for v in san.get_values_for_type(x509.UniformResourceIdentifier)]
    return dns_names, ip_names, emails, uris


def audit_wildcards(dns_names: Sequence[str]) -> WildcardAudit:
    """Wildcard presence and scope over the DNS SAN entries (item 6)."""
    entries = [n for n in dns_names if "*" in n]
    if not entries:
        return WildcardAudit(present=False)

    depths = [len(n.split(".")) for n in entries]
    min_depth = min(depths)

    notes: List[str] = []
    # RFC 6125 §6.4.3: the wildcard must be the complete leftmost label.
    # `f*.example.com` and `*.*.example.com` are rejected by modern clients,
    # so a certificate containing them is effectively broken for those names.
    malformed = [
        n
        for n in entries
        if not n.startswith("*.") or "*" in n.split(".", 1)[1] or n.count("*") > 1
    ]
    if malformed:
        notes.append(
            "partial or non-leftmost wildcard labels are rejected by modern "
            f"clients: {', '.join(sorted(malformed))}"
        )

    overly_broad = min_depth <= 2
    if overly_broad:
        notes.append(
            "wildcard spans two labels or fewer; authoritative scope requires "
            "the Public Suffix List (foundation item 19) and is not checked here"
        )

    return WildcardAudit(
        present=True,
        entries=sorted(entries),
        min_label_depth=min_depth,
        overly_broad=overly_broad,
        note="; ".join(notes) if notes else None,
    )


# ---------------------------------------------------------------------------
# Hostname matching (item 11)
# ---------------------------------------------------------------------------


def _match_dns_label(pattern: str, hostname: str) -> bool:
    """RFC 6125 §6.4.3 name matching for one dNSName pattern.

    Rules enforced, each of which a naive `fnmatch` would get wrong:

    * the wildcard is only valid as the complete leftmost label — `f*.a.com`
      does not match;
    * `*.example.com` matches `a.example.com` but **not** `example.com`
      itself, which is the single most common misconception here;
    * `*.example.com` does **not** match `a.b.example.com` — a wildcard spans
      exactly one label;
    * comparison is case-insensitive on ASCII.

    IDNA is the caller's responsibility. Both sides are compared as A-labels;
    `DomainManager` already normalises input, and re-encoding here would give
    two normalisation paths that could disagree.
    """
    pattern = pattern.lower().rstrip(".")
    hostname = hostname.lower().rstrip(".")

    if "*" not in pattern:
        return pattern == hostname

    if not pattern.startswith("*."):
        return False
    remainder = pattern[2:]
    if "*" in remainder or not remainder:
        return False

    host_labels = hostname.split(".")
    pattern_labels = remainder.split(".")
    # The wildcard consumes exactly one label, so the hostname must carry
    # exactly one more label than the pattern remainder.
    if len(host_labels) != len(pattern_labels) + 1:
        return False
    if not host_labels[0]:
        return False
    return host_labels[1:] == pattern_labels


def match_hostname(info: CertificateInfo, hostname: str) -> HostnameMatch:
    """Check `hostname` against the certificate's SANs (item 11).

    Subject CN is deliberately **not** consulted as a fallback. CN-as-hostname
    was deprecated by RFC 2818 in 2000 and removed from Chrome in 2017, so a
    certificate whose only name is in the CN does not work in any current
    client. Matching on CN here would report a certificate as valid for a name
    that every browser rejects — a false pass, which is worse than a false
    finding.
    """
    if not hostname:
        return HostnameMatch.NOT_CHECKED

    if not info.san_dns and not info.san_ip:
        return HostnameMatch.NO_SAN

    # An IP literal must match an iPAddress SAN, never a dNSName.
    try:
        target_ip = ipaddress.ip_address(hostname.strip("[]"))
    except ValueError:
        target_ip = None

    if target_ip is not None:
        for candidate in info.san_ip:
            try:
                if ipaddress.ip_address(candidate) == target_ip:
                    return HostnameMatch.MATCH
            except ValueError:
                continue
        return HostnameMatch.MISMATCH

    for pattern in info.san_dns:
        if _match_dns_label(pattern, hostname):
            return HostnameMatch.MATCH
    return HostnameMatch.MISMATCH


# ---------------------------------------------------------------------------
# Key and signature audit
# ---------------------------------------------------------------------------


def audit_public_key(cert: x509.Certificate, errors: List[str]) -> PublicKeyInfo:
    """Key type, size and weak-key verdict (item 8)."""
    try:
        key = cert.public_key()
    except Exception as exc:  # pragma: no cover — malformed key
        errors.append(f"public key unparseable: {exc}")
        return PublicKeyInfo(key_type=KeyType.UNKNOWN)

    if isinstance(key, rsa.RSAPublicKey):
        bits = key.key_size
        weak = bits < MIN_RSA_BITS
        return PublicKeyInfo(
            key_type=KeyType.RSA,
            key_size=bits,
            weak=weak,
            weak_reason=(f"RSA {bits}-bit is below {MIN_RSA_BITS}" if weak else None),
        )

    if isinstance(key, ec.EllipticCurvePublicKey):
        curve = key.curve.name
        bits = key.curve.key_size
        reasons: List[str] = []
        if bits < MIN_EC_BITS:
            reasons.append(f"EC {bits}-bit is below {MIN_EC_BITS}")
        if curve.lower() in WEAK_EC_CURVES:
            reasons.append(f"curve {curve} is deprecated")
        return PublicKeyInfo(
            key_type=KeyType.ECDSA,
            key_size=bits,
            curve_name=curve,
            weak=bool(reasons),
            weak_reason="; ".join(reasons) if reasons else None,
        )

    if isinstance(key, ed25519.Ed25519PublicKey):
        # Ed25519 has no size parameter; 256 is its fixed key size and is
        # recorded so numeric comparisons across key types do not break.
        return PublicKeyInfo(key_type=KeyType.ED25519, key_size=256)

    if isinstance(key, ed448.Ed448PublicKey):
        return PublicKeyInfo(key_type=KeyType.ED448, key_size=448)

    if isinstance(key, dsa.DSAPublicKey):
        return PublicKeyInfo(
            key_type=KeyType.DSA,
            key_size=key.key_size,
            weak=True,
            weak_reason="DSA is not permitted for TLS server certificates",
        )

    return PublicKeyInfo(key_type=KeyType.UNKNOWN)


def audit_signature(
    cert: x509.Certificate,
    errors: List[str],
) -> Tuple[Optional[str], Optional[str], bool, Optional[str]]:
    """Return (algorithm_oid_name, hash_name, weak, reason) (item 7).

    Ed25519 and Ed448 have no separable signature hash — `cryptography` raises
    for `signature_hash_algorithm` on those. That is not a weak signature and
    must not be reported as an unknown hash, which would put the strongest
    algorithms in the tool into the same bucket as MD5.
    """
    algorithm: Optional[str]
    try:
        algorithm = cert.signature_algorithm_oid._name
    except AttributeError:  # pragma: no cover
        algorithm = cert.signature_algorithm_oid.dotted_string

    oid = cert.signature_algorithm_oid.dotted_string
    # id-Ed25519 / id-Ed448
    if oid in ("1.3.101.112", "1.3.101.113"):
        return algorithm, None, False, None

    hash_name: Optional[str] = None
    try:
        hash_algorithm: Optional[hashes.HashAlgorithm] = cert.signature_hash_algorithm
        if hash_algorithm is not None:
            hash_name = hash_algorithm.name
    except (ValueError, UnsupportedAlgorithm) as exc:
        errors.append(f"signature hash unavailable: {exc}")
        return algorithm, None, False, None

    if hash_name is None:
        return algorithm, None, False, None

    if hash_name.lower() in WEAK_SIGNATURE_HASHES:
        return (
            algorithm,
            hash_name,
            True,
            f"{hash_name.upper()} is broken for certificate signing",
        )
    return algorithm, hash_name, False, None


# ---------------------------------------------------------------------------
# Lifetime audit (items 16, 17, 18)
# ---------------------------------------------------------------------------


def audit_lifetime(
    cert: x509.Certificate,
    now: Optional[datetime] = None,
) -> LifetimeAudit:
    """Audit validity period against the CA/B schedule.

    The CA/B Baseline Requirements define the validity period as notBefore
    through notAfter inclusive, and the cap as an upper bound on that span. So
    the comparison is `not_after - not_before > cap`, matching how zlint
    implements the same lint — not `>=`, which would fail every certificate
    issued exactly at the limit.
    """
    now = now or datetime.now(tz=timezone.utc)

    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc

    span = not_after - not_before
    lifetime_days = span.days
    days_remaining = (not_after - now).days

    cap_days, cap_from = cab_lifetime_cap(not_before)
    short_threshold = cab_short_lived_threshold(not_before)
    short_lived = short_threshold is not None and span <= timedelta(
        days=short_threshold
    )

    audit = LifetimeAudit(
        not_before=not_before,
        not_after=not_after,
        lifetime_days=lifetime_days,
        days_remaining=days_remaining,
        verdict=LifetimeVerdict.UNKNOWN,
        cap_days=cap_days,
        cap_effective_from=cap_from,
        short_lived=short_lived,
        short_lived_threshold_days=short_threshold,
        expired=now > not_after,
        not_yet_valid=now < not_before,
    )

    if cap_days is None:
        audit.detail = (
            "issued before the first CA/Browser Forum lifetime cap in the "
            "schedule; no cap to audit against"
        )
        return audit

    if span > timedelta(days=cap_days):
        audit.verdict = LifetimeVerdict.NON_COMPLIANT
        audit.detail = (
            f"validity period of {lifetime_days} days exceeds the {cap_days}-day "
            f"cap in force from {cap_from.date().isoformat() if cap_from else '?'}"
        )
        return audit

    # Item 17 — forward look. A renewal issued the moment this certificate
    # expires falls under whichever cap is in force then. If a certificate of
    # this same length would breach it, that is actionable now, because the
    # renewal has to be shortened before it happens rather than after.
    next_days, next_from = _next_cap_after(not_before)
    audit.next_cap_days = next_days
    audit.next_cap_effective_from = next_from

    if (
        next_days is not None
        and next_from is not None
        and not_after >= next_from
        and span > timedelta(days=next_days)
    ):
        audit.verdict = LifetimeVerdict.FAILS_AT_NEXT_RENEWAL
        audit.detail = (
            f"validity period of {lifetime_days} days is within the current "
            f"{cap_days}-day cap, but exceeds the {next_days}-day cap taking "
            f"effect {next_from.date().isoformat()}; renewal at this length "
            "will be refused"
        )
        return audit

    audit.verdict = LifetimeVerdict.COMPLIANT
    return audit


# ---------------------------------------------------------------------------
# Extension extraction
# ---------------------------------------------------------------------------


def extract_revocation_endpoints(
    cert: x509.Certificate,
    errors: List[str],
) -> RevocationEndpoints:
    """Pull AIA, CRL DP and TLS Feature out of the certificate (items 13, 31)."""
    endpoints = RevocationEndpoints()

    try:
        aia = cert.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_INFORMATION_ACCESS
        ).value
        if isinstance(aia, x509.AuthorityInformationAccess):
            for description in aia:
                location = description.access_location
                if not isinstance(location, x509.UniformResourceIdentifier):
                    continue
                if description.access_method == AuthorityInformationAccessOID.OCSP:
                    endpoints.ocsp_urls.append(str(location.value))
                elif (
                    description.access_method
                    == AuthorityInformationAccessOID.CA_ISSUERS
                ):
                    endpoints.ca_issuer_urls.append(str(location.value))
    except x509.ExtensionNotFound:
        pass
    except ValueError as exc:
        errors.append(f"AIA unparseable: {exc}")

    try:
        crl_dp = cert.extensions.get_extension_for_oid(
            ExtensionOID.CRL_DISTRIBUTION_POINTS
        ).value
        if isinstance(crl_dp, x509.CRLDistributionPoints):
            for point in crl_dp:
                for name in point.full_name or []:
                    if isinstance(name, x509.UniformResourceIdentifier):
                        endpoints.crl_urls.append(str(name.value))
    except x509.ExtensionNotFound:
        pass
    except ValueError as exc:
        errors.append(f"CRL distribution points unparseable: {exc}")

    try:
        features = cert.extensions.get_extension_for_class(x509.TLSFeature).value
        if isinstance(features, x509.TLSFeature):
            endpoints.must_staple = any(
                feature == x509.TLSFeatureType.status_request for feature in features
            )
    except x509.ExtensionNotFound:
        pass
    except ValueError as exc:
        errors.append(f"TLS feature extension unparseable: {exc}")

    return endpoints


def audit_usage(cert: x509.Certificate, errors: List[str]) -> UsageAudit:
    """keyUsage / extendedKeyUsage / basicConstraints audit (item 36)."""
    audit = UsageAudit()

    try:
        usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        if isinstance(usage, x509.KeyUsage):
            flags = {
                "digitalSignature": usage.digital_signature,
                "contentCommitment": usage.content_commitment,
                "keyEncipherment": usage.key_encipherment,
                "dataEncipherment": usage.data_encipherment,
                "keyAgreement": usage.key_agreement,
                "keyCertSign": usage.key_cert_sign,
                "cRLSign": usage.crl_sign,
            }
            # encipherOnly/decipherOnly raise unless keyAgreement is asserted,
            # which is a documented quirk rather than an error condition.
            if usage.key_agreement:
                flags["encipherOnly"] = usage.encipher_only
                flags["decipherOnly"] = usage.decipher_only
            audit.key_usage = sorted(name for name, on in flags.items() if on)
            audit.asserts_cert_sign = usage.key_cert_sign
    except x509.ExtensionNotFound:
        pass
    except ValueError as exc:
        errors.append(f"keyUsage unparseable: {exc}")

    try:
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        if isinstance(eku, x509.ExtendedKeyUsage):
            names: List[str] = []
            for oid in eku:
                dotted = oid.dotted_string
                label = getattr(oid, "_name", None) or dotted
                names.append(str(label))
                if oid == ExtendedKeyUsageOID.SERVER_AUTH:
                    audit.has_server_auth = True
                conflict = CONFLICTING_EKUS.get(dotted)
                if conflict:
                    audit.conflicting_ekus.append(conflict)
            audit.extended_key_usage = names
    except x509.ExtensionNotFound:
        pass
    except ValueError as exc:
        errors.append(f"extendedKeyUsage unparseable: {exc}")

    try:
        constraints = cert.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value
        if isinstance(constraints, x509.BasicConstraints):
            audit.is_ca = constraints.ca
            audit.path_length = constraints.path_length
    except x509.ExtensionNotFound:
        pass
    except ValueError as exc:
        errors.append(f"basicConstraints unparseable: {exc}")

    return audit


def compute_fingerprints(cert: x509.Certificate) -> Fingerprints:
    """Certificate and SPKI fingerprints (item 9)."""
    spki_der = cert.public_key().public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
    )
    digest = hashes.Hash(hashes.SHA256())
    digest.update(spki_der)
    spki_sha256 = digest.finalize()

    return Fingerprints(
        cert_sha256=cert.fingerprint(hashes.SHA256()).hex(),
        cert_sha1=cert.fingerprint(hashes.SHA1()).hex(),
        spki_sha256=spki_sha256.hex(),
        spki_sha256_b64=base64.b64encode(spki_sha256).decode("ascii"),
    )


def _verify_self_signature(cert: x509.Certificate) -> Optional[bool]:
    """Whether the certificate's own key signed it (item 10).

    Returns None when the check cannot be performed — an unsupported
    algorithm, or a `cryptography` too old for `verify_directly_issued_by`.
    `None` is not `False`: a check that could not run has not established that
    the certificate was signed by someone else.
    """
    verifier = getattr(cert, "verify_directly_issued_by", None)
    if verifier is None:
        return None
    try:
        verifier(cert)
        return True
    except (ValueError, TypeError, UnsupportedAlgorithm):
        return False
    except Exception:  # pragma: no cover — signature mismatch raises InvalidSignature
        return False


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------


def parse_certificate(
    der: bytes,
    now: Optional[datetime] = None,
) -> CertificateInfo:
    """Parse DER certificate bytes into a `CertificateInfo`.

    Raises `ValueError` when the bytes are not a certificate at all. Every
    lesser problem — an unparseable individual extension, an unsupported
    signature algorithm — is recorded in `parse_errors` and the rest of the
    certificate is still reported.

    That asymmetry is deliberate. The existing `_parse_cert_der` in
    `http_bench/core.py` wraps everything in one `except Exception` and returns
    all-`None` on any failure, so a certificate with one malformed extension is
    indistinguishable from no certificate at all. A scanner exists to find
    malformed certificates; discarding them is the opposite of the job.
    """
    errors: List[str] = []
    cert = x509.load_der_x509_certificate(der)

    dns_names, ip_names, emails, uris = _split_san(cert, errors)
    algorithm, hash_name, sig_weak, sig_reason = audit_signature(cert, errors)

    try:
        version = cert.version.name
    except ValueError as exc:  # pragma: no cover — invalid version encoding
        version = "unknown"
        errors.append(f"certificate version unparseable: {exc}")

    info = CertificateInfo(
        subject_dn=cert.subject.rfc4514_string(),
        issuer_dn=cert.issuer.rfc4514_string(),
        serial_number=format(cert.serial_number, "x"),
        version=version,
        subject_cn=_attr_value(cert.subject, NameOID.COMMON_NAME),
        issuer_cn=_attr_value(cert.issuer, NameOID.COMMON_NAME),
        issuer_org=_attr_value(cert.issuer, NameOID.ORGANIZATION_NAME),
        san_dns=dns_names,
        san_ip=ip_names,
        san_email=emails,
        san_uri=uris,
        wildcard=audit_wildcards(dns_names),
        signature_algorithm=algorithm,
        signature_hash=hash_name,
        signature_weak=sig_weak,
        signature_weak_reason=sig_reason,
        public_key=audit_public_key(cert, errors),
        fingerprints=compute_fingerprints(cert),
        lifetime=audit_lifetime(cert, now=now),
        revocation=extract_revocation_endpoints(cert, errors),
        usage=audit_usage(cert, errors),
        parse_errors=errors,
    )

    info.self_issued = cert.subject == cert.issuer
    if info.self_issued:
        info.self_signed = _verify_self_signature(cert)

    return info


def parse_cert_der_compat(
    cert_der: bytes,
) -> Tuple[Optional[int], Optional[str], Optional[str], List[str], bool]:
    """Drop-in replacement for `http_bench.core._parse_cert_der` (item 15).

    Returns `(days_remaining, subject_cn, issuer_cn, sans, wildcard)`, the
    exact tuple that function returns today, so `HTTPResult` population is
    unchanged and the migration is an import swap.

    Kept deliberately thin. New HTTP work should call `parse_certificate()` and
    read the fields it needs; this exists so the migration does not have to
    rewrite `HTTPBenchmarkEngine` in the same change.
    """
    try:
        info = parse_certificate(cert_der)
    except Exception:
        return None, None, None, [], False
    days = info.lifetime.days_remaining if info.lifetime else None
    return (
        days,
        info.subject_cn,
        info.issuer_cn,
        list(info.san_dns),
        info.wildcard.present,
    )


__all__ = [
    "CAB_LIFETIME_SCHEDULE",
    "DEFAULT_EXPIRY_TIERS",
    "ExpiryAlert",
    "ExpiryTier",
    "expiry_alert",
    "CAB_SHORT_LIVED_SCHEDULE",
    "CertificateInfo",
    "Fingerprints",
    "HostnameMatch",
    "KeyType",
    "LifetimeAudit",
    "LifetimeVerdict",
    "PublicKeyInfo",
    "RevocationEndpoints",
    "UsageAudit",
    "WildcardAudit",
    "audit_lifetime",
    "audit_public_key",
    "audit_signature",
    "audit_usage",
    "audit_wildcards",
    "cab_lifetime_cap",
    "cab_short_lived_threshold",
    "compute_fingerprints",
    "extract_revocation_endpoints",
    "match_hostname",
    "parse_cert_der_compat",
    "parse_certificate",
]
