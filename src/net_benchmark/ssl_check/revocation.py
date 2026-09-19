"""Live OCSP and CRL revocation checking for the SSL/TLS module.

net-benchmark 0.6.1 — ROADMAP.md, SSL "Revocation" items 27-30/32-35
(originally items 17-18 in the earlier Roadmap Discussion #45 draft, before
the more detailed roadmap superseded it — see chain.py's docstring for the
same correction). Item 31 (extracting the OCSP/CRL URLs themselves) is
`certificate.py`'s `RevocationEndpoints`, already done; that module's own
docstring names this one as the thing that answers whether those endpoints
say the certificate is still good.

Item 20 (OCSP stapling) is deliberately NOT here
--------------------------------------------------
The roadmap line for item 20 says stdlib `ssl` can detect stapling via "TLS
extension inspection". It cannot: CPython's `ssl` module has never exposed
the stapled `CertificateStatus` response (TLS <= 1.2) or the `status_request`
extension on the Certificate message (TLS 1.3) through any public API --
there is nothing to inspect from Python once OpenSSL has processed the
handshake. `handshake.py`'s memory-BIO design does not help either: OpenSSL
decrypts the handshake flight internally before this module ever sees the
bytes, so the raw stream never contains a parsed, attributable OCSP
extension. Getting this would need a library that exposes OpenSSL's OCSP
callback API directly (e.g. pyOpenSSL) -- a second compiled TLS binding
alongside `cryptography`, which the dependency policy (`cryptography` is the
sole permitted compiled dependency) does not allow without a deliberate
exception. Flagged rather than silently dropped or half-implemented.

Getting the issuer certificate
-------------------------------
OCSP request construction needs the issuer's name and key hash, not the
whole chain to a trust anchor; CRL and OCSP-response signature verification
need the issuer's public key, same scope. This module does not build a
chain itself -- `check_revocation()` takes an already-available issuer
certificate (`SSLResult.chain_audit.links[0].raw`, when chain verification
ran) or, when none was supplied, fetches exactly one certificate itself via
`chain.fetch_issuer_certificate` -- the same AIA CA-Issuers fetch chain.py
uses, reused rather than duplicated.

What "revoked" means here
---------------------------
CRL is the primary channel, OCSP secondary -- not two equal-weight checks.
The CA/Browser Forum made CRL mandatory and OCSP optional in its August 2023
Baseline Requirements ballot, and the shift is not theoretical: Let's Encrypt
stopped including OCSP URLs in certificates on 7 May 2025 and shut its OCSP
responders down entirely on 6 August 2025. A large share of the public web
now has no OCSP endpoint to check at all, so treating the two as symmetric
would silently downgrade "we only have one channel to check" into "the other
channel found nothing wrong" for exactly the certificates most likely to lack
one. `check_revocation()` runs the CRL check first, for this reason, and a
CRL is the channel this module caches to disk (see `CRLCache` below) --
OCSP responses are far smaller and their own freshness window is typically
much shorter, so there's less to gain from caching them.

`RevocationAudit.revoked` is `True` if *either* channel said REVOKED --
revocation is the one place a security tool should stay conservative, so an
OCSP REVOKED is never suppressed just because CRL disagrees or wasn't
checked. It is `False` only when CRL gave a fresh GOOD (OCSP's GOOD alone,
with no CRL corroboration, is treated as the weaker signal it now is given
the paragraph above), and `None` when neither channel produced a usable
answer.
"""

from __future__ import annotations

import hashlib
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

import httpx
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import ocsp

from net_benchmark.ssl_check.certificate import RevocationEndpoints
from net_benchmark.ssl_check.chain import fetch_issuer_certificate

DEFAULT_OCSP_TIMEOUT = 10.0
DEFAULT_CRL_TIMEOUT = 10.0

# Raised from the original 8 MiB: a CRL is every certificate a CA has ever
# revoked, unlike a single certificate, and a large CA's CRL runs to the
# tens or low hundreds of MiB -- an 8 MiB cap would have silently rejected
# a real CRL from a real large CA, not just protected against a hostile one.
# `cryptography` has no incremental CRL parser (the whole file is loaded to
# parse it regardless), so this bounds memory for one fetch; the disk cache
# below is what keeps repeated fetches of the same large CRL affordable.
DEFAULT_MAX_CRL_BYTES = 256 * 1024 * 1024

# How long a cached CRL is used without re-fetching, when the CRL's own
# `next_update` is further out than this. A CRL's own freshness window can
# be days; re-fetching a multi-hundred-MiB file every scan run within that
# window just to confirm nothing changed is the exact cost this cache exists
# to remove. Deliberately shorter than most CRLs' own `next_update` so a
# long-lived cache entry still gets refreshed periodically rather than
# trusted for its entire validity window.
DEFAULT_CRL_CACHE_MAX_AGE = 3600.0 * 6  # 6 hours

# Total on-disk budget for cached CRLs across all CAs. Oldest-by-mtime
# entries are evicted once this is exceeded, after a new entry is written --
# never a reason to fail a fetch, only to make room for it.
DEFAULT_CRL_CACHE_MAX_BYTES = 512 * 1024 * 1024

_OCSP_REQUEST_CONTENT_TYPE = "application/ocsp-request"


class OCSPStatus(str, Enum):
    NOT_CHECKED = "not_checked"
    GOOD = "good"
    REVOKED = "revoked"
    # Responder answered SUCCESSFUL but doesn't have an opinion on this
    # serial -- RFC 6960's own UNKNOWN, not a parse or network failure.
    UNKNOWN = "unknown"
    UNREACHABLE = "unreachable"
    # Parsed fine, but `next_update` has already passed -- not trusted
    # either way, since a stale GOOD is what a responder returns right up
    # until the moment it is finally told about a compromise.
    STALE = "stale"
    # Response body parsed but the signature over it did not verify against
    # the issuer (or, for a delegated responder, the issuer-issued delegate)
    # -- treated as untrustworthy, not as evidence of anything.
    INVALID_SIGNATURE = "invalid_signature"


class CRLStatus(str, Enum):
    NOT_CHECKED = "not_checked"
    GOOD = "good"
    REVOKED = "revoked"
    UNREACHABLE = "unreachable"
    STALE = "stale"
    INVALID_SIGNATURE = "invalid_signature"


@dataclass
class RevocationAudit:
    """Result of checking one leaf certificate against its own OCSP
    responders and CRL distribution points.
    """

    attempted: bool = False
    issuer_source: Optional[str] = None  # "provided" | "aia_fetch" | None

    ocsp_status: OCSPStatus = OCSPStatus.NOT_CHECKED
    ocsp_responder_url: Optional[str] = None
    ocsp_responder_delegated: bool = False
    ocsp_produced_at: Optional[datetime] = None
    ocsp_this_update: Optional[datetime] = None
    ocsp_next_update: Optional[datetime] = None
    ocsp_revocation_time: Optional[datetime] = None
    ocsp_revocation_reason: Optional[str] = None

    crl_status: CRLStatus = CRLStatus.NOT_CHECKED
    crl_url: Optional[str] = None
    # Item 32 (0.6.1): served from the on-disk cache rather than fetched
    # fresh this run. See `CRLCache`.
    crl_from_cache: bool = False
    crl_this_update: Optional[datetime] = None
    crl_next_update: Optional[datetime] = None
    crl_revocation_time: Optional[datetime] = None

    check_errors: List[str] = field(default_factory=list)

    @property
    def revoked(self) -> Optional[bool]:
        """True if either channel said REVOKED -- revocation stays the
        conservative case regardless of channel priority. False only when
        CRL (the primary channel; see the module docstring) gave a fresh
        GOOD; OCSP's GOOD alone is the weaker signal now that a large share
        of certificates have no OCSP endpoint to begin with, so it is not
        enough on its own to call a certificate confirmed-good. None when
        neither channel produced a usable answer.
        """
        if (
            self.ocsp_status is OCSPStatus.REVOKED
            or self.crl_status is CRLStatus.REVOKED
        ):
            return True
        if self.crl_status is CRLStatus.GOOD:
            return False
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "attempted": self.attempted,
            "issuer_source": self.issuer_source,
            "revoked": self.revoked,
            "ocsp_status": self.ocsp_status.value,
            "ocsp_responder_url": self.ocsp_responder_url,
            "ocsp_responder_delegated": self.ocsp_responder_delegated,
            "ocsp_produced_at": (
                self.ocsp_produced_at.isoformat() if self.ocsp_produced_at else None
            ),
            "ocsp_this_update": (
                self.ocsp_this_update.isoformat() if self.ocsp_this_update else None
            ),
            "ocsp_next_update": (
                self.ocsp_next_update.isoformat() if self.ocsp_next_update else None
            ),
            "ocsp_revocation_time": (
                self.ocsp_revocation_time.isoformat()
                if self.ocsp_revocation_time
                else None
            ),
            "ocsp_revocation_reason": self.ocsp_revocation_reason,
            "crl_status": self.crl_status.value,
            "crl_url": self.crl_url,
            "crl_from_cache": self.crl_from_cache,
            "crl_this_update": (
                self.crl_this_update.isoformat() if self.crl_this_update else None
            ),
            "crl_next_update": (
                self.crl_next_update.isoformat() if self.crl_next_update else None
            ),
            "crl_revocation_time": (
                self.crl_revocation_time.isoformat()
                if self.crl_revocation_time
                else None
            ),
            "check_errors": list(self.check_errors),
        }


# ---------------------------------------------------------------------------
# Signature verification helpers
# ---------------------------------------------------------------------------


# The key types `CertificateRevocationList.is_signature_valid` accepts --
# narrower than `Certificate.public_key()`'s return type, which also admits
# X25519/X448 (key-exchange-only, never a CA signing key in practice, but
# the type system doesn't know that).
_CRLSigningKey = Union[
    dsa.DSAPublicKey,
    rsa.RSAPublicKey,
    ec.EllipticCurvePublicKey,
    ed25519.Ed25519PublicKey,
    ed448.Ed448PublicKey,
]


def _crl_signing_key(cert: x509.Certificate) -> Optional[_CRLSigningKey]:
    key = cert.public_key()
    if isinstance(
        key,
        (
            dsa.DSAPublicKey,
            rsa.RSAPublicKey,
            ec.EllipticCurvePublicKey,
            ed25519.Ed25519PublicKey,
            ed448.Ed448PublicKey,
        ),
    ):
        return key
    return None


def _verify_signature(
    public_key: Any,
    signature: bytes,
    data: bytes,
    hash_algorithm: Optional[hashes.HashAlgorithm],
) -> bool:
    """Verify `signature` over `data` was made by `public_key`.

    Dispatches on key type the same way `certificate.audit_public_key` does
    -- Ed25519/Ed448 take no hash algorithm, RSA needs PKCS1v15 padding, EC
    needs the algorithm wrapped in `ec.ECDSA`. Returns False (not raises) for
    both a genuine signature mismatch and an unsupported key type, since
    both mean "this cannot be trusted", not "the caller made a mistake".
    """
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            from cryptography.hazmat.primitives.asymmetric import padding

            if hash_algorithm is None:
                return False
            public_key.verify(signature, data, padding.PKCS1v15(), hash_algorithm)
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            if hash_algorithm is None:
                return False
            public_key.verify(signature, data, ec.ECDSA(hash_algorithm))
        elif isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            public_key.verify(signature, data)
        else:
            return False
        return True
    except InvalidSignature:
        return False
    except (ValueError, TypeError):  # pragma: no cover -- malformed key/sig
        return False


def _ocsp_signer_key(
    response: ocsp.OCSPResponse, issuer: x509.Certificate
) -> Optional[Tuple[Any, bool]]:
    """The public key that should have signed `response`, and whether it
    belongs to a delegated responder rather than the issuer itself.

    A delegated responder's certificate travels inside the OCSP response
    itself (`response.certificates`); it is only trusted here once verified
    to have been issued directly by `issuer` -- an unverified delegate cert
    is just a certificate an attacker included in their own forged response.
    Only the first delegate certificate is considered, matching what every
    responder that uses delegation actually sends (one).
    """
    if not response.certificates:
        return issuer.public_key(), False
    delegate = response.certificates[0]
    verifier = getattr(delegate, "verify_directly_issued_by", None)
    if verifier is None:
        return None
    try:
        verifier(issuer)
    except Exception:
        return None
    return delegate.public_key(), True


def _verify_ocsp_response(
    response: ocsp.OCSPResponse, issuer: x509.Certificate
) -> Tuple[bool, bool]:
    """Returns (signature_valid, delegated)."""
    signer = _ocsp_signer_key(response, issuer)
    if signer is None:
        return False, False
    public_key, delegated = signer
    valid = _verify_signature(
        public_key,
        response.signature,
        response.tbs_response_bytes,
        response.signature_hash_algorithm,
    )
    return valid, delegated


# ---------------------------------------------------------------------------
# OCSP
# ---------------------------------------------------------------------------


async def check_ocsp(
    audit: RevocationAudit,
    leaf: x509.Certificate,
    issuer: x509.Certificate,
    urls: Sequence[str],
    *,
    client: httpx.AsyncClient,
    now: datetime,
    timeout: float = DEFAULT_OCSP_TIMEOUT,
) -> None:
    """Query each OCSP responder URL in turn; stop at the first that gives a
    definitive GOOD or REVOKED. Writes directly onto `audit` -- explicit
    per-field assignment rather than a generic dict handed back to the
    caller, so a typo'd field name is a mypy error here, not a silently
    dropped write at the call site.
    """
    last_inconclusive: Optional[OCSPStatus] = None

    def _apply_detail(
        url: str,
        delegated: bool,
        produced_at: Optional[datetime],
        this_update: Optional[datetime],
        next_update: Optional[datetime],
    ) -> None:
        audit.ocsp_responder_url = url
        audit.ocsp_responder_delegated = delegated
        audit.ocsp_produced_at = produced_at
        audit.ocsp_this_update = this_update
        audit.ocsp_next_update = next_update

    for url in urls:
        try:
            request = (
                ocsp.OCSPRequestBuilder()
                .add_certificate(leaf, issuer, hashes.SHA1())
                .build()
            )
            body = request.public_bytes(Encoding.DER)
            response = await client.post(
                url,
                content=body,
                headers={
                    "Content-Type": _OCSP_REQUEST_CONTENT_TYPE,
                    "Accept": "application/ocsp-response",
                },
                timeout=timeout,
            )
            response.raise_for_status()
            parsed = ocsp.load_der_ocsp_response(response.content)
        except httpx.HTTPError as exc:
            audit.check_errors.append(f"{url}: {type(exc).__name__}: {exc}")
            continue
        except ValueError as exc:
            audit.check_errors.append(
                f"{url}: response did not parse as an OCSP response: {exc}"
            )
            continue

        if parsed.response_status is not ocsp.OCSPResponseStatus.SUCCESSFUL:
            audit.check_errors.append(
                f"{url}: responder returned {parsed.response_status}"
            )
            continue

        valid, delegated = _verify_ocsp_response(parsed, issuer)
        if not valid:
            audit.check_errors.append(f"{url}: response signature did not verify")
            _apply_detail(
                url,
                delegated,
                parsed.produced_at_utc,
                parsed.this_update_utc,
                parsed.next_update_utc,
            )
            last_inconclusive = OCSPStatus.INVALID_SIGNATURE
            continue

        if parsed.next_update_utc is not None and now > parsed.next_update_utc:
            audit.check_errors.append(
                f"{url}: response is stale (next_update has passed)"
            )
            _apply_detail(
                url,
                delegated,
                parsed.produced_at_utc,
                parsed.this_update_utc,
                parsed.next_update_utc,
            )
            last_inconclusive = OCSPStatus.STALE
            continue

        _apply_detail(
            url,
            delegated,
            parsed.produced_at_utc,
            parsed.this_update_utc,
            parsed.next_update_utc,
        )
        if parsed.certificate_status is ocsp.OCSPCertStatus.GOOD:
            audit.ocsp_status = OCSPStatus.GOOD
            return
        if parsed.certificate_status is ocsp.OCSPCertStatus.REVOKED:
            audit.ocsp_revocation_time = parsed.revocation_time_utc
            audit.ocsp_revocation_reason = (
                parsed.revocation_reason.value if parsed.revocation_reason else None
            )
            audit.ocsp_status = OCSPStatus.REVOKED
            return

        # UNKNOWN -- responder answered, has no opinion on this serial. Worth
        # remembering in case every remaining URL is unreachable, but a later
        # URL giving a real GOOD/REVOKED still wins.
        last_inconclusive = OCSPStatus.UNKNOWN

    audit.ocsp_status = (
        last_inconclusive if last_inconclusive is not None else OCSPStatus.UNREACHABLE
    )


# ---------------------------------------------------------------------------
# CRL disk cache
# ---------------------------------------------------------------------------


def default_crl_cache_dir() -> Path:
    base = os.environ.get("XDG_CACHE_HOME")
    root = Path(base) if base else Path.home() / ".cache"
    return root / "net-benchmark" / "crl"


class CRLCache:
    """On-disk cache for fetched CRLs, keyed by URL.

    A stand-in for what foundation item 19 (the "shared runtime-dataset
    fetcher": pacing, on-disk cache with eviction, provenance, shared across
    revocation endpoints, CT logs, RIR files, the HSTS preload list and the
    Mozilla profile JSON) is meant to be -- that shared component is marked
    released in the roadmap but does not exist anywhere in this codebase as
    of this module; searched for it before writing this rather than assuming.
    This cache is scoped to exactly what CRL fetching needs and nothing
    beyond it; it should be replaced by the shared fetcher if and when that
    lands, not extended into one itself.

    Every operation is best-effort: a cache read or write failure (permission
    error, disk full, a corrupted cache file) falls back to treating the
    cache as empty rather than failing the revocation check it supports.
    """

    def __init__(
        self,
        directory: Optional[Path] = None,
        *,
        max_age: float = DEFAULT_CRL_CACHE_MAX_AGE,
        max_total_bytes: int = DEFAULT_CRL_CACHE_MAX_BYTES,
    ) -> None:
        self.directory = directory if directory is not None else default_crl_cache_dir()
        self.max_age = max_age
        self.max_total_bytes = max_total_bytes

    def _path(self, url: str) -> Path:
        digest = hashlib.sha256(url.encode("utf-8")).hexdigest()
        return self.directory / f"{digest}.crl"

    def get(self, url: str) -> Optional[bytes]:
        path = self._path(url)
        try:
            stat = path.stat()
        except OSError:
            return None
        if time.time() - stat.st_mtime > self.max_age:
            return None
        try:
            return path.read_bytes()
        except OSError:
            return None

    def put(self, url: str, data: bytes) -> None:
        try:
            self.directory.mkdir(parents=True, exist_ok=True)
            self._path(url).write_bytes(data)
        except OSError:
            return
        self._evict_if_needed()

    def _evict_if_needed(self) -> None:
        try:
            entries = [(p, p.stat()) for p in self.directory.glob("*.crl")]
        except OSError:
            return
        total = sum(stat.st_size for _, stat in entries)
        if total <= self.max_total_bytes:
            return
        # Oldest-by-mtime first, so a CA whose CRL is fetched often survives
        # a purge that a one-off scan's cache entry does not.
        entries.sort(key=lambda item: item[1].st_mtime)
        for path, stat in entries:
            if total <= self.max_total_bytes:
                break
            try:
                path.unlink()
                total -= stat.st_size
            except OSError:
                continue


async def _fetch_crl(
    client: httpx.AsyncClient,
    url: str,
    *,
    timeout: float,
    cache: Optional[CRLCache] = None,
) -> Tuple[Optional[x509.CertificateRevocationList], Optional[str], bool]:
    """Returns (crl_or_None, error_or_None, served_from_cache)."""
    if cache is not None:
        cached = cache.get(url)
        if cached is not None:
            for loader in (x509.load_der_x509_crl, x509.load_pem_x509_crl):
                try:
                    return loader(cached), None, True
                except ValueError:
                    continue
            # Cached bytes don't parse (corrupted, or written by an older,
            # incompatible version of this cache) -- fall through to a fresh
            # fetch rather than treating a bad cache entry as a fetch failure.

    try:
        async with client.stream(
            "GET", url, timeout=timeout, follow_redirects=True
        ) as response:
            response.raise_for_status()
            body = bytearray()
            truncated = False
            async for chunk in response.aiter_bytes():
                body.extend(chunk)
                if len(body) > DEFAULT_MAX_CRL_BYTES:
                    truncated = True
                    break
    except httpx.HTTPError as exc:
        return None, f"{url}: {type(exc).__name__}: {exc}", False

    if truncated:
        return None, f"{url}: response exceeded {DEFAULT_MAX_CRL_BYTES} bytes", False

    body_bytes = bytes(body)
    for loader in (x509.load_der_x509_crl, x509.load_pem_x509_crl):
        try:
            crl = loader(body_bytes)
        except ValueError:
            continue
        if cache is not None:
            cache.put(url, body_bytes)
        return crl, None, False
    return None, f"{url}: response did not parse as a CRL", False


async def check_crl(
    audit: RevocationAudit,
    leaf: x509.Certificate,
    issuer: x509.Certificate,
    urls: Sequence[str],
    *,
    client: httpx.AsyncClient,
    now: datetime,
    timeout: float = DEFAULT_CRL_TIMEOUT,
    cache: Optional[CRLCache] = None,
) -> None:
    """Fetch each CRL URL in turn; stop at the first that verifies and
    yields a definitive GOOD or REVOKED for the leaf's serial number. Writes
    directly onto `audit`, same reasoning as `check_ocsp`.
    """
    last_inconclusive: Optional[CRLStatus] = None

    for url in urls:
        crl, fetch_error, from_cache = await _fetch_crl(
            client, url, timeout=timeout, cache=cache
        )
        if crl is None:
            if fetch_error:
                audit.check_errors.append(fetch_error)
            continue

        signing_key = _crl_signing_key(issuer)
        if signing_key is None or not crl.is_signature_valid(signing_key):
            audit.check_errors.append(
                f"{url}: CRL signature did not verify against the issuer"
            )
            audit.crl_url = url
            audit.crl_from_cache = from_cache
            audit.crl_this_update = crl.last_update_utc
            audit.crl_next_update = crl.next_update_utc
            last_inconclusive = CRLStatus.INVALID_SIGNATURE
            continue

        audit.crl_url = url
        audit.crl_from_cache = from_cache
        audit.crl_this_update = crl.last_update_utc
        audit.crl_next_update = crl.next_update_utc
        if crl.next_update_utc is not None and now > crl.next_update_utc:
            audit.check_errors.append(f"{url}: CRL is stale (next_update has passed)")
            last_inconclusive = CRLStatus.STALE
            continue

        entry = crl.get_revoked_certificate_by_serial_number(leaf.serial_number)
        if entry is not None:
            # --- 0.6.1: cryptography's own x509.RevokedCertificate ABC
            # (cryptography/x509/base.py) declares revocation_date_utc as
            # an abstract property, but get_revoked_certificate_by_serial_
            # number()'s stub return type resolves to the empty low-level
            # rust_x509.RevokedCertificate stub instead -- the two are
            # linked only via ABCMeta.register() (runtime-only virtual
            # subclassing; see that file's own comment: "Runtime isinstance
            # checks need this since the rust class is not a subclass"),
            # which mypy cannot see through. Confirmed directly against the
            # installed stub file and reproduced on cryptography 44.0.3;
            # fixed upstream by 50.0.1, where get_revoked_certificate_by_
            # serial_number()'s own return type resolves correctly -- so a
            # cast() here would become a redundant-cast error under
            # --strict the moment the floor moves past whatever version
            # fixed it. getattr() is the one workaround that's correct
            # across this project's whole cryptography>=44.0,<51.0 range:
            # unlike cast(Any, ...), it only bypasses static checking for
            # this one attribute -- entry stays fully typed everywhere
            # else -- and it still raises AttributeError at runtime exactly
            # like dot-access would if the attribute were ever genuinely
            # removed.
            audit.crl_revocation_time = getattr(entry, "revocation_date_utc")
            audit.crl_status = CRLStatus.REVOKED
            return
        audit.crl_status = CRLStatus.GOOD
        return

    audit.crl_status = (
        last_inconclusive if last_inconclusive is not None else CRLStatus.UNREACHABLE
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


async def check_revocation(
    leaf_der: bytes,
    revocation_endpoints: RevocationEndpoints,
    *,
    client: httpx.AsyncClient,
    issuer: Optional[x509.Certificate] = None,
    now: Optional[datetime] = None,
    ocsp_timeout: float = DEFAULT_OCSP_TIMEOUT,
    crl_timeout: float = DEFAULT_CRL_TIMEOUT,
    crl_cache: Optional[CRLCache] = None,
    use_crl_cache: bool = True,
) -> RevocationAudit:
    """Check one leaf certificate against its own CRL distribution points
    and OCSP responders -- CRL first, as the primary channel; see the
    module docstring on why.

    `issuer` should be `SSLResult.chain_audit.links[0].raw` when chain
    verification already ran -- this function fetches its own copy via AIA
    only when the caller did not already have one, so the two checks never
    double-fetch the same certificate.

    `crl_cache` lets a caller share one `CRLCache` (and its eviction budget)
    across an entire scan; when not given and `use_crl_cache` is True, a
    default-location cache is created per call. Pass `use_crl_cache=False`
    for offline/no-disk-write operation.
    """
    audit = RevocationAudit(attempted=True)
    now = now or datetime.now(tz=timezone.utc)

    if not revocation_endpoints.ocsp_urls and not revocation_endpoints.crl_urls:
        return audit

    try:
        leaf = x509.load_der_x509_certificate(leaf_der)
    except ValueError as exc:
        audit.check_errors.append(f"leaf certificate unparseable: {exc}")
        return audit

    if issuer is not None:
        audit.issuer_source = "provided"
    else:
        if not revocation_endpoints.ca_issuer_urls:
            audit.check_errors.append(
                "no issuer certificate available and none fetchable "
                "(certificate carries no CA Issuers AIA URL)"
            )
            return audit
        fetched, fetch_error = await fetch_issuer_certificate(
            client, revocation_endpoints.ca_issuer_urls, timeout=ocsp_timeout
        )
        if fetched is None:
            audit.check_errors.append(fetch_error or "issuer certificate fetch failed")
            return audit
        issuer = fetched
        audit.issuer_source = "aia_fetch"

    if revocation_endpoints.crl_urls:
        cache = (
            crl_cache
            if crl_cache is not None
            else (CRLCache() if use_crl_cache else None)
        )
        await check_crl(
            audit,
            leaf,
            issuer,
            revocation_endpoints.crl_urls,
            client=client,
            now=now,
            timeout=crl_timeout,
            cache=cache,
        )

    if revocation_endpoints.ocsp_urls:
        await check_ocsp(
            audit,
            leaf,
            issuer,
            revocation_endpoints.ocsp_urls,
            client=client,
            now=now,
            timeout=ocsp_timeout,
        )

    return audit


__all__ = [
    "DEFAULT_OCSP_TIMEOUT",
    "DEFAULT_CRL_TIMEOUT",
    "DEFAULT_MAX_CRL_BYTES",
    "OCSPStatus",
    "CRLStatus",
    "RevocationAudit",
    "check_ocsp",
    "check_crl",
    "check_revocation",
]
