"""Chain-of-trust fetching and validation for the SSL/TLS module.

net-benchmark 0.6.1 — ROADMAP.md, SSL "Chain of trust" items 19-26/24-31
(originally items 11-16 in the earlier Roadmap Discussion #45 draft; that
draft and the repo's committed ROADMAP.md were both superseded by a more
detailed roadmap during this module's development — item numbers below
follow the current one)
(full AIA chain fetch, per-certificate breakdown, root/trust-store
validation, completeness check, cross-sign detection, weak hash in chain).

Scope boundary
--------------
This module takes an already-parsed leaf certificate (DER) plus whatever
chain the peer sent during the handshake (`handshake.py`'s `peer_chain_der`,
only observable on Python 3.13+ — see that module's docstring) and produces a
*validated* chain: it fetches missing intermediates via AIA, validates the
result against a trust store, and reports what it found. Revocation
(OCSP/CRL — roadmap items 17-18) is deliberately NOT this module's job; see
`certificate.py`'s `RevocationEndpoints` docstring. `revocation.py`, when it
lands, will use this module's fetched issuer certificates to build OCSP
requests rather than re-fetching them.

Trust store
-----------
Seeded from certifi's Mozilla bundle. The roadmap line for item 13 also asks
for "system roots" — there is no portable, dependency-free way to enumerate
the OS trust store from Python (this is what packages like `truststore` exist
for), so that half of item 13 is not implemented here. `trust_anchor_paths`
lets a caller supply additional PEM roots explicitly instead.

Why `cryptography.x509.verification` rather than a hand-rolled loop
---------------------------------------------------------------------
`certificate.py`'s `_verify_self_signature` already shows the primitive
(`Certificate.verify_directly_issued_by`) that a hand-rolled chain walk would
use link-by-link. That primitive checks only the signature. RFC 5280 path
validation also has to check basicConstraints (is this actually a CA cert,
and does its pathlen allow this position), validity at `now`, and key usage —
getting all of that right by hand is exactly the class of bug this library
exists to not have. `PolicyBuilder`/`Store`/`ServerVerifier` do the full
check and hand back the validated path (leaf through trust anchor) in one
call, so a "verified" result here means the same thing OpenSSL's own
`verify_mode = CERT_REQUIRED` would have concluded, had the handshake not
deliberately disabled it (see `handshake.py`, "Why verify_mode = CERT_NONE").

Network access
--------------
AIA fetching is real, per-target network I/O — a new class of side effect for
this module (the handshake itself never does DNS lookups beyond the initial
connect, and never talks to anything but the target). It is opt-in
(`SSLCheckEngine(verify_chain=True)` / CLI `--verify-chain`) so every existing
invocation and every existing test is unaffected by this module's presence.
"""

from __future__ import annotations

import ipaddress
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

import httpx
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, pkcs7
from cryptography.x509.verification import (
    PolicyBuilder,
    ServerVerifier,
    Store,
    Subject,
    VerificationError,
)

from net_benchmark.ssl_check.certificate import (
    CertificateInfo,
    audit_signature,
    extract_revocation_endpoints,
    parse_certificate,
)

# ---------------------------------------------------------------------------
# Tuning
# ---------------------------------------------------------------------------

# Certificates beyond this many hops from the leaf are not fetched. Real
# chains are 1-3 deep; this is a loop guard against a malicious or
# misconfigured AIA responder that chains back to itself or to an
# ever-growing set of "issuers", mirroring the byte/iteration caps
# `handshake.py` applies to the handshake pump itself.
DEFAULT_MAX_CHAIN_DEPTH = 8

# A certificate is a few KiB. This is generous headroom for a legitimate
# response while still bounding memory against a responder that streams an
# unbounded body at an AIA URL this tool was pointed at by a scanned target.
DEFAULT_MAX_FETCH_BYTES = 256 * 1024

DEFAULT_AIA_TIMEOUT = 10.0


class ChainSource(str, Enum):
    """Where one non-leaf certificate in a built chain came from."""

    PEER = "peer"
    AIA_FETCH = "aia_fetch"


@dataclass
class ChainLink:
    """One non-leaf certificate in a validated chain, with its provenance."""

    certificate: CertificateInfo
    source: ChainSource
    # The parsed cryptography object, not just its `CertificateInfo` facts --
    # `revocation.py` needs the actual issuer certificate (for OCSP request
    # construction and CRL/OCSP signature verification), not a dataclass of
    # facts extracted from it. Excluded from `to_dict()`: it isn't
    # JSON-serialisable and every fact in it is already in `certificate`.
    raw: x509.Certificate
    signature_weak: bool = False
    signature_weak_reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "certificate": self.certificate.to_dict(),
            "source": self.source.value,
            "signature_weak": self.signature_weak,
            "signature_weak_reason": self.signature_weak_reason,
        }


@dataclass
class ChainAudit:
    """Result of building and validating the chain above one leaf.

    `verified is True` means a path from the leaf to a trust anchor in the
    configured store validated under RFC 5280 path validation, as of `now`.
    Every other field describes *that* validated path — a rejected candidate
    path is recorded only in `verification_error`, not in `links`, since a
    chain that did not validate is not "the chain" for reporting purposes.
    """

    # Whether chain building was attempted at all. False only when the caller
    # never invoked it (e.g. no leaf certificate to start from) — kept
    # distinct from a build that ran and failed, the same distinction
    # `SSLResult.measured` draws for the handshake itself.
    attempted: bool = False

    verified: bool = False
    verification_error: Optional[str] = None

    # True once a validated path reached a trust anchor. Equivalent to
    # `verified` today, kept as a separate field because "complete" (a chain
    # exists) and "verified" (that chain is trusted) will diverge once a
    # caller can ask "build the chain, but don't require it to validate" —
    # not exposed yet, but the field split costs nothing now and avoids a
    # breaking rename later.
    complete: bool = False

    # At least one certificate in the validated chain was not supplied by the
    # peer during the handshake and had to be fetched via AIA. A compliant
    # server is expected to send its own full chain (CA/B Baseline
    # Requirements 4.9.13 / common practice); a target that needs this to be
    # True is a configuration finding worth surfacing even when the chain
    # otherwise validates fine.
    missing_intermediate: bool = False

    # Non-leaf certificate count in the validated chain (intermediates + the
    # trust anchor itself).
    depth: Optional[int] = None

    links: List[ChainLink] = field(default_factory=list)

    weak_hash_in_chain: bool = False
    weak_hash_details: List[str] = field(default_factory=list)

    # None = not evaluated (see `check_cross_sign` on `build_chain_audit`).
    # True/False only when an independent AIA-only path was actually built
    # and compared against the path the peer's own certificates produced —
    # see the module docstring on what this heuristic does and does not
    # catch.
    cross_signed: Optional[bool] = None
    cross_sign_detail: Optional[str] = None

    # Item 24 (0.6.1): did the peer send its own certificates in the correct
    # order (each one directly followed by its own issuer)? Distinct from
    # `complete` (does a valid path exist at all, built from whatever
    # combination of peer-sent and AIA-fetched certs it took) and from
    # `verified` (does that path's cryptography actually check out) — a
    # chain can be complete and valid while still having been *sent* out of
    # order, which some clients silently re-sort and others reject. None
    # when there is nothing to check: the peer sent 0-1 certificates, or the
    # platform cannot observe the peer's chain at all (`peer_chain_der` is
    # only ever populated on Python 3.13+; see `handshake.py`).
    peer_chain_ordered: Optional[bool] = None
    peer_chain_order_detail: Optional[str] = None

    fetch_errors: List[str] = field(default_factory=list)

    @property
    def root(self) -> Optional[CertificateInfo]:
        return self.links[-1].certificate if self.links else None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "attempted": self.attempted,
            "verified": self.verified,
            "verification_error": self.verification_error,
            "complete": self.complete,
            "missing_intermediate": self.missing_intermediate,
            "depth": self.depth,
            "links": [link.to_dict() for link in self.links],
            "root": self.root.to_dict() if self.root is not None else None,
            "weak_hash_in_chain": self.weak_hash_in_chain,
            "weak_hash_details": list(self.weak_hash_details),
            "cross_signed": self.cross_signed,
            "cross_sign_detail": self.cross_sign_detail,
            "peer_chain_ordered": self.peer_chain_ordered,
            "peer_chain_order_detail": self.peer_chain_order_detail,
            "fetch_errors": list(self.fetch_errors),
        }


# ---------------------------------------------------------------------------
# Trust store
# ---------------------------------------------------------------------------


@lru_cache(maxsize=8)
def _load_pem_roots(pem_path: str) -> Tuple[x509.Certificate, ...]:
    data = Path(pem_path).read_bytes()
    return tuple(x509.load_pem_x509_certificates(data))


def _load_system_roots() -> List[x509.Certificate]:
    """Best-effort load of the OS trust store via `ssl.get_default_verify_paths()`.

    Item 21 (0.6.1): "Mozilla (via certifi) plus system roots in the base
    install." No new dependency needed — `ssl.get_default_verify_paths()` is
    stdlib and exposes exactly the two locations OpenSSL itself would use
    (`cafile`, a single concatenated PEM bundle; `capath`, a directory of
    hash-named cert files). Earlier revisions of this module claimed there
    was no dependency-free way to reach system roots at all; that was wrong
    — there is no *portable* one (macOS without a Homebrew OpenSSL build may
    have neither path populated, since its trust store is Keychain-based),
    but where either path exists this reaches it with nothing new to install.

    Never raises: a platform where neither path resolves, or where a file
    fails to parse, falls back to certifi alone, exactly as before this was
    added.
    """
    roots: List[x509.Certificate] = []
    try:
        paths = ssl.get_default_verify_paths()
    except Exception:  # pragma: no cover — platform-dependent stdlib call
        return roots

    if paths.cafile:
        cafile = Path(paths.cafile)
        if cafile.is_file():
            try:
                roots.extend(x509.load_pem_x509_certificates(cafile.read_bytes()))
            except ValueError:
                pass

    if paths.capath:
        capath = Path(paths.capath)
        if capath.is_dir():
            for entry in capath.iterdir():
                if not entry.is_file():
                    continue
                try:
                    roots.append(x509.load_pem_x509_certificate(entry.read_bytes()))
                except ValueError:
                    # Not every hash-named entry is a parseable PEM cert on
                    # every distribution's layout; skipped rather than
                    # treated as a fatal error for the whole store.
                    continue
    return roots


@lru_cache(maxsize=8)
def default_trust_store(extra_pem_paths: Tuple[str, ...] = ()) -> Store:
    """Build a `Store` from certifi's bundle, the OS trust store, and any
    extra PEM files.

    Cached (keyed on `extra_pem_paths`) because parsing certifi's ~150 roots
    plus a system bundle is real work — paying it once per process rather
    than once per target is the difference between chain verification adding
    milliseconds and adding seconds to a multi-target scan. `extra_pem_paths`
    must be a tuple, not a list, so it is hashable for the cache key.
    """
    import certifi

    roots: List[x509.Certificate] = list(
        x509.load_pem_x509_certificates(Path(certifi.where()).read_bytes())
    )
    roots.extend(_load_system_roots())
    for pem_path in extra_pem_paths:
        roots.extend(_load_pem_roots(pem_path))
    return Store(roots)


# ---------------------------------------------------------------------------
# AIA fetching
# ---------------------------------------------------------------------------


def _parse_fetched_certificate(
    body: bytes, content_type: Optional[str]
) -> Optional[x509.Certificate]:
    """Best-effort parse of an AIA CA Issuers response.

    RFC 5280/2585 name `application/pkix-cert` (single DER certificate) as
    the expected type; in practice CAs also serve PEM and, occasionally, a
    degenerate PKCS#7 certs-only bundle (`application/pkcs7-mime`). All three
    are tried regardless of the declared content-type — CAs are not
    consistent about setting it correctly, and guessing from content is what
    every TLS client's chain-building code actually does.
    """
    for loader in (
        x509.load_der_x509_certificate,
        x509.load_pem_x509_certificate,
    ):
        try:
            return loader(body)
        except ValueError:
            continue
    try:
        bundle = pkcs7.load_der_pkcs7_certificates(body)
    except ValueError:
        bundle = None
    if bundle:
        return bundle[0]
    return None


async def fetch_issuer_certificate(
    client: httpx.AsyncClient,
    urls: Sequence[str],
    *,
    timeout: float,
) -> Tuple[Optional[x509.Certificate], Optional[str]]:
    """Try each CA Issuers URL in order; return the first certificate that
    parses, or (None, last_error).
    """
    last_error: Optional[str] = None
    for url in urls:
        body = bytearray()
        truncated = False
        content_type: Optional[str] = None
        try:
            async with client.stream(
                "GET", url, timeout=timeout, follow_redirects=True
            ) as response:
                response.raise_for_status()
                async for chunk in response.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > DEFAULT_MAX_FETCH_BYTES:
                        truncated = True
                        break
                content_type = response.headers.get("content-type")
        except httpx.HTTPError as exc:
            last_error = f"{url}: {type(exc).__name__}: {exc}"
            continue

        if truncated:
            last_error = f"{url}: response exceeded {DEFAULT_MAX_FETCH_BYTES} bytes"
            continue

        certificate = _parse_fetched_certificate(bytes(body), content_type)
        if certificate is None:
            last_error = f"{url}: response did not parse as a certificate"
            continue
        return certificate, None
    return None, last_error


# ---------------------------------------------------------------------------
# Chain building
# ---------------------------------------------------------------------------


def _verifier_subject(hostname: str) -> Subject:
    try:
        return x509.IPAddress(ipaddress.ip_address(hostname))
    except ValueError:
        return x509.DNSName(hostname)


def _audit_chain_signature(
    cert: x509.Certificate,
) -> Tuple[bool, Optional[str]]:
    _, _, weak, reason = audit_signature(cert, [])
    return weak, reason


def _check_chain_order(
    peer_sequence: Sequence[x509.Certificate],
) -> Tuple[Optional[bool], Optional[str]]:
    """Item 24 (0.6.1): did the peer send its certificates in the correct
    order — each one directly followed by its own issuer?

    A DN-level check (`cert[i].issuer == cert[i+1].subject`), not a signature
    verification — whether the signatures actually check out is what
    `build_chain_audit`'s validated path already establishes separately, via
    `cryptography.x509.verification`, which doesn't care what order its
    candidate list arrives in. This function exists only to answer the
    narrower, sequence-specific question a validating client's tolerance
    would otherwise hide: a chain that validates fine here because
    `ServerVerifier.verify()` doesn't care about input order can still be
    exactly the misordered chain that breaks a stricter client.

    `peer_sequence` is the full peer-sent list, leaf first — pass
    `[leaf, *peer_intermediates]`, not just the intermediates, since a
    leaf-to-first-intermediate mismatch is exactly as much an ordering
    problem as a mismatch further down the chain.
    """
    if len(peer_sequence) < 2:
        return None, None

    problems: List[str] = []
    for i in range(len(peer_sequence) - 1):
        current, next_cert = peer_sequence[i], peer_sequence[i + 1]
        if current.issuer != next_cert.subject:
            problems.append(
                f"position {i + 1} ({current.subject.rfc4514_string()}) is "
                f"not directly followed by its issuer — position {i + 2} is "
                f"{next_cert.subject.rfc4514_string()!r}, expected "
                f"{current.issuer.rfc4514_string()!r}"
            )
    if problems:
        return False, "; ".join(problems)
    return True, None


async def _build_path(
    leaf: x509.Certificate,
    seed_intermediates: Sequence[x509.Certificate],
    *,
    client: httpx.AsyncClient,
    verifier: ServerVerifier,
    max_depth: int,
    fetch_timeout: float,
) -> Tuple[Optional[List[x509.Certificate]], Set[bytes], List[str]]:
    """Verify `leaf` against `verifier`, fetching more candidates via AIA
    one at a time until it validates, the depth cap is hit, or AIA is
    exhausted.

    Returns (validated_chain_or_None, fetched_der_set, fetch_errors).
    `validated_chain` is the full path — leaf through trust anchor — exactly
    as `ServerVerifier.verify()` returns it; the trust anchor itself is
    never a fetched certificate, it is looked up from the `Store`.
    """
    candidates: List[x509.Certificate] = list(seed_intermediates)
    fetched: Set[bytes] = set()
    fetch_errors: List[str] = []
    error: Optional[Exception] = None
    frontier = leaf

    for _ in range(max_depth + 1):
        try:
            return verifier.verify(leaf, candidates), fetched, fetch_errors
        except VerificationError as exc:
            error = exc

        if frontier.subject == frontier.issuer:
            # Self-issued — no further AIA hop makes sense, and following
            # one would risk a loop back to the same certificate.
            break
        endpoints = extract_revocation_endpoints(frontier, [])
        if not endpoints.ca_issuer_urls:
            break

        next_cert, fetch_error = await fetch_issuer_certificate(
            client, endpoints.ca_issuer_urls, timeout=fetch_timeout
        )
        if fetch_error:
            fetch_errors.append(fetch_error)
        if next_cert is None:
            break

        candidates.append(next_cert)
        fetched.add(next_cert.public_bytes(Encoding.DER))
        frontier = next_cert

    if error is not None:
        fetch_errors.insert(0, str(error))
    return None, fetched, fetch_errors


async def build_chain_audit(
    leaf_der: bytes,
    peer_chain_der: Optional[Sequence[bytes]],
    *,
    client: httpx.AsyncClient,
    hostname: str,
    now: Optional[datetime] = None,
    store: Optional[Store] = None,
    max_depth: int = DEFAULT_MAX_CHAIN_DEPTH,
    fetch_timeout: float = DEFAULT_AIA_TIMEOUT,
    check_cross_sign: bool = False,
) -> ChainAudit:
    """Build and validate the chain above one leaf certificate.

    `peer_chain_der` is `SSLResult`/`HandshakeResult`'s `peer_chain_der` —
    leaf first, exactly as the peer sent it, or `None` when the platform
    cannot observe it (Python < 3.13). Only the entries after the first are
    used as seed candidates here; the leaf itself always comes from
    `leaf_der`.
    """
    audit = ChainAudit(attempted=True)
    now = now or datetime.now(tz=timezone.utc)
    store = store or default_trust_store()

    try:
        leaf = x509.load_der_x509_certificate(leaf_der)
    except ValueError as exc:
        audit.verification_error = f"leaf certificate unparseable: {exc}"
        return audit

    peer_intermediates: List[x509.Certificate] = []
    if peer_chain_der and len(peer_chain_der) > 1:
        for der in peer_chain_der[1:]:
            try:
                peer_intermediates.append(x509.load_der_x509_certificate(der))
            except ValueError as exc:
                audit.fetch_errors.append(
                    f"peer-supplied chain certificate unparseable: {exc}"
                )

    audit.peer_chain_ordered, audit.peer_chain_order_detail = _check_chain_order(
        [leaf, *peer_intermediates]
    )

    verifier = (
        PolicyBuilder()
        .store(store)
        .time(now)
        .build_server_verifier(_verifier_subject(hostname))
    )

    built_chain, fetched_ders, fetch_errors = await _build_path(
        leaf,
        peer_intermediates,
        client=client,
        verifier=verifier,
        max_depth=max_depth,
        fetch_timeout=fetch_timeout,
    )
    audit.fetch_errors.extend(fetch_errors)

    if built_chain is None:
        audit.verified = False
        audit.complete = False
        audit.verification_error = (
            fetch_errors[0]
            if fetch_errors
            else (
                "no trust path found from the leaf to a certificate in the "
                "trust store"
            )
        )
        return audit

    audit.verified = True
    audit.complete = True
    audit.verification_error = None

    non_leaf = built_chain[1:]
    audit.depth = len(non_leaf)
    for cert in non_leaf:
        der = cert.public_bytes(Encoding.DER)
        source = ChainSource.AIA_FETCH if der in fetched_ders else ChainSource.PEER
        if source is ChainSource.AIA_FETCH:
            audit.missing_intermediate = True
        weak, reason = _audit_chain_signature(cert)
        info = parse_certificate(der, now=now)
        audit.links.append(
            ChainLink(
                certificate=info,
                source=source,
                raw=cert,
                signature_weak=weak,
                signature_weak_reason=reason,
            )
        )
        if weak:
            audit.weak_hash_in_chain = True
            audit.weak_hash_details.append(
                f"{info.subject_cn or info.subject_dn}: {reason}"
            )

    if check_cross_sign and peer_intermediates:
        await _check_cross_sign(
            audit,
            leaf,
            built_chain,
            client=client,
            verifier=verifier,
            max_depth=max_depth,
            fetch_timeout=fetch_timeout,
        )

    return audit


async def _check_cross_sign(
    audit: ChainAudit,
    leaf: x509.Certificate,
    peer_path_chain: List[x509.Certificate],
    *,
    client: httpx.AsyncClient,
    verifier: ServerVerifier,
    max_depth: int,
    fetch_timeout: float,
) -> None:
    """Best-effort item 15: does an AIA-only path (ignoring whatever the
    peer sent) validate to a *different* trust anchor than the peer's own
    chain did?

    This only ever detects a cross-sign that is visible from two paths this
    tool can independently build — it is not a CT-log search and will miss a
    cross-sign where the alternate root is not reachable via AIA from any
    certificate in either path. See the module docstring.
    """
    aia_only_chain, _, _ = await _build_path(
        leaf,
        [],
        client=client,
        verifier=verifier,
        max_depth=max_depth,
        fetch_timeout=fetch_timeout,
    )
    if aia_only_chain is None:
        audit.cross_signed = None
        return

    peer_root = peer_path_chain[-1]
    aia_root = aia_only_chain[-1]
    # DER equality rather than a fingerprint: the same certificate always
    # serialises identically, and this sidesteps `signature_hash_algorithm`
    # raising on Ed25519/Ed448 roots (see `certificate.audit_signature`).
    if peer_root.public_bytes(Encoding.DER) == aia_root.public_bytes(Encoding.DER):
        audit.cross_signed = False
        return

    audit.cross_signed = True
    audit.cross_sign_detail = (
        f"peer-supplied path trusts {peer_root.subject.rfc4514_string()!r}; "
        f"an independently AIA-fetched path trusts "
        f"{aia_root.subject.rfc4514_string()!r} instead"
    )


__all__ = [
    "DEFAULT_MAX_CHAIN_DEPTH",
    "DEFAULT_MAX_FETCH_BYTES",
    "DEFAULT_AIA_TIMEOUT",
    "ChainSource",
    "ChainLink",
    "ChainAudit",
    "default_trust_store",
    "fetch_issuer_certificate",
    "build_chain_audit",
]
