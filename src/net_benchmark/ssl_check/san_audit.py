"""Multi-SAN certificate audit against active subdomains (0.6.2 item 27).

A certificate covering many SAN entries (shared hosting, CDNs, and internal
multi-service certs commonly list a dozen to a hundred+ hostnames) doesn't
say anything about whether each of those hostnames is actually live. This
module checks, for each DNS-type SAN entry a certificate lists: does it
resolve at all, and if so, does connecting to it on the same port serve
this *same* certificate?

Two distinct findings this surfaces
----------------------------------------
- **Coverage waste**: a SAN entry that doesn't resolve, or resolves but
  doesn't accept a TLS connection at all — the certificate is larger (and
  its blast radius on key compromise wider) than its actual live coverage.
- **SAN inconsistency**: a SAN entry that *is* live and serves TLS, but
  with a *different* certificate than the one that lists it — worth
  knowing about specifically because it's a real misconfiguration
  signature (a decommissioned service still named in a shared cert, DNS
  pointed somewhere unexpected, or a virtual-hosting setup where this
  hostname was never actually meant to be covered).

Scope: literal DNS names only
----------------------------------
Wildcard SAN entries (`*.example.com`) aren't checked — there's no single
concrete hostname a wildcard names, and enumerating candidate subdomains to
guess at would be a fundamentally different (and much noisier, more
false-positive-prone) kind of check than this module does for every other
entry. IP-address and other non-DNS SAN types (already parsed separately
into `san_ip` etc. by `certificate.py`) aren't in scope either, for the
same reason a "subdomain" framing doesn't apply to them.

Cost control
--------------
A single certificate can list 100+ SAN entries. `max_entries` bounds how
many get probed (the rest are recorded, not silently dropped — see
`SanAuditResult.skipped_entries`), and probing runs at a bounded
concurrency, not one-at-a-time or fully unbounded.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from net_benchmark.ssl_check.handshake import (
    HandshakeStatus,
    ProbeConfig,
    StartTLSProtocol,
    probe_tls,
)

if TYPE_CHECKING:
    from net_benchmark.ssl_check.certificate import CertificateInfo

DEFAULT_MAX_ENTRIES = 25
DEFAULT_CONCURRENCY = 10
DEFAULT_TIMEOUT = 5.0


@dataclass
class SanEntryStatus:
    hostname: str
    dns_resolves: Optional[bool] = None
    resolved_ip: Optional[str] = None
    tls_reachable: Optional[bool] = None
    serves_same_certificate: Optional[bool] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hostname": self.hostname,
            "dns_resolves": self.dns_resolves,
            "resolved_ip": self.resolved_ip,
            "tls_reachable": self.tls_reachable,
            "serves_same_certificate": self.serves_same_certificate,
            "error": self.error,
        }


@dataclass
class SanAuditResult:
    attempted: bool = False
    entries: List[SanEntryStatus] = field(default_factory=list)
    # SAN entries not probed at all: wildcards, non-DNS types, and any
    # overflow past max_entries — named explicitly, not silently dropped.
    skipped_entries: List[str] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def inactive_sans(self) -> List[str]:
        """DNS resolves but no TLS reached, or DNS doesn't resolve at
        all — the "coverage waste" finding.
        """
        return [
            e.hostname
            for e in self.entries
            if e.dns_resolves is False
            or (e.dns_resolves is True and e.tls_reachable is False)
        ]

    @property
    def inconsistent_sans(self) -> List[str]:
        """Live, reachable, but serving a different certificate — the
        "SAN inconsistency" finding.
        """
        return [e.hostname for e in self.entries if e.serves_same_certificate is False]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "attempted": self.attempted,
            "entries": [e.to_dict() for e in self.entries],
            "skipped_entries": list(self.skipped_entries),
            "inactive_sans": self.inactive_sans,
            "inconsistent_sans": self.inconsistent_sans,
            "error": self.error,
        }


async def _check_one_san(
    hostname: str,
    port: int,
    reference_fingerprint: str,
    *,
    starttls: Optional[StartTLSProtocol],
    timeout: float,
) -> SanEntryStatus:
    import socket

    status = SanEntryStatus(hostname=hostname)
    loop = asyncio.get_event_loop()

    try:
        infos = await loop.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
        status.dns_resolves = True
        status.resolved_ip = str(infos[0][4][0]) if infos else None
    except OSError as exc:
        status.dns_resolves = False
        status.error = f"DNS resolution failed: {exc}"
        return status

    config = ProbeConfig(
        server_hostname=hostname, connect_timeout=timeout, handshake_timeout=timeout
    )
    handshake = await probe_tls(hostname, port, starttls=starttls, config=config)
    if handshake.status is not HandshakeStatus.OK or handshake.leaf_der is None:
        status.tls_reachable = False
        status.error = handshake.error_message or handshake.status.value
        return status

    status.tls_reachable = True
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes

    observed_fingerprint = (
        x509.load_der_x509_certificate(handshake.leaf_der)
        .fingerprint(hashes.SHA256())
        .hex()
    )
    status.serves_same_certificate = observed_fingerprint == reference_fingerprint
    return status


async def audit_san_entries(
    certificate: "CertificateInfo",
    *,
    port: int = 443,
    starttls: Optional[StartTLSProtocol] = None,
    max_entries: int = DEFAULT_MAX_ENTRIES,
    concurrency: int = DEFAULT_CONCURRENCY,
    timeout: float = DEFAULT_TIMEOUT,
) -> SanAuditResult:
    """Audit every literal DNS SAN entry on `certificate` (see the module
    docstring for what's excluded and why). `certificate.fingerprints.
    cert_sha256` is the reference each live SAN entry's own certificate is
    compared against.
    """
    result = SanAuditResult(attempted=True)

    if certificate.fingerprints is None:
        result.error = "certificate fingerprints were not computed"
        return result
    reference_fingerprint = certificate.fingerprints.cert_sha256

    candidates = [h for h in certificate.san_dns if not h.startswith("*.")]
    wildcards = [h for h in certificate.san_dns if h.startswith("*.")]
    result.skipped_entries.extend(wildcards)

    to_probe = candidates[:max_entries]
    result.skipped_entries.extend(candidates[max_entries:])

    if not to_probe:
        return result

    semaphore = asyncio.Semaphore(concurrency)

    async def _bounded(hostname: str) -> SanEntryStatus:
        async with semaphore:
            return await _check_one_san(
                hostname,
                port,
                reference_fingerprint,
                starttls=starttls,
                timeout=timeout,
            )

    result.entries = await asyncio.gather(*(_bounded(h) for h in to_probe))
    return result


__all__ = [
    "DEFAULT_MAX_ENTRIES",
    "DEFAULT_CONCURRENCY",
    "DEFAULT_TIMEOUT",
    "SanEntryStatus",
    "SanAuditResult",
    "audit_san_entries",
]
