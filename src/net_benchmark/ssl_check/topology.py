"""Certificate topology checks: virtual hosting and dual-stack consistency.

net-benchmark 0.6.1 items 16-17.

Item 16 — virtual host / multi-cert detection
------------------------------------------------
Purely descriptive, not a pass/fail check: for any IP address that was
scanned under more than one hostname in the same run, report how many
distinct certificates it served. A shared IP serving different certificates
per hostname is ordinary SNI-based virtual hosting (most CDNs work exactly
this way) — the finding is topology information, not a misconfiguration
verdict. This is a post-scan comparison across `SSLResult`s already
collected, not a live probe, so it lives here as a plain function over a
result list rather than an engine method.

Item 17 — IPv4 vs IPv6 certificate consistency
--------------------------------------------------
A live check: resolves a hostname's A and AAAA records explicitly (not left
to whichever `getaddrinfo()` returns first, which is what the engine's
normal single-target resolution does — see `handshake.py`'s own
`_resolve_target`) and, when the host is genuinely dual-stack, probes each
address and compares certificate fingerprints. A real-world misconfiguration
this catches: an IPv6 endpoint quietly serving a stale or different
certificate than the IPv4 one for the same name.
"""

from __future__ import annotations

import asyncio
import socket
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Sequence

from net_benchmark.ssl_check.handshake import (
    HandshakeStatus,
    ProbeConfig,
    StartTLSProtocol,
    probe_tls,
)

if TYPE_CHECKING:
    from net_benchmark.ssl_check.core import SSLResult


# ---------------------------------------------------------------------------
# Item 16 — virtual hosting / multi-cert detection
# ---------------------------------------------------------------------------


@dataclass
class MultiCertGroup:
    """One IP address scanned under more than one hostname, and what it
    served each of them.
    """

    ip: str
    fingerprint_by_host: Dict[str, Optional[str]] = field(default_factory=dict)

    @property
    def hosts(self) -> List[str]:
        return sorted(self.fingerprint_by_host)

    @property
    def distinct_certificate_count(self) -> int:
        return len({fp for fp in self.fingerprint_by_host.values() if fp is not None})

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip": self.ip,
            "hosts": self.hosts,
            "distinct_certificate_count": self.distinct_certificate_count,
            "fingerprint_by_host": dict(self.fingerprint_by_host),
        }


def detect_virtual_hosting(results: Sequence["SSLResult"]) -> List[MultiCertGroup]:
    """Group `results` by resolved IP; return one `MultiCertGroup` per IP
    that was scanned under 2+ distinct hostnames. An IP seen under only one
    hostname has nothing to compare and is omitted, not reported with a
    trivial "1 hostname, 1 cert" entry.
    """
    by_ip: Dict[str, Dict[str, Optional[str]]] = {}
    for result in results:
        if result.resolved_ip is None:
            continue
        fingerprint = (
            result.certificate.fingerprints.cert_sha256
            if result.certificate is not None
            and result.certificate.fingerprints is not None
            else None
        )
        by_ip.setdefault(result.resolved_ip, {})[result.host] = fingerprint

    return [
        MultiCertGroup(ip=ip, fingerprint_by_host=host_fps)
        for ip, host_fps in by_ip.items()
        if len(host_fps) > 1
    ]


# ---------------------------------------------------------------------------
# Item 17 — IPv4 vs IPv6 certificate consistency
# ---------------------------------------------------------------------------


@dataclass
class DualStackAudit:
    attempted: bool = False
    ipv4_address: Optional[str] = None
    ipv6_address: Optional[str] = None
    ipv4_fingerprint: Optional[str] = None
    ipv6_fingerprint: Optional[str] = None
    ipv4_error: Optional[str] = None
    ipv6_error: Optional[str] = None
    # None: not dual-stack (one family didn't resolve) or one/both probes
    # failed — not the same as False, which is a confirmed mismatch between
    # two certificates this function actually obtained.
    consistent: Optional[bool] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "attempted": self.attempted,
            "ipv4_address": self.ipv4_address,
            "ipv6_address": self.ipv6_address,
            "ipv4_fingerprint": self.ipv4_fingerprint,
            "ipv6_fingerprint": self.ipv6_fingerprint,
            "ipv4_error": self.ipv4_error,
            "ipv6_error": self.ipv6_error,
            "consistent": self.consistent,
        }


async def check_dual_stack_consistency(
    host: str,
    port: int,
    *,
    starttls: Optional[StartTLSProtocol] = None,
    base_config: Optional[ProbeConfig] = None,
) -> DualStackAudit:
    """Resolve `host`'s A and AAAA records explicitly; when both exist,
    probe each address and compare the certificate each one serves.

    `base_config.pinned_ip`, if set, is overridden per address here — this
    check is specifically about comparing the two families, so it needs to
    control the address itself regardless of any `--resolve` pin the rest
    of the scan is using for this target.
    """
    audit = DualStackAudit(attempted=True)
    loop = asyncio.get_event_loop()

    try:
        ipv4_infos = await loop.getaddrinfo(
            host, port, family=socket.AF_INET, type=socket.SOCK_STREAM
        )
        audit.ipv4_address = str(ipv4_infos[0][4][0]) if ipv4_infos else None
    except OSError as exc:
        audit.ipv4_error = f"IPv4 resolution failed: {exc}"

    try:
        ipv6_infos = await loop.getaddrinfo(
            host, port, family=socket.AF_INET6, type=socket.SOCK_STREAM
        )
        audit.ipv6_address = str(ipv6_infos[0][4][0]) if ipv6_infos else None
    except OSError as exc:
        audit.ipv6_error = f"IPv6 resolution failed: {exc}"

    if audit.ipv4_address is None or audit.ipv6_address is None:
        # Not dual-stack (or one family's DNS lookup failed) — nothing to
        # compare. Whichever error was captured above stays as the reason.
        return audit

    base_config = base_config or ProbeConfig()

    config_v4 = replace(base_config, pinned_ip=audit.ipv4_address)
    config_v6 = replace(base_config, pinned_ip=audit.ipv6_address)

    handshake_v4 = await probe_tls(host, port, starttls=starttls, config=config_v4)
    handshake_v6 = await probe_tls(host, port, starttls=starttls, config=config_v6)

    if handshake_v4.status is HandshakeStatus.OK and handshake_v4.leaf_der is not None:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes

        audit.ipv4_fingerprint = (
            x509.load_der_x509_certificate(handshake_v4.leaf_der)
            .fingerprint(hashes.SHA256())
            .hex()
        )
    else:
        audit.ipv4_error = handshake_v4.error_message or handshake_v4.status.value

    if handshake_v6.status is HandshakeStatus.OK and handshake_v6.leaf_der is not None:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes

        audit.ipv6_fingerprint = (
            x509.load_der_x509_certificate(handshake_v6.leaf_der)
            .fingerprint(hashes.SHA256())
            .hex()
        )
    else:
        audit.ipv6_error = handshake_v6.error_message or handshake_v6.status.value

    if audit.ipv4_fingerprint is not None and audit.ipv6_fingerprint is not None:
        audit.consistent = audit.ipv4_fingerprint == audit.ipv6_fingerprint

    return audit


__all__ = [
    "MultiCertGroup",
    "detect_virtual_hosting",
    "DualStackAudit",
    "check_dual_stack_consistency",
]
