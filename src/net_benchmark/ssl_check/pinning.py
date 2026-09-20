"""SPKI pin set generation (0.6.2 item 25).

Generates a certificate-pinning pin set from an already-scanned
`SSLResult` — the leaf's SPKI SHA-256 pin plus backup pins from the rest of
the validated chain (intermediates and, optionally, the root). This is net-
benchmark's own formatting work over data `certificate.py`/`chain.py`
already computed (item 9's `Fingerprints.spki_sha256_b64` per certificate);
nothing here re-parses or re-hashes anything.

Why backup pins, and why more than one
-------------------------------------------
Pinning only the leaf's key breaks the moment that certificate renews with
a new key — which is routine, not a failure. The standard mitigation
(RFC 7469 §2.5, and every modern pinning library — TrustKit, OkHttp's
`CertificatePinner` — still follows this even though HPKP itself is dead)
is to also pin at least one certificate further up the chain that is
expected to remain stable across the leaf's own renewals.

HPKP is dead; the notation isn't
-------------------------------------
No browser has honoured the `Public-Key-Pins` HTTP header since 2018 —
`hpkp_header_value` here is never meant to be deployed as an actual
response header. It's included because `pin-sha256="..."` is still the
de facto notation the wider ecosystem (mobile pinning configs, ops
documentation, other tools) uses to communicate an SPKI pin set, and
producing it costs nothing once the pins themselves are computed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Dict, List, Optional

if TYPE_CHECKING:
    from net_benchmark.ssl_check.core import SSLResult


@dataclass
class Pin:
    label: str
    spki_sha256_b64: str
    subject_cn: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "label": self.label,
            "spki_sha256_b64": self.spki_sha256_b64,
            "subject_cn": self.subject_cn,
        }


@dataclass
class PinSetResult:
    attempted: bool = False
    pins: List[Pin] = field(default_factory=list)
    # Standard pin-sha256="..." notation, one entry per pin, in the same
    # order as `pins` — a convenience rendering, not a second data source.
    hpkp_header_value: Optional[str] = None
    # True when the chain wasn't available (no --verify-chain), so `pins`
    # contains only the leaf and has no real backup pin at all — a single-
    # pin set is fragile (see the module docstring) and the caller should
    # know that's what they got, not assume backups were considered and
    # found unnecessary.
    backup_pins_unavailable: bool = False
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "attempted": self.attempted,
            "pins": [p.to_dict() for p in self.pins],
            "hpkp_header_value": self.hpkp_header_value,
            "backup_pins_unavailable": self.backup_pins_unavailable,
            "error": self.error,
        }


def generate_pin_set(result: "SSLResult", *, include_root: bool = True) -> PinSetResult:
    """Build a pin set from `result`'s already-collected certificate and
    chain data. `include_root` controls whether the trust anchor itself
    gets a pin — often left out in practice, since a root's key is shared
    across every certificate that CA issues and pinning it provides much
    weaker protection than pinning an intermediate or the leaf, but some
    pinning policies still want it as a last-resort backup.
    """
    pin_set = PinSetResult(attempted=True)

    if result.certificate is None:
        pin_set.error = "no certificate observed — nothing to pin"
        return pin_set
    if result.certificate.fingerprints is None:
        pin_set.error = "certificate fingerprints were not computed"
        return pin_set

    pin_set.pins.append(
        Pin(
            label="leaf",
            spki_sha256_b64=result.certificate.fingerprints.spki_sha256_b64,
            subject_cn=result.certificate.subject_cn,
        )
    )

    if (
        result.chain_audit is not None
        and result.chain_audit.attempted
        and result.chain_audit.links
    ):
        links = (
            result.chain_audit.links if include_root else result.chain_audit.links[:-1]
        )
        for index, link in enumerate(links):
            if link.certificate.fingerprints is None:
                continue
            is_root = include_root and index == len(result.chain_audit.links) - 1
            label = "root" if is_root else f"intermediate-{index + 1}"
            pin_set.pins.append(
                Pin(
                    label=label,
                    spki_sha256_b64=link.certificate.fingerprints.spki_sha256_b64,
                    subject_cn=link.certificate.subject_cn,
                )
            )
    else:
        pin_set.backup_pins_unavailable = True

    pin_set.hpkp_header_value = "; ".join(
        f'pin-sha256="{p.spki_sha256_b64}"' for p in pin_set.pins
    )
    return pin_set


__all__ = ["Pin", "PinSetResult", "generate_pin_set"]
