"""Full multi-store trust validation (0.6.2 item 22): does this chain
validate under Apple's, Google's (Chrome), and Microsoft's own root
programs, not just Mozilla's (already covered by `chain.py`'s own default
store) and the local system's?

Why this matters: root programs disagree
----------------------------------------------
Each vendor runs its own CA inclusion process, on its own timeline. A
certificate can validate under Mozilla's store and fail under Microsoft's
(or the reverse) — a real, user-visible difference depending on which
browser or platform actually connects. `MultiStoreAudit.consistent` is
this check's actual point: whether every store agrees, not any single
store's verdict.

Data source — verified directly, not assumed
--------------------------------------------------
Apple and Google do not themselves publish a clean, directly-consumable
PEM bundle of their root program (Apple's lives inside a low-level OSS
distribution repo; Google's is embedded in Chromium's own source as a
`.certs` file). This module fetches pre-built PEM bundles from
`tls-inspector/rootca` (`api.tlsinspector.com`) instead — a third-party
aggregator, MPL-2.0 licensed for its own code, that itself sources from
each vendor's official upstream (confirmed by reading its own
documentation): Apple's OSS distribution repo directly, Chromium's own
source tree directly, and Microsoft's Windows-Update-downloaded Subject
Trust Lists directly. This is the same shape of trust `certifi` itself
already asks for regarding Mozilla's store — a well-established pattern,
not a novel risk — but it is still a third party standing between this
tool and each vendor's own publication, and that's named here rather than
presented as equivalent to a first-party source. Microsoft's bundle is
fetched from `mscerts` instead — an actual, actively-maintained PyPI
package (itself modelled directly on `certifi`) — since a real package
exists for that one vendor and using it avoids the third-party-aggregator
question entirely for at least one of the three.

The aggregator API requires an identifiable User-Agent header (its own
documented policy rejects generic `python-requests`/`curl` user agents) and
is explicitly published "as-is", with no availability guarantee — failures
are therefore expected occasionally and handled per-vendor, never treated
as blocking the rest of the scan.

Efficiency note
------------------
This does not repeat AIA fetching per vendor store. The chain already
built and validated by `chain.py`'s own primary (Mozilla + system)
verification is reused as the candidate set for every additional store —
if that same set of certificates also chains to a trust anchor in a given
vendor's store, it validates there too; if not, that's the finding. A
vendor store containing some entirely different, not-yet-fetched
intermediate the peer never sent would be missed by this — an accepted,
documented scope limit, not a silent gap: catching that case would need a
full second AIA-fetching pass per vendor store, multiplying network cost
for a scenario this project has not observed in practice.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import httpx
from cryptography import x509
from cryptography.x509.verification import PolicyBuilder, Store, VerificationError

TLS_INSPECTOR_API = "https://api.tlsinspector.com"
# Required by the aggregator's own stated policy — it rejects requests
# using a default/generic user agent.
USER_AGENT = "net-benchmark-ssl-check (+https://github.com/net-benchmark/net-benchmark)"
DEFAULT_MAX_AGE = 3600.0 * 24 * 7  # root programs change rarely; weekly is generous
DEFAULT_TIMEOUT = 10.0

# Vendors fetched via the aggregator. Microsoft is handled separately, via
# the `mscerts` package — see the module docstring.
_AGGREGATOR_VENDORS = ("apple", "google")


def default_multi_store_cache_dir() -> Path:
    import os

    base = os.environ.get("XDG_CACHE_HOME")
    root = Path(base) if base else Path.home() / ".cache"
    return root / "net-benchmark" / "trust-stores"


async def fetch_vendor_bundle(
    client: httpx.AsyncClient,
    vendor: str,
    *,
    cache_dir: Optional[Path] = None,
    max_age: float = DEFAULT_MAX_AGE,
    timeout: float = DEFAULT_TIMEOUT,
) -> Tuple[Optional[bytes], Optional[str]]:
    """Fetch one vendor's PEM bundle (`"apple"` or `"google"`) from the
    aggregator, or a disk cache younger than `max_age`. Returns
    (pem_bytes_or_None, error_or_None).
    """
    cache_dir = cache_dir if cache_dir is not None else default_multi_store_cache_dir()
    cache_path = cache_dir / f"{vendor}_ca_bundle.pem"

    import time

    try:
        stat = cache_path.stat()
        if time.time() - stat.st_mtime <= max_age:
            return cache_path.read_bytes(), None
    except OSError:
        pass

    url = f"{TLS_INSPECTOR_API}/rootca/asset/latest/{vendor}_ca_bundle.pem"
    try:
        response = await client.get(
            url,
            timeout=timeout,
            follow_redirects=True,
            headers={"User-Agent": USER_AGENT},
        )
        response.raise_for_status()
        body = response.content
    except httpx.HTTPError as exc:
        return None, f"{url}: {type(exc).__name__}: {exc}"

    try:
        cache_dir.mkdir(parents=True, exist_ok=True)
        cache_path.write_bytes(body)
    except OSError:
        pass

    return body, None


def _microsoft_bundle_path() -> Optional[Path]:
    try:
        import mscerts
    except ImportError:
        return None
    return Path(mscerts.where())


def _build_store(pem_bytes: bytes) -> Store:
    certs = x509.load_pem_x509_certificates(pem_bytes)
    return Store(certs)


@dataclass
class StoreVerificationResult:
    store_name: str
    verified: Optional[bool] = None
    verification_error: Optional[str] = None
    unavailable_reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "store_name": self.store_name,
            "verified": self.verified,
            "verification_error": self.verification_error,
            "unavailable_reason": self.unavailable_reason,
        }


@dataclass
class MultiStoreAudit:
    attempted: bool = False
    results: List[StoreVerificationResult] = field(default_factory=list)

    @property
    def consistent(self) -> Optional[bool]:
        """True if every store that actually produced a verdict agrees;
        False if they disagree — that disagreement is this check's whole
        point. None if fewer than two stores produced a verdict at all
        (nothing to compare).
        """
        verdicts = [r.verified for r in self.results if r.verified is not None]
        if len(verdicts) < 2:
            return None
        return len(set(verdicts)) == 1

    def to_dict(self) -> Dict[str, Any]:
        return {
            "attempted": self.attempted,
            "results": [r.to_dict() for r in self.results],
            "consistent": self.consistent,
        }


async def check_multi_store_trust(
    leaf_der: bytes,
    peer_chain_der: Optional[Sequence[bytes]],
    *,
    client: httpx.AsyncClient,
    hostname: str,
    now: Optional[datetime] = None,
    cache_dir: Optional[Path] = None,
) -> MultiStoreAudit:
    """Validate one certificate chain against Apple's, Google's, and
    Microsoft's own root stores. `leaf_der` and `peer_chain_der` are the
    same values `chain.py`'s own primary verification already used — see
    the module docstring's efficiency note on why this doesn't repeat AIA
    fetching per vendor.
    """
    from net_benchmark.ssl_check.chain import _verifier_subject

    audit = MultiStoreAudit(attempted=True)
    now = now or datetime.now(tz=timezone.utc)

    try:
        leaf = x509.load_der_x509_certificate(leaf_der)
    except ValueError as exc:
        audit.results.append(
            StoreVerificationResult(
                store_name="all",
                unavailable_reason=f"leaf certificate unparseable: {exc}",
            )
        )
        return audit

    candidates: List[x509.Certificate] = []
    if peer_chain_der and len(peer_chain_der) > 1:
        for der in peer_chain_der[1:]:
            try:
                candidates.append(x509.load_der_x509_certificate(der))
            except ValueError:
                continue

    for vendor in _AGGREGATOR_VENDORS:
        pem_bytes, fetch_error = await fetch_vendor_bundle(
            client, vendor, cache_dir=cache_dir
        )
        if pem_bytes is None:
            audit.results.append(
                StoreVerificationResult(
                    store_name=vendor, unavailable_reason=fetch_error
                )
            )
            continue
        result = StoreVerificationResult(store_name=vendor)
        try:
            store = _build_store(pem_bytes)
            verifier = (
                PolicyBuilder()
                .store(store)
                .time(now)
                .build_server_verifier(_verifier_subject(hostname))
            )
            verifier.verify(leaf, candidates)
            result.verified = True
        except VerificationError as exc:
            result.verified = False
            result.verification_error = str(exc)
        except ValueError as exc:
            result.unavailable_reason = f"vendor bundle unusable: {exc}"
        audit.results.append(result)

    ms_path = _microsoft_bundle_path()
    if ms_path is None:
        audit.results.append(
            StoreVerificationResult(
                store_name="microsoft",
                unavailable_reason=(
                    "mscerts is not installed. Microsoft root-store validation "
                    "requires the [crypto] extra: pip install 'net-benchmark[crypto]'"
                ),
            )
        )
    else:
        result = StoreVerificationResult(store_name="microsoft")
        try:
            store = _build_store(ms_path.read_bytes())
            verifier = (
                PolicyBuilder()
                .store(store)
                .time(now)
                .build_server_verifier(_verifier_subject(hostname))
            )
            verifier.verify(leaf, candidates)
            result.verified = True
        except VerificationError as exc:
            result.verified = False
            result.verification_error = str(exc)
        except (OSError, ValueError) as exc:
            result.unavailable_reason = f"microsoft bundle unusable: {exc}"
        audit.results.append(result)

    return audit


__all__ = [
    "TLS_INSPECTOR_API",
    "USER_AGENT",
    "DEFAULT_MAX_AGE",
    "DEFAULT_TIMEOUT",
    "StoreVerificationResult",
    "MultiStoreAudit",
    "default_multi_store_cache_dir",
    "fetch_vendor_bundle",
    "check_multi_store_trust",
]
