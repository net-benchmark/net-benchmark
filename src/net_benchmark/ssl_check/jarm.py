"""JARM server fingerprinting (0.6.2 item 24), via `pyjarm`.

Scope: JARM only, not JA4S
------------------------------
Item 24 names both JARM and JA4S. JARM ships here; JA4S does not, for two
separate, verified reasons rather than one vague "not available":

- Every maintained Python JA4S implementation found (`ja4plus`) is built
  around offline/live *packet capture* (scapy, pcap files) — a
  fundamentally different operating model than this project's own
  connect-and-handshake one. Getting JA4S here would mean either capturing
  raw packets during this project's own handshakes (a real architectural
  change, and one that commonly needs elevated privileges) or
  reimplementing JA4S's own hashing scheme independently against the
  ServerHello data already parsed elsewhere in this module.
- `ja4plus`'s JA4S support (along with every JA4+ method besides JA4
  itself) ships under FoxIO's own "FoxIO License 1.1" — not a standard MIT/
  BSD/Apache term, and its own stated scope ("academic, internal business,
  and security research use") is unclear for a project this permissive
  elsewhere, distributed for others to build on, including inside a
  commercial SaaS layer. That is a licensing call worth naming rather than
  making silently by installing it anyway.

Why `pyjarm`, verified rather than assumed
------------------------------------------------
`pyjarm` (PyPI, ISC licence, PaloAltoNetworks-maintained, zero runtime
dependencies) was checked directly before adopting it, the same way
`pkilint` and `CryptoLyzer` were: installed and run against a real live
target, producing a real, correctly-formatted 62-character JARM hash.
Its most recent release (0.0.5, Feb 2021) is old enough to be worth
naming plainly — the same "low recent activity" category of risk that
turned out to be real for `oscrypto` earlier in this project — but JARM
itself is a frozen 2020 specification with no protocol evolution to keep
pace with, unlike a live TLS stack implementation, so a library not
receiving frequent updates is a materially different risk here than it
was for `oscrypto`.

Concurrency
-------------
`pyjarm` ships native asyncio support (`Scanner.scan_async`) — no executor
bridging needed here, unlike the CryptoLyzer-backed probes in
`deep_introspection.py`. One known, benign quirk observed directly and
worth recording rather than chasing: `pyjarm` races `concurrency=2`
parallel connection attempts internally and does not always clean up the
losing attempt, which can surface as a harmless
`RuntimeWarning: coroutine 'Connection.jarm_connect' was never awaited`
during garbage collection. Confirmed this doesn't affect result
correctness (fingerprints are deterministic and repeatable across runs)
before deciding not to work around third-party internals for a cosmetic
warning.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Optional

DEFAULT_JARM_TIMEOUT = 20.0


class JarmAvailability(str, Enum):
    AVAILABLE = "available"
    NOT_INSTALLED = "not_installed"


def jarm_availability() -> JarmAvailability:
    try:
        import jarm  # noqa: F401
    except ImportError:
        return JarmAvailability.NOT_INSTALLED
    return JarmAvailability.AVAILABLE


@dataclass
class JarmResult:
    attempted: bool = False
    availability: JarmAvailability = JarmAvailability.NOT_INSTALLED
    fingerprint: Optional[str] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "attempted": self.attempted,
            "availability": self.availability.value,
            "fingerprint": self.fingerprint,
            "error": self.error,
        }


async def probe_jarm(
    host: str, port: int, *, timeout: float = DEFAULT_JARM_TIMEOUT
) -> JarmResult:
    """Compute a JARM fingerprint for `host:port`. A JARM of all zeros
    (`"00000...0"`) is itself a meaningful, valid result — it means the
    target did not respond to any of the ten probe ClientHellos as a TLS
    server would — so it is returned as-is, not treated as a failure.
    """
    result = JarmResult(attempted=True)
    result.availability = jarm_availability()
    if result.availability is not JarmAvailability.AVAILABLE:
        result.error = (
            "pyjarm is not installed. JARM fingerprinting requires the "
            "[crypto] extra: pip install 'net-benchmark[crypto]'"
        )
        return result

    try:
        from jarm.scanner.scanner import Scanner

        fingerprint, _host, _port = await Scanner.scan_async(
            host, port, timeout=int(timeout)
        )
        result.fingerprint = fingerprint
    except Exception as exc:  # noqa: BLE001 — third-party scanner, arbitrary targets
        result.error = f"{type(exc).__name__}: {exc}"
    return result


__all__ = [
    "DEFAULT_JARM_TIMEOUT",
    "JarmAvailability",
    "JarmResult",
    "jarm_availability",
    "probe_jarm",
]
