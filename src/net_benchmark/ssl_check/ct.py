"""Certificate Transparency log identification and trust status.

net-benchmark 0.6.1 -- ROADMAP.md items 10, 12: CT log query (net-benchmark's
own implementation, not a hard dependency on crt.sh) and CT log
identification/trust status (resolve each embedded SCT's log ID to a named
log and report whether that log is currently trusted).

Scope actually built here
---------------------------
"CT log query for issuance history" (item 10's own phrase) can't mean
"search a log by domain name" -- RFC 6962's actual API (get-sth, get-entries,
get-proof-by-hash) has no domain-search operation at all. That capability
(what crt.sh actually provides) requires either downloading and indexing
entire logs or depending on a third-party search service, neither of which
fits a benchmarking CLI's scope, and neither is what item 12 actually asks
for. What IS directly buildable from a log registry, and is what item 12
describes, is: given the SCTs a scanned certificate already carries
(certificate.py's `extract_scts`, item 11), resolve each one's log_id
against the authoritative log registry and report whether that log is
currently trusted. That is what this module does. Bulk log mirroring or
domain search is explicitly out of scope.

Log registry
-------------
Chrome's published CT log list
(https://www.gstatic.com/ct/log_list/v3/all_logs_list.json) -- the de facto
standard source every CT-aware client and library (Chrome itself, Google's
own certificate-transparency-go, Let's Encrypt's boulder) uses for exactly
this lookup. Schema fetched and verified against the published
log_list_schema.json before writing this, not guessed. No explicit
redistribution licence is published for the data itself (unlike, say,
MaxMind's GeoLite2 EULA or IP2Location's CC-BY-SA share-alike, both of which
the dependency policy explicitly excludes on that basis) -- worth a
maintainer's own confirmation per dependency policy item 6 ("datasets...
evaluated on their terms before use"), flagged here rather than silently
assumed clear.

Trust semantics
-----------------
Per the log list schema's own design (googlechrome.github.io's log-list
discussion): USABLE, QUALIFIED and READONLY logs are relied upon; PENDING
and REJECTED are not. RETIRED is time-bound in principle -- an SCT issued
before a log went read-only/retired can still be valid -- but `LogState.trusted`
here doesn't have the certificate's own issuance time to check that against,
so RETIRED is conservatively reported as untrusted. A caller with the
certificate's `not_before` can special-case it.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import httpx

from net_benchmark.ssl_check.certificate import SignedCertificateTimestampInfo

DEFAULT_LOG_LIST_URL = "https://www.gstatic.com/ct/log_list/v3/all_logs_list.json"
# Chrome updates its published list daily; matching that cadence rather than
# re-fetching every scan run.
DEFAULT_LOG_LIST_MAX_AGE = 3600.0 * 24
DEFAULT_LOG_LIST_TIMEOUT = 10.0

_STATE_KEYS = ("usable", "qualified", "readonly", "pending", "retired", "rejected")


def default_log_list_cache_path() -> Path:
    base = os.environ.get("XDG_CACHE_HOME")
    root = Path(base) if base else Path.home() / ".cache"
    return root / "net-benchmark" / "ct" / "log_list.json"


class LogState(str, Enum):
    PENDING = "pending"
    QUALIFIED = "qualified"
    USABLE = "usable"
    READONLY = "readonly"
    RETIRED = "retired"
    REJECTED = "rejected"
    # The log_id wasn't found in the registry at all -- distinct from any of
    # the schema's own states, since this could mean "genuinely unknown log"
    # or "the registry fetch failed/was stale", not a state the log itself
    # has ever reported.
    UNKNOWN = "unknown"

    @property
    def trusted(self) -> bool:
        return self in (LogState.USABLE, LogState.QUALIFIED, LogState.READONLY)


@dataclass
class CTLog:
    log_id_hex: str
    description: str
    operator: str
    state: LogState
    state_timestamp: Optional[datetime] = None
    url: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "log_id_hex": self.log_id_hex,
            "description": self.description,
            "operator": self.operator,
            "state": self.state.value,
            "state_timestamp": (
                self.state_timestamp.isoformat() if self.state_timestamp else None
            ),
            "url": self.url,
        }


@dataclass
class CTLogRegistry:
    """A parsed log list, keyed by log_id for `SignedCertificateTimestampInfo`
    lookup. Construct via `parse_log_list` / `fetch_log_registry`, not
    directly -- `_by_hex` is populated by the parser.
    """

    source_url: Optional[str] = None
    list_version: Optional[str] = None
    fetched_at: Optional[datetime] = None
    from_cache: bool = False
    _by_hex: Dict[str, CTLog] = field(default_factory=dict)

    def get(self, log_id_hex: str) -> Optional[CTLog]:
        return self._by_hex.get(log_id_hex.lower())

    @property
    def logs(self) -> List[CTLog]:
        return list(self._by_hex.values())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_url": self.source_url,
            "list_version": self.list_version,
            "fetched_at": self.fetched_at.isoformat() if self.fetched_at else None,
            "from_cache": self.from_cache,
            "log_count": len(self._by_hex),
        }


def parse_log_list(
    data: Dict[str, Any], *, source_url: Optional[str] = None
) -> CTLogRegistry:
    """Parse one `log_list.json`/`all_logs_list.json` document (schema
    verified against `log_list_schema.json` before writing this parser).
    """
    by_hex: Dict[str, CTLog] = {}
    for operator in data.get("operators", []):
        operator_name = operator.get("name", "unknown")
        entries = list(operator.get("logs", [])) + list(operator.get("tiled_logs", []))
        for log_entry in entries:
            log_id_b64 = log_entry.get("log_id")
            if not log_id_b64:
                continue
            try:
                log_id_hex = base64.b64decode(log_id_b64).hex()
            except (ValueError, binascii.Error):
                continue

            state_obj = log_entry.get("state") or {}
            state = LogState.UNKNOWN
            state_timestamp: Optional[datetime] = None
            for state_key in _STATE_KEYS:
                if state_key in state_obj:
                    state = LogState(state_key)
                    ts_str = state_obj[state_key].get("timestamp")
                    if ts_str:
                        try:
                            state_timestamp = datetime.fromisoformat(
                                ts_str.replace("Z", "+00:00")
                            )
                        except ValueError:
                            state_timestamp = None
                    break

            by_hex[log_id_hex] = CTLog(
                log_id_hex=log_id_hex,
                description=log_entry.get("description", ""),
                operator=operator_name,
                state=state,
                state_timestamp=state_timestamp,
                url=log_entry.get("url") or log_entry.get("submission_url"),
            )

    registry = CTLogRegistry(
        source_url=source_url,
        list_version=data.get("version"),
        fetched_at=datetime.now(tz=timezone.utc),
    )
    registry._by_hex = by_hex
    return registry


async def fetch_log_registry(
    client: httpx.AsyncClient,
    *,
    url: str = DEFAULT_LOG_LIST_URL,
    cache_path: Optional[Path] = None,
    max_age: float = DEFAULT_LOG_LIST_MAX_AGE,
    timeout: float = DEFAULT_LOG_LIST_TIMEOUT,
) -> Tuple[Optional[CTLogRegistry], Optional[str]]:
    """Fetch the CT log registry, or use a cached copy younger than `max_age`.

    Returns (registry_or_None, error_or_None). A cache write failure is
    never a fetch failure -- best-effort, same as `CRLCache` in
    `revocation.py`.
    """
    cache_path = cache_path if cache_path is not None else default_log_list_cache_path()

    try:
        stat = cache_path.stat()
        if time.time() - stat.st_mtime <= max_age:
            data = json.loads(cache_path.read_bytes())
            registry = parse_log_list(data, source_url=url)
            registry.from_cache = True
            return registry, None
    except (OSError, ValueError):
        pass  # no usable cache -- fall through to a fresh fetch

    try:
        response = await client.get(url, timeout=timeout, follow_redirects=True)
        response.raise_for_status()
        body = response.content
    except httpx.HTTPError as exc:
        return None, f"{url}: {type(exc).__name__}: {exc}"

    try:
        data = json.loads(body)
    except ValueError as exc:
        return None, f"{url}: response was not valid JSON: {exc}"

    try:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_bytes(body)
    except OSError:
        pass

    return parse_log_list(data, source_url=url), None


@dataclass
class SCTTrust:
    """One embedded SCT, resolved against the log registry."""

    sct: SignedCertificateTimestampInfo
    log: Optional[CTLog]
    # None when the registry itself wasn't available to check against --
    # distinct from a definite "log not found" (log is None but the registry
    # loaded fine, which is itself a `False` — an SCT from a log absent from
    # the registry entirely is not evidence of anything, same reasoning as an
    # explicitly REJECTED log).
    trusted: Optional[bool]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sct": self.sct.to_dict(),
            "log": self.log.to_dict() if self.log is not None else None,
            "trusted": self.trusted,
        }


def resolve_sct_trust(
    scts: Sequence[SignedCertificateTimestampInfo],
    registry: Optional[CTLogRegistry],
) -> List[SCTTrust]:
    results: List[SCTTrust] = []
    for sct in scts:
        if registry is None:
            results.append(SCTTrust(sct=sct, log=None, trusted=None))
            continue
        log = registry.get(sct.log_id_hex)
        trusted = log.state.trusted if log is not None else False
        results.append(SCTTrust(sct=sct, log=log, trusted=trusted))
    return results


@dataclass
class CTAudit:
    """Result of resolving one certificate's embedded SCTs against the log
    registry.
    """

    attempted: bool = False
    registry_error: Optional[str] = None
    sct_trust: List[SCTTrust] = field(default_factory=list)

    @property
    def all_trusted(self) -> Optional[bool]:
        """True iff every SCT resolved to a currently-trusted log. None when
        there was nothing to check (no SCTs, or the registry itself could
        not be fetched) -- not the same as False, which means a definite,
        checked finding.
        """
        if not self.sct_trust:
            return None
        return all(entry.trusted for entry in self.sct_trust)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "attempted": self.attempted,
            "registry_error": self.registry_error,
            "sct_trust": [entry.to_dict() for entry in self.sct_trust],
            "all_trusted": self.all_trusted,
        }


async def check_ct_logs(
    scts: Sequence[SignedCertificateTimestampInfo],
    *,
    client: httpx.AsyncClient,
    registry: Optional[CTLogRegistry] = None,
    cache_path: Optional[Path] = None,
    timeout: float = DEFAULT_LOG_LIST_TIMEOUT,
) -> CTAudit:
    """Entry point: resolve `scts` against the CT log registry.

    `registry` lets a caller share one fetched/cached registry across an
    entire scan (the registry is the same regardless of which certificate is
    being checked) -- when not given, this fetches its own copy.
    """
    audit = CTAudit(attempted=True)
    if not scts:
        return audit

    if registry is None:
        registry, error = await fetch_log_registry(
            client, cache_path=cache_path, timeout=timeout
        )
        if error is not None:
            audit.registry_error = error

    audit.sct_trust = resolve_sct_trust(scts, registry)
    return audit


__all__ = [
    "DEFAULT_LOG_LIST_URL",
    "DEFAULT_LOG_LIST_MAX_AGE",
    "DEFAULT_LOG_LIST_TIMEOUT",
    "LogState",
    "CTLog",
    "CTLogRegistry",
    "SCTTrust",
    "CTAudit",
    "parse_log_list",
    "fetch_log_registry",
    "resolve_sct_trust",
    "check_ct_logs",
]
