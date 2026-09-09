"""Statistical analysis of SSL/TLS check results.

net-benchmark 0.6.0 — SSL items 38, 42, 43, 44, 50, 51, 54, 57.

Mirrors `dns_benchmark/analysis.py` and `http_bench/analysis.py`: a per-target
stats dataclass, a pandas-backed analyzer, and a metric namespace that
thresholds are evaluated against.

Reuses rather than reimplements
-------------------------------
`LatencyHistogram`, `Threshold`, `ThresholdResult`, `parse_threshold`,
`evaluate_thresholds` and `thresholds_passed` are imported from
`http_bench.analysis`. Foundation item 8 relocates them to a module-neutral
package; until then this module imports from their current home rather than
carrying a second copy. A second histogram would mean a second set of merge
semantics, and a second threshold parser would mean `p95_handshake_ms<500`
could mean different things in two commands.

`cert_expiry_days` is deliberately the same metric name HTTP already exposes,
so a threshold written for one command means the same thing in the other.

Which rows feed which aggregate
-------------------------------
The `measured` / `compliant` split from `core.py` is load-bearing here:

* **latency, protocol and certificate aggregates filter on `measured`** — the
  handshake completed, so there are real samples;
* **outcome aggregates filter on `compliant`** — policy passed.

An expired certificate on a server that handshakes perfectly is `measured` and
not `compliant`, and its handshake latency is a real measurement that belongs
in the percentiles. Filtering latency on `compliant` would make a badly
configured server look faster than a healthy one by dropping its samples, which
is the HTTP 0.5.2 failure ("0.0 ms latency with 100% HSTS coverage") in a new
costume.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional, Sequence, Tuple, cast

import numpy as np
import pandas as pd

# Foundation item 8 moves these to a module-neutral package; one import line.
from net_benchmark.http_bench.analysis import (
    LatencyHistogram,
    Threshold,
    ThresholdResult,
    evaluate_thresholds,
    parse_threshold,
    thresholds_passed,
)
from net_benchmark.ssl_check.certificate import (
    ExpiryAlert,
    HostnameMatch,
    LifetimeVerdict,
)
from net_benchmark.ssl_check.core import SSLResult
from net_benchmark.ssl_check.handshake import HandshakeStatus, TLSVersion

__all__ = [
    "HostStats",
    "SSLAnalyzer",
    "SSL_SAMPLE_DEPENDENT_METRICS",
    "Threshold",
    "ThresholdResult",
    "build_ssl_metric_namespace",
    "evaluate_thresholds",
    "expiry_timeline",
    "parse_threshold",
    "ssl_metric_names",
    "thresholds_passed",
]


# Metrics computed from handshake samples. Dropped from the namespace when a
# target produced none, so a threshold against them fails loudly instead of
# passing against a 0.0 that means "never measured". Same rule and same reason
# as SAMPLE_DEPENDENT_METRICS in http_bench.analysis.
SSL_SAMPLE_DEPENDENT_METRICS: FrozenSet[str] = frozenset(
    {
        "min_handshake_ms",
        "max_handshake_ms",
        "avg_handshake_ms",
        "median_handshake_ms",
        "p95_handshake_ms",
        "p99_handshake_ms",
        "jitter",
        "consistency_score",
        "avg_tcp_connect_ms",
        "avg_handshake_bytes",
    }
)


# ---------------------------------------------------------------------------
# Per-target statistics
# ---------------------------------------------------------------------------


@dataclass
class HostStats:
    """Statistics for a single host:port target.

    Field layout mirrors `ResolverStats` and `TargetStats`:

        target              <- resolver_name / target      (identity)
        port                <- (no DNS equivalent - SSL-specific)
        total_checks        <- total_queries / total_requests
        measured_checks     <- responded_requests
        successful_checks   <- successful_queries / successful_requests
        success_rate        <- success_rate
        min/max/avg/...     <- same latency stat field names and formulas,
                               measuring TLS handshake duration here
        tls13_rate          <- dnssec_validation_rate / http2_rate
                               (the protocol quality signal slot)

    Latency fields keep the `_latency` naming of the other two modules so a
    shared exporter and the SaaS grading layer read the same field off any
    module's stats. `*_handshake_ms` aliases exist in the metric namespace for
    thresholds, where the explicit name is clearer.
    """

    target: str
    port: int
    total_checks: int
    measured_checks: int
    successful_checks: int
    success_rate: float
    # handshake latency — identical field names and formulas as ResolverStats
    min_latency: float
    max_latency: float
    avg_latency: float
    median_latency: float
    std_latency: float
    p95_latency: float
    p99_latency: float
    jitter: float = 0.0
    consistency_score: float = 0.0

    # --- phase timing ---
    avg_dns_ms: float = 0.0
    avg_tcp_connect_ms: float = 0.0
    avg_starttls_ms: float = 0.0

    # --- protocol quality ---
    tls13_rate: float = 0.0
    deprecated_tls_rate: float = 0.0
    forward_secrecy_rate: float = 0.0
    resumption_rate: Optional[float] = None

    # --- certificate posture ---
    hostname_match_rate: float = 0.0
    weak_key_rate: float = 0.0
    weak_signature_rate: float = 0.0
    self_signed_rate: float = 0.0
    expired_rate: float = 0.0
    must_staple_rate: float = 0.0
    revocation_source_rate: float = 0.0
    lifetime_compliant_rate: float = 0.0
    lifetime_fails_next_renewal_rate: float = 0.0

    # --- expiry (items 42, 43) ---
    #
    # None, never 0, when no certificate was observed. A 0 here would read as
    # "expires today" and fire every expiry alert in the tool for a host that
    # simply did not answer. Same rule as NULL-means-predates-this-version in
    # the migrations: the absence of a measurement must not be encoded as a
    # value that is itself a valid measurement.
    cert_expiry_days_min: Optional[int] = None
    cert_expiry_days_avg: Optional[float] = None
    certificates_observed: int = 0

    # --- bytes (item 54) ---
    avg_handshake_bytes: float = 0.0
    # None when no chain was observable on this interpreter. Distinct from 0,
    # which would claim the server sent no certificate bytes.
    avg_chain_bytes: Optional[float] = None
    chains_observed: int = 0

    # --- distribution ---
    latency_histogram: Optional[LatencyHistogram] = None
    latency_overflow_count: int = 0
    # Set when every measured check refused percentiles for too few samples
    # (item 57). The percentile fields are 0.0 in that case and must not be
    # read as measurements.
    percentiles_refused: bool = False

    # --- expiry alert tiers (item 42) ---
    # Counts by level. UNKNOWN rows are targets where no certificate was seen;
    # they are NOT folded into EXPIRED.
    expiry_alert_counts: Dict[str, int] = field(default_factory=dict)
    worst_expiry_alert: str = ExpiryAlert.UNKNOWN.value

    # --- failure breakdown ---
    status_counts: Dict[str, int] = field(default_factory=dict)
    policy_failure_counts: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "port": self.port,
            "total_checks": self.total_checks,
            "measured_checks": self.measured_checks,
            "successful_checks": self.successful_checks,
            "success_rate": self.success_rate,
            "min_latency": self.min_latency,
            "max_latency": self.max_latency,
            "avg_latency": self.avg_latency,
            "median_latency": self.median_latency,
            "std_latency": self.std_latency,
            "p95_latency": self.p95_latency,
            "p99_latency": self.p99_latency,
            "jitter": self.jitter,
            "consistency_score": self.consistency_score,
            "avg_dns_ms": self.avg_dns_ms,
            "avg_tcp_connect_ms": self.avg_tcp_connect_ms,
            "avg_starttls_ms": self.avg_starttls_ms,
            "tls13_rate": self.tls13_rate,
            "deprecated_tls_rate": self.deprecated_tls_rate,
            "forward_secrecy_rate": self.forward_secrecy_rate,
            "resumption_rate": self.resumption_rate,
            "hostname_match_rate": self.hostname_match_rate,
            "weak_key_rate": self.weak_key_rate,
            "weak_signature_rate": self.weak_signature_rate,
            "self_signed_rate": self.self_signed_rate,
            "expired_rate": self.expired_rate,
            "must_staple_rate": self.must_staple_rate,
            "revocation_source_rate": self.revocation_source_rate,
            "lifetime_compliant_rate": self.lifetime_compliant_rate,
            "lifetime_fails_next_renewal_rate": (self.lifetime_fails_next_renewal_rate),
            "cert_expiry_days_min": self.cert_expiry_days_min,
            "cert_expiry_days_avg": self.cert_expiry_days_avg,
            "certificates_observed": self.certificates_observed,
            "avg_handshake_bytes": self.avg_handshake_bytes,
            "avg_chain_bytes": self.avg_chain_bytes,
            "chains_observed": self.chains_observed,
            "latency_overflow_count": self.latency_overflow_count,
            "percentiles_refused": self.percentiles_refused,
            "expiry_alert_counts": dict(self.expiry_alert_counts),
            "worst_expiry_alert": self.worst_expiry_alert,
            "status_counts": dict(self.status_counts),
            "policy_failure_counts": dict(self.policy_failure_counts),
        }


# ---------------------------------------------------------------------------
# Metric namespace (item 50)
# ---------------------------------------------------------------------------


def build_ssl_metric_namespace(
    stats: HostStats,
    extra: Optional[Dict[str, float]] = None,
) -> Dict[str, float]:
    """Metric names an SSL `Threshold` may refer to.

    Built from `HostStats` so `ssl check` and any future `ssl monitor` path
    evaluate identical expressions against identical definitions, which is
    also what the SaaS grading layer consumes.

    Sample-dependent metrics are dropped when nothing was measured, and
    `cert_expiry_days` is omitted when no certificate was seen, so
    `--threshold 'cert_expiry_days>30'` against an unreachable host fails with
    a reason rather than passing against a fabricated zero.
    """
    namespace: Dict[str, float] = {
        "total_checks": float(stats.total_checks),
        "measured_checks": float(stats.measured_checks),
        "successful_checks": float(stats.successful_checks),
        "success_rate": stats.success_rate,
        # Complement of success_rate. Named failure_rate because that is what
        # people write gates against.
        "failure_rate": 100.0 - stats.success_rate,
        "min_latency": stats.min_latency,
        "max_latency": stats.max_latency,
        "avg_latency": stats.avg_latency,
        "median_latency": stats.median_latency,
        "p95_latency": stats.p95_latency,
        "p99_latency": stats.p99_latency,
        # Explicit aliases. `p95_latency` keeps parity with the other modules'
        # field naming; `p95_handshake_ms` says what it actually measures, and
        # in a TLS context that distinction matters enough to spell out.
        "min_handshake_ms": stats.min_latency,
        "max_handshake_ms": stats.max_latency,
        "avg_handshake_ms": stats.avg_latency,
        "median_handshake_ms": stats.median_latency,
        "p95_handshake_ms": stats.p95_latency,
        "p99_handshake_ms": stats.p99_latency,
        "jitter": stats.jitter,
        "consistency_score": stats.consistency_score,
        "avg_dns_ms": stats.avg_dns_ms,
        "avg_tcp_connect_ms": stats.avg_tcp_connect_ms,
        "avg_starttls_ms": stats.avg_starttls_ms,
        "tls13_rate": stats.tls13_rate,
        "deprecated_tls_rate": stats.deprecated_tls_rate,
        "forward_secrecy_rate": stats.forward_secrecy_rate,
        "hostname_match_rate": stats.hostname_match_rate,
        "weak_key_rate": stats.weak_key_rate,
        "weak_signature_rate": stats.weak_signature_rate,
        "self_signed_rate": stats.self_signed_rate,
        "expired_rate": stats.expired_rate,
        "must_staple_rate": stats.must_staple_rate,
        "revocation_source_rate": stats.revocation_source_rate,
        "lifetime_compliant_rate": stats.lifetime_compliant_rate,
        "lifetime_fails_next_renewal_rate": stats.lifetime_fails_next_renewal_rate,
        "avg_handshake_bytes": stats.avg_handshake_bytes,
        "latency_overflow_count": float(stats.latency_overflow_count),
    }

    if stats.measured_checks <= 0:
        for name in SSL_SAMPLE_DEPENDENT_METRICS:
            namespace.pop(name, None)

    if stats.percentiles_refused:
        # Item 57 — the percentile fields are 0.0 because too few samples were
        # collected to report them, and 0.0 would pass every `<` gate ever
        # written. Dropped so the threshold fails with a reason instead.
        for name in (
            "median_latency",
            "p95_latency",
            "p99_latency",
            "median_handshake_ms",
            "p95_handshake_ms",
            "p99_handshake_ms",
        ):
            namespace.pop(name, None)

    # Same metric name HTTP exposes, so a gate means the same thing in both.
    if stats.cert_expiry_days_min is not None:
        namespace["cert_expiry_days"] = float(stats.cert_expiry_days_min)

    if stats.resumption_rate is not None:
        namespace["resumption_rate"] = stats.resumption_rate

    if stats.avg_chain_bytes is not None:
        namespace["avg_chain_bytes"] = stats.avg_chain_bytes

    if extra:
        namespace.update(extra)
    return namespace


def ssl_metric_names() -> FrozenSet[str]:
    """Every metric name `build_ssl_metric_namespace` can emit.

    Derived from a zero-valued `HostStats` rather than hand-listed, so it
    cannot drift as metrics are added. The conditional keys are unioned back
    in explicitly — being dropped for an empty run is exactly what makes them
    conditional.

    Used by the CLI to reject a mistyped metric name before a scan starts:
    `parse_threshold` validates only the shape of the expression, so
    `cert_expiry_dayz>30` parses cleanly and would otherwise fail after the
    scan had already run.

    Deliberately a superset — a name that is real but absent from a particular
    run must still reach `evaluate_thresholds`, which fails it with a reason
    specific to what happened rather than a generic "unknown metric".
    """
    probe = HostStats(
        target="_",
        port=443,
        total_checks=0,
        measured_checks=0,
        successful_checks=0,
        success_rate=0.0,
        min_latency=0.0,
        max_latency=0.0,
        avg_latency=0.0,
        median_latency=0.0,
        std_latency=0.0,
        p95_latency=0.0,
        p99_latency=0.0,
    )
    return frozenset(
        set(build_ssl_metric_namespace(probe))
        | set(SSL_SAMPLE_DEPENDENT_METRICS)
        | {
            "cert_expiry_days",
            "resumption_rate",
            "avg_chain_bytes",
            "median_latency",
            "p95_latency",
            "p99_latency",
            "median_handshake_ms",
            "p95_handshake_ms",
            "p99_handshake_ms",
        }
    )


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------


# Most urgent first. UNKNOWN sorts last: a target with no certificate has not
# established anything about expiry, and letting it outrank a real EXPIRED
# finding would bury the one that needs acting on.
_EXPIRY_SEVERITY: Tuple[str, ...] = (
    ExpiryAlert.EXPIRED.value,
    ExpiryAlert.CRITICAL.value,
    ExpiryAlert.WARNING.value,
    ExpiryAlert.NOTICE.value,
    ExpiryAlert.OK.value,
    ExpiryAlert.UNKNOWN.value,
)


def _worst_expiry_alert(levels: Sequence[str]) -> str:
    for level in _EXPIRY_SEVERITY:
        if level in levels:
            return level
    return ExpiryAlert.UNKNOWN.value


class SSLAnalyzer:
    """Analyze SSL check results and compute per-target statistics."""

    def __init__(self, results: Sequence[SSLResult]) -> None:
        self.results = list(results)
        self.df = self._create_dataframe()

    def _create_dataframe(self) -> pd.DataFrame:
        rows: List[Dict[str, Any]] = []
        for result in self.results:
            certificate = result.certificate
            lifetime = certificate.lifetime if certificate is not None else None
            rows.append(
                {
                    "target": result.target,
                    "host": result.host,
                    "port": result.port,
                    "status": result.status.value,
                    # The two gates. Everything downstream filters on one of
                    # these; see the module docstring.
                    "measured": result.measured,
                    "compliant": bool(result.compliant),
                    # Held apart from `compliant` so an unevaluated result is
                    # not counted as a policy pass or a policy failure.
                    "policy_evaluated": result.compliant is not None,
                    "handshake_ms": result.handshake_ms,
                    "dns_ms": result.dns_ms,
                    "tcp_connect_ms": result.tcp_connect_ms,
                    "starttls_ms": result.starttls_ms,
                    "tls13": result.tls_version is TLSVersion.TLSV1_3,
                    "tls_deprecated": result.tls_version_deprecated,
                    "forward_secrecy": result.forward_secrecy,
                    "resumption_supported": result.resumption_supported,
                    "hostname_ok": result.hostname_match is HostnameMatch.MATCH,
                    "hostname_checked": result.hostname_match
                    is not HostnameMatch.NOT_CHECKED,
                    "handshake_bytes": (
                        result.handshake_bytes_sent + result.handshake_bytes_received
                    ),
                    "chain_bytes": result.chain_bytes,
                    "has_certificate": certificate is not None,
                    "cert_expiry_days": (
                        lifetime.days_remaining if lifetime is not None else None
                    ),
                    "expiry_alert": result.expiry_alert.value,
                    "cert_expired": (
                        lifetime.expired if lifetime is not None else False
                    ),
                    "weak_key": (
                        certificate.public_key.weak
                        if certificate is not None
                        else False
                    ),
                    "weak_signature": (
                        certificate.signature_weak if certificate is not None else False
                    ),
                    "self_signed": (
                        bool(certificate.self_signed)
                        if certificate is not None
                        else False
                    ),
                    "must_staple": (
                        certificate.revocation.must_staple
                        if certificate is not None
                        else False
                    ),
                    "revocation_source": (
                        certificate.revocation.has_any_source
                        if certificate is not None
                        else False
                    ),
                    "lifetime_compliant": (
                        lifetime is not None
                        and lifetime.verdict is LifetimeVerdict.COMPLIANT
                    ),
                    "lifetime_fails_next": (
                        lifetime is not None
                        and lifetime.verdict is LifetimeVerdict.FAILS_AT_NEXT_RENEWAL
                    ),
                    "samples_refused": result.handshake_samples_refused,
                    "sample_count": len(result.handshake_samples_ms),
                    "policy_failures": list(result.policy_failures),
                }
            )
        return pd.DataFrame(rows)

    # -- helpers ----------------------------------------------------------

    @staticmethod
    def _rate(numerator: int, denominator: int) -> float:
        return (numerator / denominator * 100.0) if denominator else 0.0

    @staticmethod
    def _mean(series: "pd.Series[Any]") -> float:
        clean = series.dropna()
        return float(clean.mean()) if len(clean) else 0.0

    def _merged_histogram(
        self,
        results: Sequence[SSLResult],
    ) -> Optional[LatencyHistogram]:
        """Merge per-target handshake histograms.

        Merged from the histograms themselves, never by averaging the
        per-result percentiles. Averaging p95s produces a different number, not
        an approximation of the union's p95, and no arithmetic recovers the
        real one once the samples are gone.
        """
        histograms = [
            r.handshake_histogram for r in results if r.handshake_histogram is not None
        ]
        if not histograms:
            return None
        return LatencyHistogram.merge_all(histograms)

    # -- per-target -------------------------------------------------------

    def get_target_statistics(self) -> List[HostStats]:
        """Compute `HostStats` for every host:port in the result set."""
        if self.df.empty:
            return []

        stats_list: List[HostStats] = []

        for target, group in self.df.groupby("target", sort=False):
            target_name = str(target)
            matching = [r for r in self.results if r.target == target_name]

            total = len(group)
            measured_mask = group["measured"].astype(bool)
            measured_count = int(measured_mask.sum())

            # Outcome rate is over policy-evaluated rows only. A run with no
            # policy configured would otherwise report 0% success for a set of
            # perfectly healthy endpoints.
            evaluated_mask = group["policy_evaluated"].astype(bool)
            evaluated_count = int(evaluated_mask.sum())
            if evaluated_count:
                successful = int(group[evaluated_mask]["compliant"].sum())
                success_rate = self._rate(successful, evaluated_count)
            else:
                successful = measured_count
                success_rate = self._rate(measured_count, total)

            # All handshake samples across this target's checks, not just the
            # single `handshake_ms` per result.
            samples: List[float] = []
            for result in matching:
                samples.extend(result.handshake_samples_ms)
            if not samples:
                samples = [
                    float(v)
                    for v in group[measured_mask]["handshake_ms"].dropna().tolist()
                ]

            histogram = self._merged_histogram(matching)
            refused = bool(
                measured_count and group[measured_mask]["samples_refused"].all()
            )

            if samples:
                array = np.array(samples, dtype=float)
                min_latency = float(array.min())
                max_latency = float(array.max())
                avg_latency = float(array.mean())
                std_latency = float(array.std())
                if refused:
                    # Item 57 — percentiles withheld. Left at 0.0 to keep the
                    # dataclass numeric, and `percentiles_refused` marks them
                    # so no consumer reads a withheld value as a measurement.
                    median_latency = p95 = p99 = 0.0
                else:
                    median_latency = float(np.median(array))
                    p95 = float(np.percentile(array, 95))
                    p99 = float(np.percentile(array, 99))
                jitter = (
                    float(np.mean(np.abs(np.diff(array)))) if len(array) > 1 else 0.0
                )
                consistency = (
                    max(0.0, 100.0 - (std_latency / avg_latency * 100.0))
                    if avg_latency > 0
                    else 0.0
                )
            else:
                min_latency = max_latency = avg_latency = 0.0
                median_latency = std_latency = p95 = p99 = 0.0
                jitter = consistency = 0.0

            measured = group[measured_mask]

            # Expiry over observed certificates only. None, not 0, when none
            # were seen — a 0 reads as "expires today".
            cert_days = measured["cert_expiry_days"].dropna()
            expiry_min = int(cert_days.min()) if len(cert_days) else None
            expiry_avg = float(cert_days.mean()) if len(cert_days) else None

            chain_series = measured["chain_bytes"].dropna()
            avg_chain = float(chain_series.mean()) if len(chain_series) else None

            resumption_series = measured["resumption_supported"].dropna()
            resumption_rate = (
                self._rate(int(resumption_series.sum()), len(resumption_series))
                if len(resumption_series)
                else None
            )

            hostname_checked = measured[measured["hostname_checked"].astype(bool)]
            fs_series = measured["forward_secrecy"].dropna()
            certs = measured[measured["has_certificate"].astype(bool)]
            cert_count = len(certs)

            failure_counts: Dict[str, int] = {}
            for entries in group["policy_failures"]:
                for entry in entries:
                    failure_counts[entry] = failure_counts.get(entry, 0) + 1

            stats_list.append(
                HostStats(
                    target=target_name,
                    port=int(group["port"].iloc[0]),
                    total_checks=total,
                    measured_checks=measured_count,
                    successful_checks=successful,
                    success_rate=success_rate,
                    min_latency=min_latency,
                    max_latency=max_latency,
                    avg_latency=avg_latency,
                    median_latency=median_latency,
                    std_latency=std_latency,
                    p95_latency=p95,
                    p99_latency=p99,
                    jitter=jitter,
                    consistency_score=consistency,
                    avg_dns_ms=self._mean(measured["dns_ms"]),
                    avg_tcp_connect_ms=self._mean(measured["tcp_connect_ms"]),
                    avg_starttls_ms=self._mean(measured["starttls_ms"]),
                    tls13_rate=self._rate(int(measured["tls13"].sum()), measured_count),
                    deprecated_tls_rate=self._rate(
                        int(measured["tls_deprecated"].sum()), measured_count
                    ),
                    forward_secrecy_rate=(
                        self._rate(int(fs_series.sum()), len(fs_series))
                        if len(fs_series)
                        else 0.0
                    ),
                    resumption_rate=resumption_rate,
                    hostname_match_rate=(
                        self._rate(
                            int(hostname_checked["hostname_ok"].sum()),
                            len(hostname_checked),
                        )
                        if len(hostname_checked)
                        else 0.0
                    ),
                    weak_key_rate=self._rate(int(certs["weak_key"].sum()), cert_count),
                    weak_signature_rate=self._rate(
                        int(certs["weak_signature"].sum()), cert_count
                    ),
                    self_signed_rate=self._rate(
                        int(certs["self_signed"].sum()), cert_count
                    ),
                    expired_rate=self._rate(
                        int(certs["cert_expired"].sum()), cert_count
                    ),
                    must_staple_rate=self._rate(
                        int(certs["must_staple"].sum()), cert_count
                    ),
                    revocation_source_rate=self._rate(
                        int(certs["revocation_source"].sum()), cert_count
                    ),
                    lifetime_compliant_rate=self._rate(
                        int(certs["lifetime_compliant"].sum()), cert_count
                    ),
                    lifetime_fails_next_renewal_rate=self._rate(
                        int(certs["lifetime_fails_next"].sum()), cert_count
                    ),
                    cert_expiry_days_min=expiry_min,
                    cert_expiry_days_avg=expiry_avg,
                    certificates_observed=cert_count,
                    avg_handshake_bytes=self._mean(measured["handshake_bytes"]),
                    avg_chain_bytes=avg_chain,
                    chains_observed=len(chain_series),
                    latency_histogram=histogram,
                    latency_overflow_count=(
                        histogram.overflow_count if histogram is not None else 0
                    ),
                    percentiles_refused=refused,
                    expiry_alert_counts=cast(
                        Dict[str, int],
                        group["expiry_alert"].value_counts().to_dict(),
                    ),
                    worst_expiry_alert=_worst_expiry_alert(
                        [str(v) for v in group["expiry_alert"]]
                    ),
                    status_counts=cast(
                        Dict[str, int],
                        group["status"].value_counts().to_dict(),
                    ),
                    policy_failure_counts=failure_counts,
                )
            )

        return stats_list

    # -- fleet-level ------------------------------------------------------

    def get_thresholds_report(
        self,
        thresholds: Sequence[Threshold],
    ) -> Dict[str, List[ThresholdResult]]:
        """Evaluate thresholds per target. Key is the target string.

        Mirrors HTTPAnalyzer.get_thresholds_report exactly, and for the same
        reason: kept on the analyzer rather than in the CLI so the `check`
        command and the SaaS grading layer evaluate the same expressions
        against the same metric definitions. A threshold like
        'cert_expiry_days>30' is inherently per-target — a fleet-wide average
        of expiry days across targets with wildly different certificates is
        not a number anyone would gate a build on.
        """
        report: Dict[str, List[ThresholdResult]] = {}
        for stats in self.get_target_statistics():
            namespace = build_ssl_metric_namespace(stats)
            report[stats.target] = evaluate_thresholds(thresholds, namespace)
        return report

    def get_overall_statistics(self) -> Dict[str, Any]:
        """Aggregate across every target in the run."""
        if self.df.empty:
            return {
                "total_checks": 0,
                "measured_checks": 0,
                "compliant_checks": 0,
                "targets": 0,
            }

        measured_mask = self.df["measured"].astype(bool)
        evaluated_mask = self.df["policy_evaluated"].astype(bool)
        measured = self.df[measured_mask]
        cert_days = measured["cert_expiry_days"].dropna()
        histogram = self._merged_histogram(self.results)

        return {
            "total_checks": int(len(self.df)),
            "measured_checks": int(measured_mask.sum()),
            "policy_evaluated_checks": int(evaluated_mask.sum()),
            "compliant_checks": int(self.df[evaluated_mask]["compliant"].sum()),
            "targets": int(self.df["target"].nunique()),
            "hosts": int(self.df["host"].nunique()),
            "deprecated_tls_targets": int(measured["tls_deprecated"].sum()),
            "weak_key_targets": int(measured["weak_key"].sum()),
            "expired_targets": int(measured["cert_expired"].sum()),
            "hostname_mismatch_targets": int(
                (
                    measured["hostname_checked"].astype(bool)
                    & ~measured["hostname_ok"].astype(bool)
                ).sum()
            ),
            "cert_expiry_days_min": (int(cert_days.min()) if len(cert_days) else None),
            "certificates_observed": int(len(cert_days)),
            "status_counts": cast(
                Dict[str, int], self.df["status"].value_counts().to_dict()
            ),
            "p95_handshake_ms": (
                histogram.quantile(0.95) if histogram is not None else None
            ),
            "chains_observed": int(measured["chain_bytes"].notna().sum()),
        }

    def get_failed_targets(self) -> List[Tuple[str, str, Optional[str]]]:
        """Targets whose handshake did not complete, with the reason."""
        return [
            (r.target, r.status.value, r.error_message)
            for r in self.results
            if r.status is not HandshakeStatus.OK
        ]


# ---------------------------------------------------------------------------
# Expiry timeline (items 42, 43)
# ---------------------------------------------------------------------------


def expiry_timeline(
    results: Sequence[SSLResult],
    buckets: Sequence[int] = (0, 7, 14, 30, 60, 90),
) -> List[Dict[str, Any]]:
    """Group targets into expiry windows for the timeline sheet.

    Only certificates that were actually observed are placed in a bucket. An
    unreachable target is reported in its own `unknown` group rather than
    landing in the most urgent bucket, which is what a `None` treated as 0
    would do — turning every scan failure into an expiry emergency.

    Buckets are upper-exclusive day counts; the final group catches everything
    beyond the last bucket.
    """
    ordered = sorted(set(int(b) for b in buckets))
    groups: List[Dict[str, Any]] = [
        {
            "label": f"<{edge}d" if edge > 0 else "expired",
            "max_days": edge,
            "targets": [],
        }
        for edge in ordered
    ]
    groups.append(
        {"label": f">={ordered[-1]}d", "max_days": None, "targets": []}
        if ordered
        else {"label": "all", "max_days": None, "targets": []}
    )
    unknown: List[str] = []

    for result in results:
        days = result.days_remaining
        if days is None:
            unknown.append(result.target)
            continue
        for group in groups:
            edge = group["max_days"]
            if edge is None or days < edge:
                cast(List[str], group["targets"]).append(result.target)
                break

    timeline = [
        {
            "label": group["label"],
            "max_days": group["max_days"],
            "count": len(cast(List[str], group["targets"])),
            "targets": cast(List[str], group["targets"]),
        }
        for group in groups
    ]
    timeline.append(
        {
            "label": "unknown",
            "max_days": None,
            "count": len(unknown),
            "targets": unknown,
        }
    )
    return timeline
