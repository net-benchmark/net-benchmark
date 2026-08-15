"""Statistical analysis of HTTP benchmark results."""

import math
import re
from dataclasses import (  # TargetStats.from_dict
    dataclass,
    field,
    fields as dataclass_fields,
)
from typing import (
    Any,
    Dict,
    FrozenSet,
    Iterable,
    List,
    Optional,
    Sequence,
    Set,
    Tuple,
    cast,
)

import numpy as np
import pandas as pd

from net_benchmark.dns_benchmark.core import QueryStatus
from net_benchmark.http_bench.core import HTTPProtocol, HTTPResult

# ---------------------------------------------------------------------------
# 0.5.2 — mergeable latency histogram
# ---------------------------------------------------------------------------


@dataclass
class LatencyHistogram:
    """0.5.2 — a log-linear, mergeable histogram of latency values in ms.

    Why this exists: TargetStats carries *computed* percentiles (p95_latency,
    p99_latency). Computed percentiles cannot be combined. Averaging the p95 of
    two workers does not give the p95 of their union, and there is no
    arithmetic that recovers it — the information needed is gone once the
    values are reduced to a number. Any distributed or multi-run aggregation
    therefore needs the distribution itself, not its summary.

    Layout: buckets are grouped by power-of-two exponent, each split into
    `sub_buckets` linear slices. A value v >= lowest_ms lands at
        exponent = floor(log2(v / lowest_ms))
        slice    = floor((v / (lowest_ms * 2**exponent) - 1) * sub_buckets)
    so every bucket is at most (1 / sub_buckets) wide *relative to its own
    lower bound*. With the default sub_buckets=128 that is a guaranteed
    relative error of under 0.79% at any magnitude — 0.4ms of error at 50ms,
    8ms at 1s. This is the same idea as HDRHistogram; it is implemented here
    rather than taken as a dependency because the hdrhistogram bindings pull a
    C build into an otherwise pure-Python package, and only the merge
    semantics are actually needed.

    count, total, min_ms and max_ms are tracked EXACTLY and are not subject to
    bucket error, so mean/min/max stay precise; only quantiles are
    approximate.

    Values below lowest_ms are clamped into bucket 0; values above the
    representable range land in the top bucket and are counted in
    `overflow_count` so a caller can tell that the tail is truncated rather
    than silently trusting a wrong p99.
    """

    lowest_ms: float = 0.01
    sub_buckets: int = 128
    max_exponent: int = 24  # 0.01ms * 2^24 ≈ 167s ceiling
    # Sparse: bucket_index -> count. Sparse rather than a dense array because
    # a real latency distribution occupies a few hundred buckets out of ~3000,
    # and this serialises to JSON compactly for the SaaS layer.
    counts: Dict[int, int] = field(default_factory=dict)
    count: int = 0
    total: float = 0.0
    min_ms: Optional[float] = None
    max_ms: Optional[float] = None
    overflow_count: int = 0

    # -- internals ---------------------------------------------------------

    def _index(self, value_ms: float) -> int:
        if value_ms <= self.lowest_ms:
            return 0
        ratio = value_ms / self.lowest_ms
        exponent = int(math.floor(math.log2(ratio)))
        if exponent >= self.max_exponent:
            return (self.max_exponent - 1) * self.sub_buckets + self.sub_buckets - 1
        frac = ratio / (2**exponent) - 1.0  # 0.0 <= frac < 1.0
        slice_ = int(frac * self.sub_buckets)
        if slice_ >= self.sub_buckets:  # float edge case
            slice_ = self.sub_buckets - 1
        return exponent * self.sub_buckets + slice_

    def bucket_bounds(self, index: int) -> Tuple[float, float]:
        """--- 0.5.2: public accessor for a bucket's [lower, upper) range in
        ms. Exporters need this to write bucket boundaries; reaching into
        _bounds from another module would be the same private-API coupling
        this codebase has been burned by before."""
        return self._bounds(index)

    def _bounds(self, index: int) -> Tuple[float, float]:
        exponent, slice_ = divmod(index, self.sub_buckets)
        base = self.lowest_ms * (2**exponent)
        lo = base * (1.0 + slice_ / self.sub_buckets)
        hi = base * (1.0 + (slice_ + 1) / self.sub_buckets)
        return lo, hi

    # -- recording ---------------------------------------------------------

    def record(self, value_ms: float) -> None:
        if value_ms != value_ms:  # NaN
            return
        if value_ms < 0:
            value_ms = 0.0
        if value_ms > self.lowest_ms * (2**self.max_exponent):
            self.overflow_count += 1
        idx = self._index(value_ms)
        self.counts[idx] = self.counts.get(idx, 0) + 1
        self.count += 1
        self.total += value_ms
        self.min_ms = value_ms if self.min_ms is None else min(self.min_ms, value_ms)
        self.max_ms = value_ms if self.max_ms is None else max(self.max_ms, value_ms)

    @classmethod
    def from_values(cls, values: Iterable[float], **kwargs: Any) -> "LatencyHistogram":
        h = cls(**kwargs)
        for v in values:
            h.record(float(v))
        return h

    # -- merging -----------------------------------------------------------

    def merge(self, other: "LatencyHistogram") -> "LatencyHistogram":
        """0.5.2 — combine two histograms into a new one.

        This is the operation the whole class exists for: it is what lets N
        workers (threads, processes, or geographically separate nodes) each
        record locally and still produce a correct global p95/p99. Requires
        identical bucket parameters — merging mismatched layouts would produce
        a plausible but meaningless result, so it raises instead.
        """
        if (
            self.lowest_ms != other.lowest_ms
            or self.sub_buckets != other.sub_buckets
            or self.max_exponent != other.max_exponent
        ):
            raise ValueError(
                "cannot merge LatencyHistograms with different bucket layouts "
                f"({self.lowest_ms}/{self.sub_buckets}/{self.max_exponent} vs "
                f"{other.lowest_ms}/{other.sub_buckets}/{other.max_exponent})"
            )
        merged = LatencyHistogram(
            lowest_ms=self.lowest_ms,
            sub_buckets=self.sub_buckets,
            max_exponent=self.max_exponent,
            counts=dict(self.counts),
            count=self.count + other.count,
            total=self.total + other.total,
            overflow_count=self.overflow_count + other.overflow_count,
        )
        for idx, c in other.counts.items():
            merged.counts[idx] = merged.counts.get(idx, 0) + c
        mins = [v for v in (self.min_ms, other.min_ms) if v is not None]
        maxs = [v for v in (self.max_ms, other.max_ms) if v is not None]
        merged.min_ms = min(mins) if mins else None
        merged.max_ms = max(maxs) if maxs else None
        return merged

    @classmethod
    def merge_all(cls, histograms: Sequence["LatencyHistogram"]) -> "LatencyHistogram":
        """0.5.2 — fold a sequence of histograms (e.g. one per worker/node)."""
        if not histograms:
            return cls()
        acc = histograms[0]
        for h in histograms[1:]:
            acc = acc.merge(h)
        return acc

    # -- reading -----------------------------------------------------------

    def quantile(self, q: float) -> float:
        """Value at quantile q (0.0-1.0). Returns the bucket midpoint.

        Accurate to within sub_buckets resolution — see the class docstring.
        Returns 0.0 for an empty histogram rather than raising, matching how
        get_target_statistics() reports p95/p99 for a target with no
        successful requests.
        """
        if self.count == 0:
            return 0.0
        if q <= 0:
            return self.min_ms or 0.0
        if q >= 1:
            return self.max_ms or 0.0
        target_rank = q * self.count
        seen = 0
        for idx in sorted(self.counts):
            seen += self.counts[idx]
            if seen >= target_rank:
                lo, hi = self._bounds(idx)
                mid = (lo + hi) / 2.0
                # Never report outside the exact observed range.
                if self.min_ms is not None:
                    mid = max(mid, self.min_ms)
                if self.max_ms is not None:
                    mid = min(mid, self.max_ms)
                return mid
        return self.max_ms or 0.0

    @property
    def mean(self) -> float:
        """Exact — computed from the running total, not from buckets."""
        return self.total / self.count if self.count else 0.0

    def to_dict(self) -> Dict[str, Any]:
        """0.5.2 — JSON-safe form. Keys are stringified for JSON object rules."""
        return {
            "lowest_ms": self.lowest_ms,
            "sub_buckets": self.sub_buckets,
            "max_exponent": self.max_exponent,
            "counts": {str(k): v for k, v in sorted(self.counts.items())},
            "count": self.count,
            "total": self.total,
            "min_ms": self.min_ms,
            "max_ms": self.max_ms,
            "overflow_count": self.overflow_count,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "LatencyHistogram":
        """0.5.2 — inverse of to_dict(); the wire format for distributed runs."""
        return cls(
            lowest_ms=float(d.get("lowest_ms", 0.01)),
            sub_buckets=int(d.get("sub_buckets", 128)),
            max_exponent=int(d.get("max_exponent", 24)),
            counts={int(k): int(v) for k, v in d.get("counts", {}).items()},
            count=int(d.get("count", 0)),
            total=float(d.get("total", 0.0)),
            min_ms=d.get("min_ms"),
            max_ms=d.get("max_ms"),
            overflow_count=int(d.get("overflow_count", 0)),
        )


# ---------------------------------------------------------------------------
# 0.5.2 — thresholds (pass/fail criteria)
# ---------------------------------------------------------------------------

# Operators, longest-first so "<=" is matched before "<".
_THRESHOLD_OPS: Dict[str, Any] = {
    "<=": lambda a, b: a <= b,
    ">=": lambda a, b: a >= b,
    "==": lambda a, b: a == b,
    "!=": lambda a, b: a != b,
    "<": lambda a, b: a < b,
    ">": lambda a, b: a > b,
}

_THRESHOLD_RE = re.compile(
    r"^\s*(?P<metric>[a-zA-Z_][a-zA-Z0-9_]*)\s*"
    r"(?P<op><=|>=|==|!=|<|>)\s*"
    r"(?P<value>-?\d+(?:\.\d+)?)\s*$"
)


@dataclass
class Threshold:
    """0.5.2 — one pass/fail criterion, e.g. `p95_latency < 500`."""

    metric: str
    op: str
    value: float

    def __str__(self) -> str:
        return f"{self.metric}{self.op}{self.value:g}"


@dataclass
class ThresholdResult:
    """0.5.2 — the outcome of evaluating one Threshold."""

    threshold: Threshold
    actual: Optional[float]
    passed: bool
    # Set when the metric name isn't in the namespace. An unknown metric is
    # reported as a FAILURE, not skipped: silently passing a threshold the
    # user asked for (because they typo'd it) is the worst possible outcome
    # for a CI gate.
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "threshold": str(self.threshold),
            "metric": self.threshold.metric,
            "op": self.threshold.op,
            "limit": self.threshold.value,
            "actual": self.actual,
            "passed": self.passed,
            "error": self.error,
        }


def parse_threshold(spec: str) -> Threshold:
    """0.5.2 — parse `"p95_latency<500"` into a Threshold.

    Raises ValueError on anything unparseable rather than guessing, so a
    malformed --threshold on the CLI fails loudly at argument-parse time
    instead of silently never firing.
    """
    m = _THRESHOLD_RE.match(spec)
    if not m:
        raise ValueError(
            f"invalid threshold {spec!r}; expected "
            "'<metric><op><number>', e.g. 'p95_latency<500' or 'error_rate<=1'"
        )
    return Threshold(
        metric=m.group("metric"),
        op=m.group("op"),
        value=float(m.group("value")),
    )


# --- 0.5.2: metrics computed from COMPLETED requests only. When a run has
# zero successful requests, TargetStats reports 0.0 for every one of them
# (there is nothing to average), and 0.0 satisfies any `<` threshold. A CI
# gate would therefore go green precisely when every single request failed —
# the worst possible outcome for a gate. build_metric_namespace() omits these
# when there are no samples, so a threshold naming one FAILS loudly instead.
#
# Counting metrics (total_requests, success_rate, error_rate,
# transport_error_rate, ...) stay defined at zero successes, because zero IS
# their meaningful value there.
SAMPLE_DEPENDENT_METRICS = frozenset(
    {
        "min_latency",
        "max_latency",
        "avg_latency",
        "median_latency",
        "p95_latency",
        "p99_latency",
        "jitter",
        "consistency_score",
        "avg_ttfb_ms",
        "p95_ttfb_ms",
        "avg_duration_ms",
        "p95_duration_ms",
        "avg_blocked_ms",
        "p95_blocked_ms",
        "avg_admission_wait_ms",
        "avg_sending_ms",
        "avg_waiting_ms",
        "p95_waiting_ms",
        "avg_receiving_ms",
        "avg_dns_ms",
        "avg_tcp_ms",
        "avg_tls_ms",
        "http2_rate",
        "http2_downgrade_rate",
        "redirect_rate",
        "connection_reuse_rate",
        "tls_resumption_rate",
    }
)

# --- 0.5.2: metrics that cannot survive a cross-worker merge.
#
# Same shape as SAMPLE_DEPENDENT_METRICS above, different cause. Only total_ms
# carries a mergeable LatencyHistogram, so load_test._merge_target_stats leaves
# these at 0.0 — there is no arithmetic that recovers a standard deviation or a
# phase percentile from per-worker summaries. But 0.0 is ALSO TargetStats'
# "no samples" value, so a merged summary that kept them in the namespace let
# `--threshold 'p95_waiting_ms<500'` pass vacuously and drive a green CI exit
# code on a distributed run.
#
# build_metric_namespace(merged=True) drops them, so such a threshold fails
# loudly as an unknown metric instead. Evaluate phase and dispersion thresholds
# per worker, where the values are exact.
#
# Note p95_latency/p99_latency/median_latency are deliberately NOT here: those
# ARE merged, correctly, from the merged histogram.
UNMERGEABLE_METRICS = frozenset(
    {
        "std_latency",
        "jitter",
        "consistency_score",
        "p95_ttfb_ms",
        "p95_duration_ms",
        "p95_blocked_ms",
        "p95_waiting_ms",
    }
)


def build_metric_namespace(
    stats: "TargetStats",
    duration_s: Optional[float] = None,
    extra: Optional[Dict[str, float]] = None,
    # --- 0.5.2: True when `stats` came out of _merge_target_stats. Appended
    # last and defaulted, so every existing caller is unaffected.
    merged: bool = False,
) -> Dict[str, float]:
    """0.5.2 — the metric names a Threshold may refer to.

    Built from TargetStats so the `http benchmark` path and the `http
    load-test` path evaluate identical expressions against identical
    definitions — one source of truth, which is also what the SaaS grading
    layer will consume. `extra` lets the load-test path add metrics that only
    exist there (dropped_rate, queue delay) without this function needing to
    know about load_test.py.
    """
    ns: Dict[str, float] = {
        "total_requests": float(stats.total_requests),
        "successful_requests": float(stats.successful_requests),
        "success_rate": stats.success_rate,
        # Complement of success_rate, as a percentage. Named error_rate
        # because that is what people write thresholds against.
        "error_rate": 100.0 - stats.success_rate,
        "transport_error_rate": stats.transport_error_rate,
        "unexpected_status_rate": stats.unexpected_status_rate,
        # --- 0.5.2: the missing third member of the classification set.
        # transport + unexpected + expected == 100. Only the first two were
        # thresholdable, so the positive form of the gate could not be written.
        "expected_response_rate": stats.expected_response_rate,
        "responded_requests": float(stats.responded_requests),
        "min_latency": stats.min_latency,
        "max_latency": stats.max_latency,
        "avg_latency": stats.avg_latency,
        "median_latency": stats.median_latency,
        "p95_latency": stats.p95_latency,
        "p99_latency": stats.p99_latency,
        "jitter": stats.jitter,
        "consistency_score": stats.consistency_score,
        "avg_ttfb_ms": stats.avg_ttfb_ms,
        "p95_ttfb_ms": stats.p95_ttfb_ms,
        # 0.5.2 — phase timings
        "avg_duration_ms": stats.avg_duration_ms,
        "p95_duration_ms": stats.p95_duration_ms,
        "avg_blocked_ms": stats.avg_blocked_ms,
        "p95_blocked_ms": stats.p95_blocked_ms,
        "avg_admission_wait_ms": stats.avg_admission_wait_ms,
        "avg_sending_ms": stats.avg_sending_ms,
        "avg_waiting_ms": stats.avg_waiting_ms,
        "p95_waiting_ms": stats.p95_waiting_ms,
        "avg_receiving_ms": stats.avg_receiving_ms,
        "avg_dns_ms": stats.avg_dns_ms,
        "avg_tcp_ms": stats.avg_tcp_ms,
        "avg_tls_ms": stats.avg_tls_ms,
        "http2_rate": stats.http2_rate,
        "http2_downgrade_rate": stats.http2_downgrade_rate,
        "redirect_rate": stats.redirect_rate,
        "connection_reuse_rate": stats.connection_reuse_rate,
        "tls_resumption_rate": stats.tls_resumption_rate,
        "total_response_bytes": float(stats.total_response_bytes),
        "total_upload_bytes": float(stats.total_upload_bytes),
        "latency_overflow_count": float(stats.latency_overflow_count),  # --- 0.5.2
    }
    # --- 0.5.2: drop the sample-dependent metrics when nothing completed.
    # See SAMPLE_DEPENDENT_METRICS above.
    # --- 0.5.2: gate on responded_requests. These metrics are dropped
    # because they have NO SAMPLES, and the samples come from responded
    # requests. Under the old gate a target that answered every request with
    # an unexpected status carried a good avg_latency on TargetStats but had
    # it stripped from the namespace, so `--threshold 'p95_latency<500'`
    # failed with "unknown metric" against a run that measured p95 ten times.
    if stats.responded_requests <= 0:
        for name in SAMPLE_DEPENDENT_METRICS:
            ns.pop(name, None)

    # --- 0.5.2: see UNMERGEABLE_METRICS. Dropped rather than reported as 0.0,
    # so a threshold naming one fails loudly against a merged summary instead
    # of passing against a value that only ever meant "not merged".
    if merged:
        for name in UNMERGEABLE_METRICS:
            ns.pop(name, None)

    if stats.cert_expiry_days_min is not None:
        ns["cert_expiry_days"] = float(stats.cert_expiry_days_min)
    if duration_s and duration_s > 0:
        ns["rps"] = stats.total_requests / duration_s
        ns["received_bytes_per_s"] = stats.total_response_bytes / duration_s
    if extra:
        ns.update(extra)
    return ns


def core_metric_names() -> FrozenSet[str]:
    """--- 0.5.2: every metric name build_metric_namespace can ever emit.

    Derived rather than hand-listed, so it cannot drift as metrics are added:
    a zero-valued TargetStats produces the unconditional keys, and the
    conditional ones are unioned back in explicitly — being popped or gated for
    a zero run is exactly what makes them conditional.

    Used by the CLI to reject a MISTYPED metric name before a run starts.
    parse_threshold validates only the shape of the expression, so
    `p95_latenci<500` parsed cleanly and failed at evaluation — after a 30s
    load test had already run. A typo should cost a second, not a full run.

    Deliberately a SUPERSET: a name that is real but absent from a particular
    run (sample-dependent on a failed run, dropped_rate on an unpaced one,
    un-mergeable on a merged one) must still reach evaluate_thresholds, which
    fails it with a reason specific to what happened rather than a generic
    "unknown metric".
    """
    probe = TargetStats(
        target="_",
        method="GET",
        total_requests=0,
        successful_requests=0,
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
        set(build_metric_namespace(probe, duration_s=1.0))
        | set(SAMPLE_DEPENDENT_METRICS)
        | set(UNMERGEABLE_METRICS)
        | {"cert_expiry_days"}
    )


def evaluate_thresholds(
    thresholds: Sequence[Threshold],
    namespace: Dict[str, float],
    # --- 0.5.2: lets the "why is this metric missing" message tell a merged
    # run apart from a failed one. Appended last and defaulted, so existing
    # callers are unaffected.
    merged: bool = False,
) -> List[ThresholdResult]:
    """0.5.2 — evaluate parsed thresholds against a metric namespace."""
    out: List[ThresholdResult] = []
    for t in thresholds:
        if t.metric not in namespace:
            # --- 0.5.2: distinguish "you typo'd the metric name" from "that
            # metric exists but this run produced no samples to compute it
            # from". Both FAIL — a threshold must never pass vacuously — but
            # the second needs a message that points at the run, not the
            # expression.
            if merged and t.metric in UNMERGEABLE_METRICS:
                # --- 0.5.2: checked BEFORE the sample-dependent branch. The
                # two sets overlap (p95_waiting_ms is in both), and on a merged
                # run the sample-dependent message is actively wrong — it told
                # the reader the run had no successful requests when it had
                # thousands, sending them to debug a failure that never
                # happened.
                reason = (
                    f"{t.metric} cannot be computed for a merged run: no "
                    "arithmetic recovers a dispersion or phase percentile from "
                    "per-worker summaries. Evaluate it per worker, or use "
                    "--workers 1"
                )
            elif t.metric in SAMPLE_DEPENDENT_METRICS:
                reason = (
                    f"{t.metric} is undefined: the run had no successful "
                    "requests, so there is nothing to measure"
                )
            else:
                reason = f"unknown metric {t.metric!r}; available: " + ", ".join(
                    sorted(namespace)
                )
            out.append(
                ThresholdResult(threshold=t, actual=None, passed=False, error=reason)
            )
            continue
        actual = float(namespace[t.metric])
        out.append(
            ThresholdResult(
                threshold=t,
                actual=actual,
                passed=bool(_THRESHOLD_OPS[t.op](actual, t.value)),
            )
        )
    return out


def thresholds_passed(results: Sequence[ThresholdResult]) -> bool:
    """0.5.2 — True only if every threshold passed. Drives the CLI exit code."""
    return all(r.passed for r in results)


# ---------------------------------------------------------------------------
# --- 0.5.2: queueing vocabulary — three distinct concepts, easily confused
# ---------------------------------------------------------------------------
#
#   blocked_ms          (HTTPResult / TargetStats)
#       Waiting for httpcore's connection pool to release a connection.
#       Bounded by the engine's max_connections.
#
#   admission_wait_ms   (HTTPResult / TargetStats)
#       Waiting on HTTPBenchmarkEngine's own max_concurrent semaphore, before
#       the request is issued at all. Normally ~0 under LoadTestEngine, where
#       the worker pool is the tighter bound.
#
#   queue_delay_ms      (load_test._TimedResult / RunCounters)
#       Sustained mode only: how late a request was sent relative to the time
#       the pacer scheduled it. Bounded by max_backlog, past which fires are
#       dropped rather than queued. This is the coordinated-omission signal.
#
# All three are "queueing"; none is interchangeable with another.
# ---------------------------------------------------------------------------


@dataclass
class TargetStats:
    """Statistics for a single HTTP target URL.

    Field layout mirrors ResolverStats:
      target              ← resolver_name  (identity)
      method              ← (no DNS equivalent — HTTP-specific)
      total_requests      ← total_queries
      successful_requests ← successful_queries
      success_rate        ← success_rate
      min/max/avg/...     ← same latency stat fields, same formulas
      http2_rate          ← dnssec_validation_rate  (protocol quality signal)

    This is also what net_benchmark.http_bench.load_test.LoadTestSummary
    embeds for its overall and per-interval stats — one stats engine shared
    by the regular `http benchmark` path and the `http load-test` path,
    rather than two separate percentile implementations.
    """

    target: str
    method: str
    total_requests: int
    successful_requests: int
    success_rate: float
    # latency — identical field names and formulas as ResolverStats
    min_latency: float
    max_latency: float
    avg_latency: float
    median_latency: float
    std_latency: float
    p95_latency: float
    p99_latency: float
    jitter: float = 0.0
    consistency_score: float = 0.0
    # HTTP-specific timing
    avg_ttfb_ms: float = 0.0
    p95_ttfb_ms: float = 0.0
    # protocol
    http2_rate: float = 0.0  # requests that negotiated HTTP/2
    redirect_rate: float = 0.0  # requests with at least one redirect

    # response
    avg_response_size_bytes: float = 0.0

    # 0.5.2 — phase timings.
    #
    #   avg/p95_duration_ms   total_ms MINUS connection setup. This is the
    #                         number to compare across requests and across
    #                         runs: total_ms (and therefore min/avg/p95/p99
    #                         _latency above) includes DNS + connect + TLS
    #                         whenever the request happened to open a new
    #                         connection, so those percentiles partly measure
    #                         the connection reuse ratio rather than the
    #                         target.
    #   avg/p95_blocked_ms    time waiting for httpcore's connection pool to
    #                         release a connection. Rising while
    #                         avg_waiting_ms stays flat is the single-node
    #                         ceiling made visible: requests are queueing
    #                         locally, and the run has stopped measuring the
    #                         target.
    #   avg_admission_wait_ms time queued on the engine's own max_concurrent
    #                         semaphore. Distinct from blocked: that is the
    #                         connection pool, this is the engine's admission
    #                         gate. Normally ~0 under LoadTestEngine.
    #   avg_sending_ms        writing request headers and body to the wire.
    #   avg/p95_waiting_ms    request fully sent -> response headers fully
    #                         received. Server processing plus round trip,
    #                         with local queueing and send time excluded —
    #                         the cleanest measure of the target itself.
    #   avg_receiving_ms      streaming the response body.

    avg_duration_ms: float = 0.0
    p95_duration_ms: float = 0.0
    avg_blocked_ms: float = 0.0
    p95_blocked_ms: float = 0.0
    avg_admission_wait_ms: float = 0.0
    avg_sending_ms: float = 0.0
    avg_waiting_ms: float = 0.0
    p95_waiting_ms: float = 0.0
    avg_receiving_ms: float = 0.0

    # 0.5.2 — how many completed requests actually opened a connection, and so
    # form the denominator of avg_tcp_ms / avg_tls_ms. Those two are now means
    # over NEW connections only (reused requests report None and are filtered
    # out), which is a change of meaning: they used to be means over every
    # request, with each keep-alive request repeating its connection's
    # original setup cost.
    connections_measured: int = 0
    # --- 0.5.2: count of latency samples that exceeded the histogram's
    # representable range (LatencyHistogram.overflow_count). Non-zero means
    # the tail is truncated and histogram percentiles understate it; the exact
    # p95/p99 fields are unaffected. Surfaced here so it can be thresholded
    # and exported rather than sitting unread on the histogram.
    latency_overflow_count: int = 0
    # 0.5.2: mean of FRESH DNS lookups only. Requests served from the
    # engine's DNS cache (HTTPResult.dns_cached) are excluded, so this is the
    # cost of resolving the hostname, not the cost amortised over a run.
    avg_dns_ms: float = 0.0
    # 0.5.2 — how many of this target's completed requests reported a
    # fresh DNS lookup. avg_dns_ms is meaningless when this is 0, and a low
    # value relative to total_requests is the expected steady state.
    dns_lookups_measured: int = 0

    avg_tcp_ms: float = 0.0
    avg_tls_ms: float = 0.0
    avg_compressed_size_bytes: float = 0.0
    avg_redirect_time_ms: float = 0.0
    http2_downgrade_rate: float = 0.0
    cache_control_present: int = 0
    etag_present: int = 0
    last_modified_present: int = 0
    age_present: int = 0
    # security signals — counts across all requests for this target
    hsts_present: int = 0
    csp_present: int = 0
    cdn_fingerprint: Optional[str] = None  # most common CDN for this target
    server_header: Optional[str] = None  # most common server header
    cert_expiry_days_min: Optional[int] = None  # worst cert seen across requests
    alt_svc: Optional[str] = None
    ip_version: Optional[str] = None  # most common across requests

    # --- 0.5.1 additions ---
    # % of completed requests that reused an existing connection instead of
    # opening a new one. Requires enable_connection_reuse=True on the
    # engine; stays 0.0 otherwise.
    connection_reuse_rate: float = 0.0
    # % of completed requests whose TLS session ID had been seen before on
    # this origin. Best-effort resumption signal, not a certainty — see
    # TimingNetworkStream.start_tls in core.py.
    tls_resumption_rate: float = 0.0
    # Total HTTP/2 server pushes observed across all requests for this
    # target. 0 if push detection was off or the h2 package is unavailable.
    http2_push_total: int = 0
    # Average multipart upload throughput (Mbps), across requests that
    # actually uploaded (multipart_file_size > 0). 0.0 if none did.
    avg_upload_throughput_mbps: float = 0.0

    # --- fields 0.5.2 ---

    # Mergeable distribution of total_ms across successful requests. p95/p99
    # above are computed exactly from the raw values and remain the numbers to
    # trust for a single run; this exists so several runs (or several workers,
    # or several nodes) can be combined into one correct percentile. See
    # LatencyHistogram.
    #
    # NOTE: latency_histogram.quantile(0.95) will NOT exactly equal
    # p95_latency above. The percentile fields are computed from the raw
    # values and are exact; the histogram returns a bucket midpoint, accurate
    # to within its resolution (<0.8% by default). Prefer the exact fields for
    # a single run, and the histogram only when combining runs.
    latency_histogram: Optional[LatencyHistogram] = None

    # Failure classification. success_rate above conflates two very different
    # things, because HTTPBenchmarkEngine marks any non-2xx/3xx response as
    # QueryStatus.UNKNOWN_ERROR: a 404 from a healthy server and a TCP reset
    # both land in the same bucket. These split them using a fact already
    # available on every result — a request that produced an http_status_code
    # reached the server, one that did not never got a response.
    #
    #   transport_error_rate    % with no HTTP response at all (DNS failure,
    #                           connection refused, TLS error, timeout)
    #   unexpected_status_rate  % that DID respond, but with a status outside
    #                           HTTPAnalyzer(expected_statuses=...)
    #   expected_response_rate  % that responded with an expected status
    #
    # A load test against an endpoint that legitimately returns 401 can set
    # expected_statuses={200, 401} and get a meaningful pass/fail instead of
    # a flat 100% failure.
    transport_error_rate: float = 0.0
    unexpected_status_rate: float = 0.0
    expected_response_rate: float = 0.0

    # 0.5.2 — requests that got an HTTP response back, whatever its status.
    # This is the sample count (and denominator) behind every latency, TTFB,
    # phase-timing, protocol and size field above. responded_requests >=
    # successful_requests always; the gap is unexpected_status_rate as a
    # count. When this is 0 the latency fields have no samples and
    # min/max/avg/median are NaN.
    responded_requests: int = 0

    # Byte totals across completed requests. Sums, not averages — these are
    # what you divide by duration to see whether the local NIC (rather than
    # the target) has become the ceiling. total_upload_bytes only counts
    # multipart upload bodies; ordinary request headers are not measured.
    total_response_bytes: int = 0
    total_upload_bytes: int = 0

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "TargetStats":
        """--- 0.5.2: rebuild a TargetStats from its serialised form.

        The inverse of load_test._stats_to_dict, and the missing half of a
        cross-machine run: without it a collector holding worker JSON cannot
        reconstruct stats to feed merge_summaries, and would have to
        reimplement the merge on the far side of the wire.

        Unknown keys are ignored rather than raising, so a newer worker can
        report to an older collector — the extra fields simply are not merged.
        Missing keys fall back to the dataclass defaults.
        """
        known = {f.name for f in dataclass_fields(cls)}
        kwargs: Dict[str, Any] = {k: v for k, v in d.items() if k in known}
        hist = kwargs.get("latency_histogram")
        if isinstance(hist, dict):
            kwargs["latency_histogram"] = LatencyHistogram.from_dict(hist)
        elif hist is not None and not isinstance(hist, LatencyHistogram):
            kwargs["latency_histogram"] = None
        return cls(**kwargs)


class HTTPAnalyzer:
    """Analyse HTTP benchmark results and compute statistics.

    Mirrors BenchmarkAnalyzer structure exactly — same __init__, same
    _create_dataframe pattern, same public method signatures.
    """

    # --- 0.5.2 — default set of status codes treated as an expected response.
    # 2xx and 3xx, matching what HTTPBenchmarkEngine already calls SUCCESS,
    # so the default changes nothing; override to make 4xx/5xx acceptable.
    DEFAULT_EXPECTED_STATUSES: range = range(200, 400)

    def __init__(
        self,
        results: List[HTTPResult],
        expected_statuses: Optional[Iterable[int]] = None,
    ) -> None:
        self.results = results
        # --- 0.5.2 — see TargetStats.unexpected_status_rate.
        self.expected_statuses: Set[int] = set(
            self.DEFAULT_EXPECTED_STATUSES
            if expected_statuses is None
            else expected_statuses
        )
        self.df = self._create_dataframe()

    def _create_dataframe(self) -> pd.DataFrame:
        """Convert HTTPResult list to DataFrame.

        Column mapping mirrors dns analysis.py _create_dataframe:
          latency_ms   → total_ms
          completed    → status == SUCCESS  (no DNSSEC_FAILED equivalent)
          resolver_name → target
          protocol.value → protocol
        """
        data = []
        for r in self.results:
            data.append(
                {
                    "target": r.target,
                    "method": r.method,
                    "total_ms": r.total_ms,
                    "ttfb_ms": r.ttfb_ms,
                    # --- 0.5.2 — phase breakdown, see TargetStats
                    "blocked_ms": r.blocked_ms,
                    "admission_wait_ms": r.admission_wait_ms,
                    "sending_ms": r.sending_ms,
                    "waiting_ms": r.waiting_ms,
                    "duration_ms": r.duration_ms,
                    "receiving_ms": r.receiving_ms,
                    "dns_resolve_ms": r.dns_resolve_ms,
                    # --- 0.5.2 — see avg_dns_ms in
                    # get_target_statistics(); cached rows are excluded from
                    # the DNS mean.
                    "dns_cached": r.dns_cached,
                    "dns_resolver_ip": r.dns_resolver_ip,
                    "tcp_connect_ms": r.tcp_connect_ms,
                    "tls_handshake_ms": r.tls_handshake_ms,
                    "status": r.status.value,
                    "completed": r.status == QueryStatus.SUCCESS,
                    # --- 0.5.2: did this request produce a MEASUREMENT?
                    #
                    # `completed` no longer answers that. Once
                    # expected_statuses landed, HTTPResult.status became a
                    # policy verdict — "was this the status code the caller
                    # asked for" — not a statement about whether a response
                    # arrived. A 403 is a complete, well-timed HTTP
                    # transaction: it carries total_ms, ttfb_ms, the phase
                    # breakdown, the negotiated protocol and every response
                    # header. Filtering the latency aggregates on `completed`
                    # discarded all of it, so a run whose responses were all
                    # an unexpected status printed "Avg latency 0.00 ms" and
                    # "HTTP/2 rate 0.0%" beside a raw CSV holding ten valid
                    # HTTP/2 samples.
                    #
                    # A response carries an http_status_code; a DNS failure,
                    # connection refusal, TLS error or timeout does not. That
                    # is the discriminator — get_target_statistics() already
                    # derived it locally for transport_error_rate, it just was
                    # never applied to the measurements.
                    #
                    # Deliberately NOT "every row": a timeout's total_ms is
                    # the timeout budget, not a latency sample.
                    "responded": r.http_status_code is not None,
                    "http_status_code": r.http_status_code,
                    "protocol": r.protocol.value,
                    "alpn_negotiated": r.alpn_negotiated or "",
                    "http2": r.protocol == HTTPProtocol.HTTP2,
                    "redirect_count": r.redirect_count,
                    "response_size_bytes": r.response_size_bytes or 0,
                    "compressed": r.compressed,
                    "compressed_size_bytes": r.compressed_size_bytes,
                    "redirect_timings": r.redirect_timings,
                    "http2_downgraded": r.http2_downgraded,
                    "hsts": r.security_headers.get("strict-transport-security")
                    is not None,
                    "csp": r.security_headers.get("content-security-policy")
                    is not None,
                    "cdn_fingerprint": r.cdn_fingerprint or "",
                    "server_header": r.server_header or "",
                    "cert_expiry_days": r.cert_expiry_days,
                    "alt_svc": r.alt_svc or "",
                    "ip_version": r.ip_version or "",
                    "error_message": r.error_message or "",
                    "attempt_number": r.attempt_number,
                    "iteration": r.iteration,
                    "query_id": r.query_id,
                    "start_time": r.start_time,
                    "cache_control": r.cache_control or "",
                    "etag": r.etag or "",
                    "last_modified": r.last_modified or "",
                    "age": r.age or "",
                    "assertion_results": r.assertion_results,
                    # --- 0.5.1 additions — previously collected on
                    # HTTPResult but silently dropped here, so
                    # get_target_statistics() had no way to surface them.
                    "connection_reused": r.connection_reused,
                    "connection_id": r.connection_id or "",
                    "tls_resumed": r.tls_resumed,
                    "tls_session_id": r.tls_session_id or "",
                    "session_ticket": r.session_ticket,
                    "http2_push_count": r.http2_push_count,
                    "upload_throughput_mbps": r.upload_throughput_mbps,
                    # 0.5.2 — needed for TargetStats.total_upload_bytes
                    "upload_size_bytes": r.upload_size_bytes or 0,
                    "websocket_handshake_ms": r.websocket_handshake_ms,
                }
            )
        return pd.DataFrame(data)

    def get_target_statistics(self) -> List[TargetStats]:
        """Compute per-target statistics. Mirrors get_resolver_statistics."""
        stats_list = []

        for target in self.df["target"].unique():
            td = self.df[self.df["target"] == target]
            method = td["method"].iloc[0]

            total = len(td)
            successful = int(td["completed"].sum())
            success_rate = (successful / total * 100) if total > 0 else 0.0

            # --- 0.5.2: the measurement mask, bound once so every aggregate
            # below is drawn from the SAME row set. The old code mixed masks
            # (latency on `completed`, hsts on every row), which is how one
            # summary box came to read "Avg latency 0.00 ms" and "HSTS
            # coverage 100.0%" at the same time. See the "responded" column
            # in _create_dataframe.
            responded = td["responded"]
            responded_count = int(responded.sum())

            latencies = td[responded]["total_ms"]
            ttfb_vals = td[responded & td["ttfb_ms"].notna()]["ttfb_ms"]

            # Timing breakdown averages
            # --- 0.5.2 — exclude rows served from the engine's DNS cache
            # (dns_cached=True). Those carry a replay of an earlier
            # measurement, not a fresh lookup, so counting them would weight
            # the mean toward one arbitrary sample repeated N times. On a
            # 1000-iteration single-target run the old behaviour averaged one
            # real value against 999 zeroes.
            dns_vals = td[
                responded & td["dns_resolve_ms"].notna() & (~td["dns_cached"])
            ]["dns_resolve_ms"]
            tcp_vals = td[responded & td["tcp_connect_ms"].notna()]["tcp_connect_ms"]
            tls_vals = td[responded & td["tls_handshake_ms"].notna()][
                "tls_handshake_ms"
            ]

            # --- 0.5.2 — phase timing series. tcp/tls already filter on .notna(),
            # which now automatically excludes keep-alive requests because
            # core.py sets those to None rather than repeating the
            # connection's original setup cost.
            dur_vals = td[responded & td["duration_ms"].notna()]["duration_ms"]
            # blocked_vals = td[td["blocked_ms"].notna()]["blocked_ms"]
            # --- 0.5.2: was missing the `completed` filter that every other
            # phase metric a few lines away applies, so failed requests were
            # mixed into this one mean and no other. Consistency matters more
            # than the extra samples: a p95_blocked_ms built from a different
            # row set than p95_waiting_ms cannot be compared against it, and
            # comparing those two is the entire point of the pair.
            blocked_vals = td[responded & td["blocked_ms"].notna()]["blocked_ms"]
            recv_vals = td[responded & td["receiving_ms"].notna()]["receiving_ms"]
            avg_duration = float(dur_vals.mean()) if len(dur_vals) > 0 else 0.0
            p95_duration = float(dur_vals.quantile(0.95)) if len(dur_vals) > 0 else 0.0
            avg_blocked = float(blocked_vals.mean()) if len(blocked_vals) > 0 else 0.0
            p95_blocked = (
                float(blocked_vals.quantile(0.95)) if len(blocked_vals) > 0 else 0.0
            )
            avg_receiving = float(recv_vals.mean()) if len(recv_vals) > 0 else 0.0
            adm_vals = td[responded & td["admission_wait_ms"].notna()][
                "admission_wait_ms"
            ]  # --- 0.5.2: same consistency fix as blocked_vals above
            send_vals = td[responded & td["sending_ms"].notna()]["sending_ms"]
            wait_vals = td[responded & td["waiting_ms"].notna()]["waiting_ms"]
            avg_admission = float(adm_vals.mean()) if len(adm_vals) > 0 else 0.0
            avg_sending = float(send_vals.mean()) if len(send_vals) > 0 else 0.0
            avg_waiting = float(wait_vals.mean()) if len(wait_vals) > 0 else 0.0
            p95_waiting = float(wait_vals.quantile(0.95)) if len(wait_vals) > 0 else 0.0
            avg_dns = float(dns_vals.mean()) if len(dns_vals) > 0 else 0.0
            avg_tcp = float(tcp_vals.mean()) if len(tcp_vals) > 0 else 0.0
            avg_tls = float(tls_vals.mean()) if len(tls_vals) > 0 else 0.0

            if len(latencies) > 0:
                arr = latencies.values
                min_l = float(latencies.min())
                max_l = float(latencies.max())
                avg_l = float(latencies.mean())
                med_l = float(latencies.median())
                std_l = float(latencies.std())
                p95_l = float(latencies.quantile(0.95))
                p99_l = float(latencies.quantile(0.99))

                if len(arr) == 1:
                    jitter = 0.0
                    consistency = 100.0
                else:
                    jitter = float(np.std(np.diff(arr)))
                    cv = std_l / avg_l if avg_l > 0 else 0.0
                    consistency = max(0.0, 100.0 - cv * 100.0)
            else:
                min_l = max_l = avg_l = med_l = std_l = float("nan")
                p95_l = p99_l = 0.0
                jitter = 0.0
                consistency = 0.0

            avg_ttfb = float(ttfb_vals.mean()) if len(ttfb_vals) > 0 else 0.0
            p95_ttfb = float(ttfb_vals.quantile(0.95)) if len(ttfb_vals) > 0 else 0.0

            # protocol signals
            http2_rate = (
                float(td[responded]["http2"].mean() * 100)
                if responded_count > 0
                else 0.0
            )
            redirect_rate = float((td["redirect_count"] > 0).mean() * 100)

            avg_size = (
                float(td[responded]["response_size_bytes"].mean())
                if responded_count > 0
                else 0.0
            )

            # security signals
            # --- 0.5.2: scoped to `responded` like every other aggregate.
            # Numerically a no-op (a request that never got a response carries
            # no headers, so hsts/csp are already False on those rows) but
            # this was the one metric computed over a different row set from
            # its neighbours, and that mismatch is what let the summary box
            # print "HSTS coverage 100.0%" directly above "HTTP/2 rate 0.0%"
            # for the same ten HTTP/2 responses.
            hsts_count = int(td[responded]["hsts"].sum())
            csp_count = int(td[responded]["csp"].sum())

            # Cache header presence (count non‑empty values among completed requests)
            cache_control_count = td[responded & (td["cache_control"] != "")].shape[0]
            etag_count = td[responded & (td["etag"] != "")].shape[0]
            last_modified_count = td[responded & (td["last_modified"] != "")].shape[0]
            age_count = td[responded & (td["age"] != "")].shape[0]

            # Compressed size average
            comp_vals = td[responded & td["compressed_size_bytes"].notna()][
                "compressed_size_bytes"
            ]
            avg_comp = float(comp_vals.mean()) if len(comp_vals) > 0 else 0.0

            # Average redirect time (flatten all hop timings)
            redirect_times = []
            for _, row in td[responded].iterrows():
                for hop in row.get("redirect_timings", []):
                    redirect_times.append(hop["duration_ms"])
            avg_redirect = (
                sum(redirect_times) / len(redirect_times) if redirect_times else 0.0
            )

            # HTTP/2 downgrade rate
            downgrade_count = int(
                td[(responded) & (td["http2_downgraded"] == True)].shape[0]
            )
            http2_downgrade_rate = (
                (downgrade_count / responded_count * 100)
                if responded_count > 0
                else 0.0
            )

            # most common CDN and server header (mode, ignoring empty strings)
            cdn_vals = td[td["cdn_fingerprint"] != ""]["cdn_fingerprint"]
            cdn = str(cdn_vals.mode().iloc[0]) if len(cdn_vals) > 0 else None

            srv_vals = td[td["server_header"] != ""]["server_header"]
            srv = str(srv_vals.mode().iloc[0]) if len(srv_vals) > 0 else None

            # worst (minimum) cert expiry seen for this target
            cert_days_series = td["cert_expiry_days"].dropna()
            cert_min = (
                int(cert_days_series.min()) if len(cert_days_series) > 0 else None
            )
            alt_svc_vals = td[td["alt_svc"] != ""]["alt_svc"]
            alt_svc = (
                str(alt_svc_vals.mode().iloc[0]) if len(alt_svc_vals) > 0 else None
            )

            ip_vals = td[td["ip_version"] != ""]["ip_version"]
            ip_version = str(ip_vals.mode().iloc[0]) if len(ip_vals) > 0 else None

            # --- 0.5.1 additions ---
            reused_count = int(td[responded]["connection_reused"].sum())
            connection_reuse_rate = (
                (reused_count / responded_count * 100) if responded_count > 0 else 0.0
            )

            resumed_count = int(td[responded]["tls_resumed"].sum())
            tls_resumption_rate = (
                (resumed_count / responded_count * 100) if responded_count > 0 else 0.0
            )

            http2_push_total = int(td["http2_push_count"].sum())

            upload_vals = td[responded & td["upload_throughput_mbps"].notna()][
                "upload_throughput_mbps"
            ]
            avg_upload_throughput_mbps = (
                float(upload_vals.mean()) if len(upload_vals) > 0 else 0.0
            )

            # --- 0.5.2 ---

            # Mergeable distribution over the same values p95/p99 came from.
            histogram = LatencyHistogram.from_values(latencies.values)

            # Failure classification. `responded` is the discriminator: a
            # result carrying an http_status_code got a response from the
            # server, one without it never did. This is derivable today
            # without any change to core.py.
            # --- 0.5.2: `responded` / `responded_count` are now bound at the
            # top of the loop, because every measurement aggregate uses the
            # same mask. This block used to be the only place that knew the
            # distinction existed.
            transport_errors = total - responded_count
            expected_count = int(
                td[
                    responded & td["http_status_code"].isin(self.expected_statuses)
                ].shape[0]
            )
            unexpected_count = responded_count - expected_count
            transport_error_rate = (
                (transport_errors / total * 100) if total > 0 else 0.0
            )
            unexpected_status_rate = (
                (unexpected_count / total * 100) if total > 0 else 0.0
            )
            expected_response_rate = (
                (expected_count / total * 100) if total > 0 else 0.0
            )

            total_response_bytes = int(td[responded]["response_size_bytes"].sum())
            total_upload_bytes = int(td[responded]["upload_size_bytes"].sum())

            stats_list.append(
                TargetStats(
                    target=target,
                    method=method,
                    total_requests=total,
                    successful_requests=successful,
                    success_rate=success_rate,
                    min_latency=min_l,
                    max_latency=max_l,
                    avg_latency=avg_l,
                    median_latency=med_l,
                    std_latency=std_l,
                    p95_latency=p95_l,
                    p99_latency=p99_l,
                    jitter=jitter,
                    consistency_score=consistency,
                    avg_ttfb_ms=avg_ttfb,
                    p95_ttfb_ms=p95_ttfb,
                    http2_rate=http2_rate,
                    redirect_rate=redirect_rate,
                    avg_response_size_bytes=avg_size,
                    avg_dns_ms=avg_dns,
                    dns_lookups_measured=len(dns_vals),
                    connections_measured=len(tcp_vals),
                    avg_duration_ms=avg_duration,
                    p95_duration_ms=p95_duration,
                    avg_blocked_ms=avg_blocked,
                    p95_blocked_ms=p95_blocked,
                    avg_receiving_ms=avg_receiving,
                    avg_admission_wait_ms=avg_admission,
                    avg_sending_ms=avg_sending,
                    avg_waiting_ms=avg_waiting,
                    p95_waiting_ms=p95_waiting,
                    avg_tcp_ms=avg_tcp,
                    avg_tls_ms=avg_tls,
                    avg_compressed_size_bytes=avg_comp,
                    avg_redirect_time_ms=avg_redirect,
                    http2_downgrade_rate=http2_downgrade_rate,
                    cache_control_present=cache_control_count,
                    etag_present=etag_count,
                    last_modified_present=last_modified_count,
                    age_present=age_count,
                    hsts_present=hsts_count,
                    csp_present=csp_count,
                    cdn_fingerprint=cdn,
                    server_header=srv,
                    cert_expiry_days_min=cert_min,
                    alt_svc=alt_svc,
                    ip_version=ip_version,
                    connection_reuse_rate=connection_reuse_rate,
                    tls_resumption_rate=tls_resumption_rate,
                    http2_push_total=http2_push_total,
                    avg_upload_throughput_mbps=avg_upload_throughput_mbps,
                    latency_histogram=histogram,
                    latency_overflow_count=histogram.overflow_count,  # --- 0.5.2
                    transport_error_rate=transport_error_rate,
                    unexpected_status_rate=unexpected_status_rate,
                    expected_response_rate=expected_response_rate,
                    responded_requests=responded_count,  # --- 0.5.2
                    total_response_bytes=total_response_bytes,
                    total_upload_bytes=total_upload_bytes,
                )
            )

        return stats_list

    # --- 0.5.2 ------------------------------------------------------------------

    GROUPABLE_COLUMNS: Tuple[str, ...] = (
        "target",
        "method",
        "protocol",
        "http_status_code",
        "connection_reused",
        "http2_downgraded",
        "ip_version",
        "cdn_fingerprint",
        "dns_cached",
    )

    def get_grouped_statistics(
        self, by: Sequence[str]
    ) -> List[Tuple[Dict[str, Any], TargetStats]]:
        """0.5.2 — per-target stats sliced by additional dimensions.

        get_target_statistics() aggregates by target only, which hides the
        most useful comparisons in a load test. Every field needed is already
        captured on HTTPResult; only the grouping was missing. Useful splits:

            by=["protocol"]           HTTP/2 vs requests that fell back to 1.1
            by=["connection_reused"]  cold-connection cost vs warm
            by=["http_status_code"]   is the p99 driven by the errors?
            by=["dns_cached"]         what a fresh resolve actually costs

        Cost note: each group re-runs HTTPAnalyzer over its subset, building
        a fresh DataFrame per group. That is deliberate — it keeps one
        implementation of the percentile maths — but grouping a million-row
        load test by http_status_code will be slow. Prefer low-cardinality
        columns (protocol, connection_reused) on large runs.

        Returns (group_key, stats) pairs. Each TargetStats is produced by
        re-running this same analyzer over the subset, so the percentile and
        latency maths is identical to the ungrouped path — no second
        implementation to drift.
        """
        if self.df.empty:
            return []

        unknown = [c for c in by if c not in self.GROUPABLE_COLUMNS]
        if unknown:
            raise ValueError(
                f"cannot group by {unknown}; available: "
                + ", ".join(self.GROUPABLE_COLUMNS)
            )
        if self.df.empty or not by:
            return [({}, st) for st in self.get_target_statistics()]

        # Index results positionally so each group can be mapped back to the
        # original HTTPResult objects and re-analysed, rather than trying to
        # recompute statistics from the DataFrame slice by hand.
        out: List[Tuple[Dict[str, Any], TargetStats]] = []
        grouped = self.df.groupby(list(by), dropna=False, sort=True)
        for key, idx in grouped.groups.items():
            key_tuple = key if isinstance(key, tuple) else (key,)
            group_key = dict(zip(by, key_tuple))
            subset = [self.results[i] for i in idx]
            sub = HTTPAnalyzer(subset, expected_statuses=self.expected_statuses)
            for st in sub.get_target_statistics():
                out.append((group_key, st))
        return out

    def get_thresholds_report(
        self,
        thresholds: Sequence[Threshold],
        duration_s: Optional[float] = None,
        extra_metrics: Optional[Dict[str, float]] = None,
    ) -> Dict[str, List[ThresholdResult]]:
        """0.5.2 — evaluate thresholds per target. Key is the target URL.

        Kept here rather than in the CLI so the load-test path, the benchmark
        path and the SaaS grading layer all evaluate the same expressions
        against the same metric definitions.
        """
        report: Dict[str, List[ThresholdResult]] = {}
        for st in self.get_target_statistics():
            ns = build_metric_namespace(st, duration_s=duration_s, extra=extra_metrics)
            report[st.target] = evaluate_thresholds(thresholds, ns)
        return report

    # ------------------------------------------------------------------

    def get_overall_statistics(self) -> Dict[str, Any]:
        """Overall benchmark statistics. Mirrors BenchmarkAnalyzer.get_overall_statistics."""
        total = len(self.df)
        successful = int(self.df["completed"].sum())
        success_rate = (successful / total * 100) if total > 0 else 0.0

        # --- 0.5.2: measurements come from rows that got a response, not
        # from rows whose status matched expected_statuses. See the
        # "responded" column in _create_dataframe.
        responded = self.df["responded"]
        responded_count = int(responded.sum())

        latencies = self.df[responded]["total_ms"]
        ttfb_vals = self.df[responded & self.df["ttfb_ms"].notna()]["ttfb_ms"]

        avg_l = float(latencies.mean()) if len(latencies) > 0 else 0.0
        med_l = float(latencies.median()) if len(latencies) > 0 else 0.0
        avg_ttfb = float(ttfb_vals.mean()) if len(ttfb_vals) > 0 else 0.0

        target_stats = self.get_target_statistics()
        ranked = sorted(
            # --- 0.5.2: rank on responded_requests. A target that answered
            # every request with an unexpected status still has a measured
            # latency and belongs in the ranking; previously it dropped out
            # and both fastest_target and slowest_target read "N/A".
            # responded_requests > 0 also guarantees avg_latency is not NaN,
            # so the sort key is well defined.
            [s for s in target_stats if s.responded_requests > 0],
            key=lambda s: s.avg_latency,
        )

        http2_rate = (
            float(self.df[responded]["http2"].mean() * 100)
            if responded_count > 0
            else 0.0
        )
        hsts_targets = sum(1 for s in target_stats if s.hsts_present > 0)
        resolver_ip = self.results[0].dns_resolver_ip if self.results else None

        # --- 0.5.2: gate on a received response, not QueryStatus.SUCCESS.
        # Assertions are evaluated against the response, so a request that
        # answered 403 and passed every assertion did pass its assertions;
        # tying this to the status-code policy conflated two independent
        # checks. Requests that never got a response stay excluded.
        #
        # KNOWN WART, deliberately unchanged: all({}.values()) is True, so a
        # run with no --assert flags reports assertion_pass_rate = 100%.
        assertion_pass_count = sum(
            1
            for r in self.results
            if r.http_status_code is not None and all(r.assertion_results.values())
        )
        assertion_pass_rate = (assertion_pass_count / total * 100) if total > 0 else 0.0

        # --- 0.5.1 additions ---
        # --- 0.5.2: denominators are responded_count, matching TargetStats.
        reused_count = int(self.df[responded]["connection_reused"].sum())
        connection_reuse_rate = (
            (reused_count / responded_count * 100) if responded_count > 0 else 0.0
        )
        resumed_count = int(self.df[responded]["tls_resumed"].sum())
        tls_resumption_rate = (
            (resumed_count / responded_count * 100) if responded_count > 0 else 0.0
        )

        return {
            "total_requests": total,
            "successful_requests": successful,
            # --- 0.5.2: requests that got an HTTP response back, whatever its
            # status. The sample count behind every latency and protocol
            # figure in this dict.
            "responded_requests": responded_count,
            "overall_success_rate": success_rate,
            "overall_avg_latency": avg_l,
            "overall_median_latency": med_l,
            "overall_avg_ttfb": avg_ttfb,
            "fastest_target": ranked[0].target if ranked else "N/A",
            "slowest_target": ranked[-1].target if ranked else "N/A",
            "target_count": len(target_stats),
            "http2_rate": http2_rate,
            "hsts_coverage": (
                (hsts_targets / len(target_stats) * 100) if target_stats else 0.0
            ),
            "dns_resolver_ip": resolver_ip,
            "assertion_pass_rate": assertion_pass_rate,
            "connection_reuse_rate": connection_reuse_rate,
            "tls_resumption_rate": tls_resumption_rate,
        }

    def get_ttfb_statistics(self) -> List[Dict[str, Any]]:
        """Per-target TTFB breakdown. Mirrors get_domain_statistics."""
        result = []
        for target in self.df["target"].unique():
            td = self.df[self.df["target"] == target]
            # --- 0.5.2: responded, not completed. See _create_dataframe.
            vals = td[td["responded"] & td["ttfb_ms"].notna()]["ttfb_ms"]
            result.append(
                {
                    "target": target,
                    "avg_ttfb_ms": float(vals.mean()) if len(vals) > 0 else 0.0,
                    "median_ttfb_ms": float(vals.median()) if len(vals) > 0 else 0.0,
                    "p95_ttfb_ms": float(vals.quantile(0.95)) if len(vals) > 0 else 0.0,
                    "p99_ttfb_ms": float(vals.quantile(0.99)) if len(vals) > 0 else 0.0,
                    "min_ttfb_ms": float(vals.min()) if len(vals) > 0 else 0.0,
                    "max_ttfb_ms": float(vals.max()) if len(vals) > 0 else 0.0,
                }
            )
        return result

    def get_protocol_distribution(self) -> List[Dict[str, Any]]:
        """HTTP/1.1 vs HTTP/2 breakdown. Mirrors get_protocol_statistics."""
        result = []
        for proto in self.df["protocol"].unique():
            pd_ = self.df[self.df["protocol"] == proto]
            total = len(pd_)
            successful = int(pd_["completed"].sum())
            # --- 0.5.2: latency percentiles come from responded rows. This
            # table exists to compare HTTP/2 against HTTP/1.1 timings, and
            # every row of an all-4xx run was previously blanked to 0.0.
            latencies = pd_[pd_["responded"]]["total_ms"]
            result.append(
                {
                    "protocol": proto,
                    "total_requests": total,
                    "successful_requests": successful,
                    "success_rate": (successful / total * 100) if total > 0 else 0.0,
                    "avg_latency": (
                        float(latencies.mean()) if len(latencies) > 0 else 0.0
                    ),
                    "median_latency": (
                        float(latencies.median()) if len(latencies) > 0 else 0.0
                    ),
                    "p95_latency": (
                        float(latencies.quantile(0.95)) if len(latencies) > 0 else 0.0
                    ),
                }
            )
        return result

    def get_security_summary(self) -> Dict[str, Any]:
        """Aggregate security signal counts across all results.
        Mirrors get_dnssec_statistics — the protocol-quality signal for HTTP.
        """
        total = len(self.df)
        completed = self.df[self.df["completed"]]

        # per-header presence counts
        header_counts: Dict[str, int] = {}
        for r in self.results:
            for h, v in r.security_headers.items():
                if v is not None:
                    header_counts[h] = header_counts.get(h, 0) + 1

        # CDN distribution
        cdn_vals = self.df[self.df["cdn_fingerprint"] != ""]["cdn_fingerprint"]
        cdn_dist = cdn_vals.value_counts().to_dict() if len(cdn_vals) > 0 else {}

        # server header leak count (present = potential info disclosure)
        server_leak_count = int((self.df["server_header"] != "").sum())

        # cert expiry — worst across all results
        cert_series = self.df["cert_expiry_days"].dropna()
        cert_min = int(cert_series.min()) if len(cert_series) > 0 else None

        return {
            "security_header_counts": header_counts,
            "cdn_distribution": cdn_dist,
            "server_header_leak_count": server_leak_count,
            "cert_expiry_days_min": cert_min,
            "total_requests": total,
            "completed_requests": int(completed["completed"].sum()),
        }

    def get_status_code_distribution(self) -> List[Dict[str, Any]]:
        """HTTP status code breakdown. No DNS equivalent — HTTP-only."""
        codes = self.df["http_status_code"].dropna().astype(int)
        dist = codes.value_counts().rename_axis("status_code").reset_index(name="count")
        dist["pct"] = (dist["count"] / len(self.df) * 100).round(2)
        return cast(List[Dict[str, Any]], dist.to_dict(orient="records"))

    def get_error_statistics(self) -> Dict[str, int]:
        """Error message counts. Mirrors BenchmarkAnalyzer.get_error_statistics."""
        # --- 0.5.2: an unexpected status is keyed "HTTP <code>" rather than
        # by error_message. A 403 sets no error_message, so ten of them
        # returned {"": 10} — an empty-string key that renders as a blank row
        # in the errors CSV. Keying matches load_test._summarize's
        # error_breakdown, so both paths label the same failure the same way.
        counts: Dict[str, int] = {}
        for r in self.results:
            if r.status == QueryStatus.SUCCESS:
                continue
            key = r.error_message or (
                f"HTTP {r.http_status_code}"
                if r.http_status_code is not None
                else str(r.status.value)
            )
            counts[key] = counts.get(key, 0) + 1
        return counts
