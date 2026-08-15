"""
Load testing engine (0.5.1): throughput, sustained rate, ramp-up.
Stats reuse HTTPAnalyzer/TargetStats from analysis.py — no separate
percentile/latency implementation.
"""

import asyncio
import functools
import math
import time
from dataclasses import (  # from_dict()
    asdict,
    dataclass,
    field,
    fields as dataclass_fields,
    replace,
)
from enum import Enum

# from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple
from typing import (
    Any,
    Awaitable,
    Callable,
    Dict,
    FrozenSet,
    Iterable,
    List,
    Optional,
    Sequence,
    Set,
    Tuple,
    TypeVar,
    cast,
)

from net_benchmark.dns_benchmark.core import QueryStatus
from net_benchmark.http_bench.analysis import (
    core_metric_names,  # --- 0.5.2: known_metric_names()
)
from net_benchmark.http_bench.analysis import (
    HTTPAnalyzer,
    LatencyHistogram,
    TargetStats,
    Threshold,
    ThresholdResult,
    build_metric_namespace,
    evaluate_thresholds,
    thresholds_passed,
)
from net_benchmark.http_bench.core import HTTPBenchmarkEngine, HTTPResult


@dataclass
class ConnectionReuseStats:
    """Keep-alive / connection-reuse detection (roadmap item 4).

    Kept separate from TargetStats.connection_reuse_rate (analysis.py) —
    that field is a rate over *completed* requests, computed from the
    connection_reused flag on each HTTPResult. This dataclass instead holds
    the raw TCP-connection-open count from the transport layer
    (HTTPBenchmarkEngine.get_connection_stats), which TargetStats has no
    equivalent for.
    """

    total_requests: int
    connections_opened: int

    @property
    def connections_reused(self) -> int:
        return max(0, self.total_requests - self.connections_opened)

    @property
    def reuse_rate(self) -> float:
        """0-1 fraction, unlike TargetStats.connection_reuse_rate which is
        0-100 — kept as a fraction here since this predates and is
        independent of the analysis.py field; exporters/CLI should be
        explicit about which one they're reading."""
        if self.total_requests == 0:
            return 0.0
        return self.connections_reused / self.total_requests


# --- 0.5.2: pushed onto the sustained-mode work queue to retire an idle
# worker. Negative because the queue otherwise carries non-negative
# scheduled offsets.
_STOP_SENTINEL = -1.0


@dataclass
class RunCounters:
    """--- 0.5.2: what the run actually managed to do.

    Without these, achieved_rps is unfalsifiable: a run that reports 5000 RPS
    while the pacer failed to fire 40% of its scheduled requests is not a 5000
    RPS run, and nothing in LoadTestSummary previously said so.

      scheduled  requests the pacer intended to issue (sustained mode only;
                 equals `started` in the saturation modes, which have no
                 schedule)
      started    requests actually handed to the engine
      dropped    scheduled but never started — every worker was busy and the
                 backlog was already at max_backlog. Non-zero means the target
                 could not keep up with target_rps.
      interrupted  still in flight when graceful_stop_s expired; cancelled,
                 so they produced no HTTPResult
      worker_errors  workers that died to an unhandled exception. A dead
                 worker silently reduces concurrency for the rest of the run.

    queue delay is the coordinated-omission signal: latency is measured from
    send, so if requests queue behind busy workers the reported percentiles
    look BETTER as the target degrades. A rising max_queue_delay_ms means the
    latency numbers are understated.
    """

    scheduled: int = 0
    started: int = 0
    dropped: int = 0
    # --- 0.5.2: True only for paced (open-model) runs, i.e. run_sustained.
    # The saturation modes have no schedule to fall behind, so `dropped` is
    # structurally always 0 there and a threshold like `dropped_rate<1` would
    # pass vacuously. metric_namespace() omits the dropped metrics entirely
    # when this is False, turning such a threshold into a loud "unknown
    # metric" failure instead of a silent pass.
    paced: bool = False
    interrupted: int = 0
    worker_errors: int = 0
    # --- 0.5.2 — exceptions raised by a user-supplied on_interval callback. The
    # callback is isolated so a broken dashboard cannot abort a load test,
    # but the failures are counted rather than swallowed.
    stream_errors: int = 0
    avg_queue_delay_ms: float = 0.0
    max_queue_delay_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """--- 0.5.2: wire format.

        asdict() rather than a hand-written mapping, which had already drifted:
        the old one omitted `paced`, so a summary that round-tripped through
        JSON lost the flag deciding whether dropped_rate is a real metric at
        all — turning a loud unknown-metric failure into a vacuous pass.
        """
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "RunCounters":
        known = {f.name for f in dataclass_fields(cls)}
        return cls(**{k: v for k, v in d.items() if k in known})


class LoadTestMode(str, Enum):
    THROUGHPUT = "throughput"  # item 1 — measure max achievable RPS
    SUSTAINED = "sustained"  # item 2 — N requests over T seconds at fixed rate
    RAMP_UP = "ramp_up"  # item 3 — gradually increasing concurrency


@dataclass
class IntervalStats:
    """One time bucket (default 1s) of results, for time-series charts
    (roadmap item 14). `stats` is a full TargetStats computed by running
    HTTPAnalyzer over just this bucket's results — same percentile/latency
    math as everywhere else, not a separate calculation.
    """

    window_index: int  # seconds since test start
    stats: TargetStats
    status_code_distribution: List[Dict[str, Any]]


@dataclass
class LoadTestSummary:
    mode: LoadTestMode
    target: str
    duration_s: float
    target_rps: Optional[float]
    # Overall run stats — a TargetStats from analysis.py, same as what
    # HTTPAnalyzer.get_target_statistics() would produce for a regular
    # `http benchmark` run against this target. Note: TargetStats.success_rate
    # and .connection_reuse_rate are 0-100 (percentages), not 0-1 fractions.
    stats: TargetStats
    status_code_distribution: List[Dict[str, Any]]
    connection_reuse: ConnectionReuseStats
    intervals: List[IntervalStats]
    results: List[HTTPResult]
    # --- 0.5.2. Defaulted and placed last so existing positional
    # constructions of LoadTestSummary keep working.
    counters: RunCounters = field(default_factory=RunCounters)
    # --- 0.5.2: error message -> count, computed while the results are still
    # in hand. The exporter used to derive this by iterating summary.results,
    # which retain_results=False empties: a run full of timeouts then produced
    # an errors file that looked complete and said "no errors". Status codes
    # alone are not a substitute — transport failures (DNS, refused, TLS,
    # timeout) carry no status code at all.
    error_breakdown: Dict[str, int] = field(default_factory=dict)
    # --- 0.5.2: the shared wall-clock epoch (Unix seconds, UTC) this run's
    # offsets were measured from, or None for a plain single-process run
    # measured from perf_counter()'s arbitrary origin.
    #
    # This is what makes duration_s and IntervalStats.window_index comparable
    # between workers. Two summaries carrying the same start_epoch describe
    # the same stretch of wall-clock time, so their window 7 is the same
    # second; two summaries carrying None do not, because perf_counter()'s
    # origin is per-process and meaningless across processes. merge_summaries
    # refuses to fold summaries whose epochs disagree for exactly that reason
    # — merging them would produce a plausible, silently misaligned timeline.
    start_epoch: Optional[float] = None
    # --- 0.5.2: True when this summary came out of merge_summaries.
    #
    # Exists to drive metric_namespace(). _merge_target_stats leaves
    # std_latency, jitter, consistency_score and the phase p95s at 0.0 because
    # nothing recovers them from per-worker summaries — but 0.0 is also
    # TargetStats' "no samples" value, so a threshold on one of them used to
    # PASS against a distributed run rather than failing. See
    # analysis.UNMERGEABLE_METRICS.
    #
    # Defaulted and placed after start_epoch, so existing constructions of
    # LoadTestSummary keep working.
    merged: bool = False
    # --- 0.5.2: the width of one IntervalStats window, in seconds.
    #
    # merge_summaries aligns intervals by window_index, and window_index alone
    # is meaningless without this: a worker on 1.0s buckets and a worker on
    # 0.5s buckets both report a "window 7", and folding them yields a
    # plausible timeline describing two different stretches of time. The epoch
    # check exists for exactly this class of error; this is its other half.
    interval_bucket_s: float = 1.0
    # --- 0.5.2: who produced this summary.
    #
    # merge_summaries is lossy by construction — after folding, nothing says
    # which node contributed which requests. That matters most for the case
    # the mechanism exists to serve: traffic from several regions with
    # different latencies, where the per-region split IS the result.
    worker_id: Optional[str] = None
    region: Optional[str] = None
    # --- 0.5.2: how late this worker actually began, in seconds after
    # start_epoch, measured at the instant the barrier released.
    #
    # Without it, worker lateness is only inferable from the index of the first
    # non-empty interval — i.e. at bucket resolution, and not at all for a
    # worker that produced no results. A synchronised run that was not
    # actually synchronised should be a number, not a shape in the timeline.
    # 0.0 for an unsynchronised run.
    start_offset_s: float = 0.0
    # --- 0.5.2: this worker's clock minus the coordinator's, in seconds, as
    # measured by the coordinator (see measure_clock_offset). None when
    # unmeasured.
    #
    # This is what start_epoch agreement CANNOT tell you. Every worker echoes
    # back the epoch it was handed, so comparing those values only proves they
    # were all told the same thing. A node whose clock runs 200 ms fast
    # genuinely starts 200 ms early, reports the agreed epoch, and sails
    # through the tolerance check. merge_summaries checks this instead when it
    # is present.
    clock_offset_s: Optional[float] = None
    # --- 0.5.2: worker_ids folded into this summary, in input order. Empty for
    # an unmerged run.
    merged_from: List[str] = field(default_factory=list)

    @property
    def latency_histogram(self) -> Optional[LatencyHistogram]:
        """--- 0.5.2 — the mergeable latency distribution for this run.

        This is the object a distributed orchestrator collects from each
        worker/node and folds with LatencyHistogram.merge_all(). p95/p99 on
        `stats` are exact for THIS run but cannot be combined across runs;
        this can. Delegates to TargetStats rather than keeping a second copy.
        """
        return self.stats.latency_histogram

    @property
    def received_bytes_per_s(self) -> float:
        """--- 0.5.2 — response bytes/sec. Compare against the local link capacity:
        when this flattens while achieved_rps also flattens, the generator is
        the ceiling, not the target."""
        if self.duration_s <= 0:
            return 0.0
        return self.stats.total_response_bytes / self.duration_s

    @property
    def sent_bytes_per_s(self) -> float:
        """--- 0.5.2 — multipart upload bytes/sec. Does not include request headers,
        which are not measured."""
        if self.duration_s <= 0:
            return 0.0
        return self.stats.total_upload_bytes / self.duration_s

    @property
    def dropped_rate(self) -> float:
        """--- 0.5.2 — % of scheduled requests that never fired. Non-zero means
        achieved_rps understates the load that was asked for, and that the
        latency figures describe a target that could not keep up."""
        if self.counters.scheduled <= 0:
            return 0.0
        return self.counters.dropped / self.counters.scheduled * 100.0

    def metric_namespace(self) -> Dict[str, float]:
        """--- 0.5.2 — metrics a Threshold can be written against.

        The shared benchmark metrics come from build_metric_namespace() so the
        `http benchmark` and `http load-test` paths agree on every definition;
        the load-test-only ones are added here.
        """
        ns = build_metric_namespace(
            self.stats,
            duration_s=self.duration_s,
            extra={
                "achieved_rps": self.achieved_rps,
                "target_rps": float(self.target_rps or 0.0),
                "interrupted": float(self.counters.interrupted),
                "worker_errors": float(self.counters.worker_errors),
                "avg_queue_delay_ms": self.counters.avg_queue_delay_ms,
                "max_queue_delay_ms": self.counters.max_queue_delay_ms,
                "connection_reuse_rate_fraction": self.connection_reuse.reuse_rate,
                "received_bytes_per_s": self.received_bytes_per_s,
                "sent_bytes_per_s": self.sent_bytes_per_s,
            },
            # --- 0.5.2: drops the un-mergeable metrics for a merged summary;
            # same "fail loudly rather than pass vacuously" reasoning as the
            # counters.paced gate just below.
            merged=self.merged,
        )
        # --- 0.5.2: see RunCounters.paced. Present only for paced runs, so a
        # dropped_rate threshold on a saturation run fails loudly as an
        # unknown metric instead of passing against a denominator that can
        # never be non-zero.
        if self.counters.paced:
            ns["dropped"] = float(self.counters.dropped)
            ns["dropped_rate"] = self.dropped_rate
        return ns

    def check_thresholds(
        self, thresholds: Sequence[Threshold]
    ) -> List[ThresholdResult]:
        """0.5.2 — evaluate pass/fail criteria against this run."""
        # --- 0.5.2: `merged` is forwarded so a threshold naming an
        # un-mergeable metric explains itself correctly. Without it the message
        # claimed the run had no successful requests, which on a merged run is
        # simply false.
        return evaluate_thresholds(
            thresholds, self.metric_namespace(), merged=self.merged
        )

    def passed(self, thresholds: Sequence[Threshold]) -> bool:
        """0.5.2 — True only if every threshold passed. Intended to drive the
        CLI exit code, which is what makes this usable as a CI gate."""
        return thresholds_passed(self.check_thresholds(thresholds))

    @property
    def achieved_rps(self) -> float:
        return (
            (self.stats.total_requests / self.duration_s)
            if self.duration_s > 0
            else 0.0
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mode": self.mode.value,
            "target": self.target,
            "duration_s": self.duration_s,
            # --- 0.5.2: on the wire so a collector can verify that the
            # summaries it is about to merge really do share an epoch.
            "start_epoch": self.start_epoch,
            # --- 0.5.2: so a consumer can tell that the dispersion and phase
            # percentile fields below are structural zeros, not measurements.
            "merged": self.merged,
            # --- 0.5.2: everything a collector needs to validate the inputs it
            # is about to merge, and to label them afterwards. Without these on
            # the wire, from_dict() could rebuild a summary that
            # merge_summaries would then happily fold against a mismatched
            # bucket width.
            "interval_bucket_s": self.interval_bucket_s,
            "worker_id": self.worker_id,
            "region": self.region,
            "start_offset_s": self.start_offset_s,
            "clock_offset_s": self.clock_offset_s,
            "merged_from": list(self.merged_from),
            "target_rps": self.target_rps,
            "achieved_rps": self.achieved_rps,
            "stats": _stats_to_dict(self.stats),
            "status_code_distribution": self.status_code_distribution,
            "connection_reuse": {
                "total_requests": self.connection_reuse.total_requests,
                "connections_opened": self.connection_reuse.connections_opened,
                "connections_reused": self.connection_reuse.connections_reused,
                "reuse_rate": self.connection_reuse.reuse_rate,
            },
            # --- 0.5.2
            "dropped_rate": self.dropped_rate,
            "received_bytes_per_s": self.received_bytes_per_s,
            "sent_bytes_per_s": self.sent_bytes_per_s,
            "latency_histogram": (
                self.latency_histogram.to_dict() if self.latency_histogram else None
            ),
            "error_breakdown": self.error_breakdown,
            # --- 0.5.2: see RunCounters.to_dict — the hand-written mapping
            # this replaces silently dropped `paced`.
            "counters": self.counters.to_dict(),
            "intervals": [
                {
                    "window_index": iv.window_index,
                    "stats": _stats_to_dict(iv.stats),
                    "status_code_distribution": iv.status_code_distribution,
                }
                for iv in self.intervals
            ],
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "LoadTestSummary":
        """--- 0.5.2: inverse of to_dict() — the collector half of a
        cross-machine run.

        to_dict() had no inverse, so merge_summaries could only ever be called
        on objects already in this process. A collector holding worker JSON had
        no way to rebuild summaries and would have had to reimplement the merge
        on the other side of the wire. This closes the loop: worker JSON ->
        from_dict -> merge_summaries -> the ordinary exporters.

        Two deliberate omissions:

          * `results` is not carried by to_dict() and is restored empty.
            Per-request rows are what retain_results=False exists to drop and
            are not something you want every node shipping back. Every
            statistic, interval and histogram survives; only the raw-result
            exports are empty for a reconstructed summary.
          * Derived values (achieved_rps, dropped_rate, the bytes/s pair) are
            recomputed from the fields they are properties of, never read back
            from the payload. A reconstructed summary that disagreed with its
            own inputs would be worse than one that is merely lossy.
        """
        reuse = d.get("connection_reuse", {})
        return cls(
            mode=LoadTestMode(d["mode"]),
            target=d["target"],
            duration_s=float(d["duration_s"]),
            target_rps=(
                float(d["target_rps"]) if d.get("target_rps") is not None else None
            ),
            stats=TargetStats.from_dict(d["stats"]),
            status_code_distribution=list(d.get("status_code_distribution", [])),
            connection_reuse=ConnectionReuseStats(
                total_requests=int(reuse.get("total_requests", 0)),
                connections_opened=int(reuse.get("connections_opened", 0)),
            ),
            intervals=[
                IntervalStats(
                    window_index=int(iv["window_index"]),
                    stats=TargetStats.from_dict(iv["stats"]),
                    status_code_distribution=list(
                        iv.get("status_code_distribution", [])
                    ),
                )
                for iv in d.get("intervals", [])
            ],
            results=[],
            counters=RunCounters.from_dict(d.get("counters", {})),
            error_breakdown=dict(d.get("error_breakdown", {})),
            start_epoch=(
                float(d["start_epoch"]) if d.get("start_epoch") is not None else None
            ),
            merged=bool(d.get("merged", False)),
            interval_bucket_s=float(d.get("interval_bucket_s", 1.0)),
            worker_id=d.get("worker_id"),
            region=d.get("region"),
            start_offset_s=float(d.get("start_offset_s", 0.0)),
            clock_offset_s=(
                float(d["clock_offset_s"])
                if d.get("clock_offset_s") is not None
                else None
            ),
            merged_from=list(d.get("merged_from", [])),
        )


@dataclass
class _TimedResult:
    result: HTTPResult
    completed_at_offset_s: float  # seconds since load test start
    # 0.5.2 — when the pacer INTENDED this request to fire, and how
    # long it actually sat waiting for a free worker. Only set by
    # run_sustained (the open-model path); None for the saturation modes,
    # which have no schedule to be late against.
    scheduled_at_offset_s: Optional[float] = None
    queue_delay_ms: Optional[float] = None


def _stats_to_dict(stats: TargetStats) -> Dict[str, Any]:
    """0.5.2 — JSON-safe TargetStats.

    Replaces the previous use of the live __dict__, which emitted
    TargetStats.latency_histogram as a LatencyHistogram OBJECT, so
    json.dumps() on a summary raised TypeError. Any future non-primitive
    field on TargetStats would break the same way; asdict() recurses into
    dataclasses, and the histogram goes through its own to_dict() so the
    bucket keys are strings (JSON object keys must be).
    """
    d = asdict(stats)
    if stats.latency_histogram is not None:
        d["latency_histogram"] = stats.latency_histogram.to_dict()
    return d


def _empty_target_stats(target: str) -> TargetStats:
    """Zeroed TargetStats for the (rare) case a run produced no results at
    all — HTTPAnalyzer can't compute stats from an empty DataFrame, so this
    is the explicit fallback rather than an IndexError on get_target_statistics()[0].
    """
    return TargetStats(
        target=target,
        method="",
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


def _build_intervals(
    timed_results: List[_TimedResult],
    bucket_s: float = 1.0,
    expected_statuses: Optional[Iterable[int]] = None,
) -> List[IntervalStats]:
    """Buckets results into time windows and runs HTTPAnalyzer over each
    bucket independently. Buckets with zero results are skipped rather than
    synthesized as zeroed stats (HTTPAnalyzer has nothing to compute from an
    empty result set) — this means a gap second just has no data point on
    the timeline rather than a misleading zero-dip.
    """
    if not timed_results:
        return []
    max_offset = max(tr.completed_at_offset_s for tr in timed_results)
    num_buckets = int(max_offset // bucket_s) + 1
    buckets: List[List[HTTPResult]] = [[] for _ in range(num_buckets)]
    for tr in timed_results:
        idx = min(int(tr.completed_at_offset_s // bucket_s), num_buckets - 1)
        buckets[idx].append(tr.result)

    intervals: List[IntervalStats] = []
    for idx, bucket in enumerate(buckets):
        if not bucket:
            continue
        analyzer = HTTPAnalyzer(bucket, expected_statuses=expected_statuses)
        target_stats_list = analyzer.get_target_statistics()
        # Single target per LoadTestEngine instance, so exactly one group.
        stats = (
            target_stats_list[0]
            if target_stats_list
            else _empty_target_stats(bucket[0].target)
        )
        status_dist = analyzer.get_status_code_distribution()
        intervals.append(
            IntervalStats(
                window_index=idx, stats=stats, status_code_distribution=status_dist
            )
        )
    return intervals


def _summarize(
    mode: LoadTestMode,
    target: str,
    duration_s: float,
    timed_results: List[_TimedResult],
    target_rps: Optional[float],
    connections_opened: int,
    counters: Optional[RunCounters] = None,
    expected_statuses: Optional[Iterable[int]] = None,
    # --- 0.5.2: defaulted, so existing keyword callers (and the tests) are
    # unaffected; None keeps the single-process perf_counter semantics.
    start_epoch: Optional[float] = None,
    # --- 0.5.2: BUG FIX. _build_intervals below was called with its default
    # 1.0 while _stream_intervals used self.interval_bucket_s, so any engine
    # built with a non-default bucket width produced streamed intervals and
    # summary.intervals on two different grids — contradicting the docstring
    # promise that the two agree. Now threaded from the caller.
    interval_bucket_s: float = 1.0,
    worker_id: Optional[str] = None,
    region: Optional[str] = None,
    start_offset_s: float = 0.0,
    clock_offset_s: Optional[float] = None,
) -> LoadTestSummary:
    results = [tr.result for tr in timed_results]

    # --- 0.5.2: see LoadTestSummary.error_breakdown. Built here, while the
    # raw results are still in hand, so retain_results=False cannot erase it.
    error_breakdown: Dict[str, int] = {}
    for r in results:
        if r.status == QueryStatus.SUCCESS:
            continue
        key = r.error_message or (
            f"HTTP {r.http_status_code}"
            if r.http_status_code is not None
            else str(r.status.value)
        )
        error_breakdown[key] = error_breakdown.get(key, 0) + 1

    # --- 0.5.2 — fold queue delay into the counters here so callers
    # don't each reimplement it.
    # --- 0.5.2: replace() rather than assigning onto the argument;
    # _summarize should not mutate an object owned by its caller.
    counters = counters or RunCounters()
    delays = [
        tr.queue_delay_ms for tr in timed_results if tr.queue_delay_ms is not None
    ]
    if delays:
        counters = replace(
            counters,
            avg_queue_delay_ms=sum(delays) / len(delays),
            max_queue_delay_ms=max(delays),
        )
    if results:
        analyzer = HTTPAnalyzer(results, expected_statuses=expected_statuses)
        target_stats_list = analyzer.get_target_statistics()
        stats = (
            target_stats_list[0] if target_stats_list else _empty_target_stats(target)
        )
        status_dist = analyzer.get_status_code_distribution()
    else:
        stats = _empty_target_stats(target)
        status_dist = []

    return LoadTestSummary(
        mode=mode,
        target=target,
        duration_s=duration_s,
        target_rps=target_rps,
        stats=stats,
        status_code_distribution=status_dist,
        connection_reuse=ConnectionReuseStats(
            total_requests=len(results), connections_opened=connections_opened
        ),
        intervals=_build_intervals(
            timed_results,
            bucket_s=interval_bucket_s,
            expected_statuses=expected_statuses,
        ),
        results=results,
        counters=counters,
        error_breakdown=error_breakdown,
        start_epoch=start_epoch,
        # --- 0.5.2
        interval_bucket_s=interval_bucket_s,
        worker_id=worker_id,
        region=region,
        start_offset_s=start_offset_s,
        clock_offset_s=clock_offset_s,
    )


# ---------------------------------------------------------------------------
# LoadTestEngine
# ---------------------------------------------------------------------------

_RunMethod = TypeVar("_RunMethod", bound=Callable[..., Awaitable["LoadTestSummary"]])


def _exclusive(fn: _RunMethod) -> _RunMethod:
    """--- 0.5.2: reject overlapping run_* calls on one LoadTestEngine.

    _start_time, _epoch, _start_offset_s and _conn_baseline are per-run state
    held on the instance. Two coroutines calling run_* on the same engine
    concurrently interleave writes to all four: the second _begin_run
    re-anchors _start_time under the first run's feet, so its offsets — and
    therefore every interval index and the reported duration — become nonsense,
    and both runs attribute the same connections to themselves. Nothing
    detected this; the numbers just came out wrong.

    A decorator rather than a `with` block inside each method, so the guard is
    one line per run_* and cannot be skipped by an early return. Released in a
    finally, so a failed run leaves the engine reusable.

    Sequential reuse — one engine across several configs — is untouched, and so
    is concurrency across DIFFERENT targets, which is one engine per target and
    the documented pattern.
    """

    @functools.wraps(fn)
    async def wrapper(
        self: "LoadTestEngine", *args: Any, **kwargs: Any
    ) -> "LoadTestSummary":
        if self._running:
            raise RuntimeError(
                f"LoadTestEngine for {self.target!r} is already running. One "
                "engine cannot execute two runs at once — its start time and "
                "connection baseline are per-run state. Construct one engine "
                "per concurrent run."
            )
        self._running = True
        try:
            return await fn(self, *args, **kwargs)
        finally:
            self._running = False

    return cast(_RunMethod, wrapper)


class LoadTestEngine:
    """Wraps a single-target HTTPBenchmarkEngine with load-shaping strategies.

    One LoadTestEngine == one target. For multi-target load tests, construct
    one instance per target (each gets its own pooled client/transport via
    the underlying HTTPBenchmarkEngine, so origins never share connections).
    """

    def __init__(
        self,
        target: str,
        http_engine: Optional[HTTPBenchmarkEngine] = None,
        expected_statuses: Optional[Iterable[int]] = None,
        on_interval: Optional[Callable[[IntervalStats], None]] = None,
        retain_results: bool = True,
        interval_bucket_s: float = 1.0,
        emit_empty_intervals: bool = False,
        # --- 0.5.2: identity labels. Appended last and defaulted, so existing
        # constructions are unaffected. Copied onto every summary this engine
        # produces, so a summary stays attributable after it crosses a wire.
        worker_id: Optional[str] = None,
        region: Optional[str] = None,
        clock_offset_s: Optional[float] = None,
    ):
        self.target = target
        # --- 0.5.2 — status codes that count as a healthy response. Without this a
        # load test against an endpoint that legitimately returns 401 or 404
        # reports a flat 100% failure, because the engine marks every non-2xx/
        # 3xx response as QueryStatus.UNKNOWN_ERROR. Passed through to
        # HTTPAnalyzer, which reports transport failures separately from
        # unexpected statuses. Default (None) preserves existing behaviour.
        self.expected_statuses: Optional[Set[int]] = (
            set(expected_statuses) if expected_statuses is not None else None
        )
        # --- 0.5.2 — called once per completed time bucket DURING the run, not
        # after it. Lets the SaaS layer write intervals to Postgres as they
        # happen and the CLI print a live table, instead of everything landing
        # in one batch at the end. Emits only non-empty buckets by default,
        # matching _build_intervals(), so the streamed sequence and the
        # final summary.intervals agree; see emit_empty_intervals below to
        # opt into a heartbeat on silent windows.
        self.on_interval = on_interval
        self.interval_bucket_s = interval_bucket_s
        # --- 0.5.2 — opt-in heartbeat. By default a window in which nothing
        # completed emits nothing, matching _build_intervals() so the
        # streamed sequence and summary.intervals agree element-for-element.
        # That is the right default for a consumer aggregating buckets, and
        # the wrong one for a consumer driving a live display: a target that
        # stalls, a long timeout window, or simply a low target_rps produces
        # silence indistinguishable from a dead run.
        #
        # When True, an empty window emits IntervalStats with zeroed stats
        # and an empty status distribution. The stream then NO LONGER
        # matches summary.intervals one-for-one -- it is a superset. A
        # consumer that persists streamed intervals as the run's interval
        # record must filter total_requests == 0 or accept the empty rows.
        self.emit_empty_intervals = emit_empty_intervals
        #
        # --- 0.5.2 — when False, LoadTestSummary.results is emptied before the
        # summary is returned. Intervals and all statistics are unaffected
        # (they are computed first). NOTE: this bounds the memory the CALLER
        # holds afterwards, not peak memory during the run — results still
        # accumulate while the test executes. Streaming-only aggregation is a
        # separate change.
        self.retain_results = retain_results
        # max_concurrent is set high by default here; individual run_* methods
        # bound actual in-flight concurrency themselves via their own
        # semaphores/pacing, so the engine-level cap just needs to not be the
        # bottleneck.
        self.engine = http_engine or HTTPBenchmarkEngine(max_concurrent=1000)
        self._start_time: float = 0.0
        # --- 0.5.2 — see _begin_run/_connections_opened_since below.
        self._conn_baseline: int = 0
        # --- 0.5.2 — the shared wall-clock epoch the current run is anchored
        # to, or None for the default single-process behaviour. Set by
        # _begin_run and copied onto the summary; see run_* start_at.
        self._epoch: Optional[float] = None
        # --- 0.5.2
        self.worker_id = worker_id
        self.region = region
        self.clock_offset_s = clock_offset_s
        # How late this run actually started against its epoch; see
        # LoadTestSummary.start_offset_s.
        self._start_offset_s: float = 0.0
        # --- 0.5.2 — re-entrancy guard. _start_time, _epoch, _conn_baseline
        # and _start_offset_s are per-run state on a shared instance, so two
        # concurrent run_* calls on one engine silently corrupt each other's
        # offsets and connection baseline. Sequential reuse (the documented
        # pattern of one engine across several configs) is unaffected; only
        # overlap is rejected, and loudly. See _exclusive.
        self._running: bool = False

    def _offset(self) -> float:
        return time.perf_counter() - self._start_time

    async def _raw_connections_opened(self) -> int:
        stats = self.engine.get_connection_stats(self.target)
        return int(stats["connections_opened"])

    async def warmup(self, requests: int) -> int:
        """--- 0.5.2: open connections before the run starts.

        Returns the number of warmup requests actually issued.

        Under a shared epoch every worker begins DNS  TCP  TLS at the barrier
        instant, so the opening seconds of a synchronised run measure
        connection establishment rather than steady-state load. Consistent
        across workers, so it does not MISALIGN anything — but the synchronised
        start was otherwise a synchronised cold start, which is a spike test,
        not the steady-state test people think they are running.

        Called from _begin_run BEFORE the barrier wait, so connections are
        already established when the epoch fires, and before the
        connections_opened baseline is snapshotted, so warmup connections are
        excluded from the run's reuse figures rather than billed to it.

        Warmup results are discarded: they are not part of the measured run and
        would otherwise skew the first bucket with handshake latency, which is
        the whole thing this removes.
        """
        if requests <= 0:
            return 0
        for _ in range(requests):
            await self.engine.request_single(self.target)
        return requests

    async def _begin_run(
        self,
        start_at: Optional[float] = None,
        warmup_requests: int = 0,  # --- 0.5.2: see warmup()
    ) -> None:
        """0.5.2: start-of-run bookkeeping.

        --- 0.5.2, start_at: an absolute wall-clock epoch in Unix seconds (the
        time.time() domain, UTC), shared by every worker in a distributed run.
        Default None preserves the previous behaviour exactly.

        Why an absolute epoch is required rather than "just start them at the
        same time": perf_counter() is monotonic but its ORIGIN is arbitrary and
        per-process. Two workers' perf_counter() values are not comparable at
        all, so offsets derived from them cannot be aligned — their window 0
        covers different stretches of real time, and summing intervals by index
        silently misaligns the series. time.time() has a shared origin across
        processes and machines, which is the only property needed here.

        Two things happen when start_at is given:

          * _start_time is set to the perf_counter INSTANT CORRESPONDING to
            start_at, so _offset() means "seconds since the shared epoch" for
            the rest of the run. Both clocks are read back-to-back so the
            conversion is not skewed by whatever happens next.
          * If start_at is still in the future, the run sleeps until it. That
            sleep is the actual start barrier.

        A start_at in the PAST is not an error and is not re-zeroed: the run
        begins immediately with _offset() already equal to how late this worker
        was. That lateness is real and belongs in the data — a worker whose
        first result lands at offset 2.4 genuinely contributed nothing to the
        first two seconds of the shared window, and re-zeroing would fabricate
        overlap that did not exist.

        Note the deliberate knock-on in run_sustained: its `stop_at` is derived
        from _start_time, so under an epoch it becomes an ABSOLUTE deadline at
        start_at + duration_s. Every worker therefore stops at the same
        wall-clock instant and a late worker simply runs shorter. That is the
        correct synchronised semantic and it falls out of the existing
        arithmetic. The consequence to know about: a start_at more than
        duration_s in the past yields a zero-request run, reported honestly as
        scheduled=0 rather than as a successful run of no work.

        TimingNetworkBackend.connections_opened is cumulative for the lifetime
        of the transport and is never reset. LoadTestEngine accepts an injected
        HTTPBenchmarkEngine, so that counter may already be non-zero when a run
        starts — from a warmup, an earlier run_* call on the same instance, or
        the SaaS layer reusing one engine across several configs. The old code
        passed the raw cumulative count straight into ConnectionReuseStats,
        where `max(0, total_requests - connections_opened)` quietly clamped the
        overcount to zero and produced a plausible-looking but wrong reuse rate.
        Snapshotting here makes connections_opened per-run.
        """
        # --- 0.5.2: warm the connection pool BEFORE the barrier, so the epoch
        # fires against established connections rather than a synchronised
        # handshake storm. Ordering matters twice over: it must also precede
        # the _conn_baseline snapshot so warmup connections are not billed to
        # the run.
        await self.warmup(warmup_requests)

        if start_at is None:
            self._epoch = None
            self._start_time = time.perf_counter()
            self._start_offset_s = 0.0
        else:
            self._epoch = start_at
            # Read both clocks adjacently: lateness is the wall-clock gap, and
            # _start_time is the perf instant that gap puts us behind.
            wall_now = time.time()
            perf_now = time.perf_counter()
            self._start_time = perf_now - (wall_now - start_at)
            delay = start_at - wall_now
            if delay > 0:
                await asyncio.sleep(delay)
            # --- 0.5.2: measured AFTER the barrier, so this is the real
            # release instant rather than the intended one. A worker that woke
            # late (loaded box, long warmup, GC pause) records the lateness it
            # actually had. Clamped at zero: sleeping until start_at can
            # overshoot but never undershoot, so a negative value would only
            # ever be clock jitter.
            self._start_offset_s = max(0.0, time.time() - start_at)
        # Snapshotted after any barrier wait, so a warmup running concurrently
        # with the wait is excluded from this run's connection count.
        self._conn_baseline = await self._raw_connections_opened()

    async def _stream_intervals(
        self,
        timed_results: List[_TimedResult],
        lock: asyncio.Lock,
        stop_event: asyncio.Event,
    ) -> int:
        """0.5.2 — emit completed time buckets while the run is still going.

        Returns the number of on_interval exceptions swallowed.

        Correctness note on the cursor: results are appended to
        `timed_results` under `lock`, and completed_at_offset_s is read inside
        that same critical section, so the list is always ordered by
        completion time. Everything belonging to an already-closed window is
        therefore a contiguous prefix of the unemitted tail, and a single
        integer cursor cannot double-count or skip a result.

        A window is CLOSED once elapsed time has passed its boundary. That
        is safe rather than merely convenient: completed_at_offset_s is
        taken inside the same critical section that appends, so a result
        appended from now on carries an offset >= now and cannot land in a
        window already behind the clock. A streamed interval therefore
        always agrees with the same bucket in summary.intervals.

        Empty windows emit nothing by default, matching _build_intervals(),
        but window_index still advances, so it always means "seconds since
        run start" even across a stretch with no completions. Set
        emit_empty_intervals=True to receive a zeroed IntervalStats for
        those windows instead; the stream is then a superset of
        summary.intervals rather than a match for it.
        """
        callback = self.on_interval
        if callback is None:
            return 0
        bucket_s = self.interval_bucket_s
        cursor = 0  # index of first not-yet-emitted result
        window = 0  # next window index to consider
        errors = 0

        def _invoke(interval: IntervalStats) -> None:
            nonlocal errors
            try:
                callback(interval)
            except Exception:  # noqa: BLE001
                # Deliberately broad: on_interval is caller-supplied and a
                # bug there must not abort a load test that is otherwise
                # producing valid data. Counted rather than hidden --
                # surfaces as RunCounters.stream_errors.
                errors += 1

        async def emit(final: bool) -> None:
            nonlocal cursor, window
            async with lock:
                pending = timed_results[cursor:]
                latest = (
                    timed_results[-1].completed_at_offset_s if timed_results else 0.0
                )
            # --- 0.5.2 fix: a window closes on the CLOCK, not on the arrival
            # of a later result.
            #
            # Gating on `latest` meant a window only closed once some LATER
            # result had been observed past its boundary. Consequences:
            # the stream lagged a full bucket at best; it stalled entirely
            # whenever completions paused (a slow target, a timeout window,
            # or simply a low target_rps); and the `if not pending: return`
            # that used to sit here returned before `window += 1`, so the
            # documented invariant -- window_index means seconds since run
            # start -- did not hold across a gap. A consumer driving a live
            # display froze while the run was perfectly healthy. A CLI
            # printing summary.intervals at the end never saw any of it,
            # because _build_intervals() re-buckets from scratch.
            #
            # Closing on elapsed time is safe, not merely convenient:
            # completed_at_offset_s is computed by _offset() INSIDE the same
            # `async with lock` that appends the result, so anything
            # appended from now on carries an offset >= now. No result can
            # land in a window whose boundary is already in the past.
            #
            # max() with `latest` covers emit(final=True), which is called
            # after the run has stopped: a result that completed in the
            # final partial window must still be flushed even though the
            # clock has moved past it.
            now = max(self._offset(), latest)
            i = 0
            while True:
                boundary = (window + 1) * bucket_s
                if not final and now < boundary:
                    break
                if final and i >= len(pending) and boundary > now:
                    break
                batch = []
                while i < len(pending) and pending[i].completed_at_offset_s < boundary:
                    batch.append(pending[i])
                    i += 1
                if batch:
                    results = [tr.result for tr in batch]
                    analyzer = HTTPAnalyzer(
                        results, expected_statuses=self.expected_statuses
                    )
                    tsl = analyzer.get_target_statistics()
                    interval = IntervalStats(
                        window_index=window,
                        stats=tsl[0] if tsl else _empty_target_stats(self.target),
                        status_code_distribution=(
                            analyzer.get_status_code_distribution()
                        ),
                    )

                    _invoke(interval)
                elif self.emit_empty_intervals:
                    # A window that closed with no completions. window_index
                    # already advances across these (that is what makes it
                    # mean "seconds since run start"); this just lets a
                    # display consumer see the tick. Zeroed stats are the
                    # honest report: nothing finished in this second.
                    _invoke(
                        IntervalStats(
                            window_index=window,
                            stats=_empty_target_stats(self.target),
                            status_code_distribution=[],
                        )
                    )
                window += 1
            cursor += i

        try:
            while not stop_event.is_set():
                await asyncio.sleep(bucket_s)
                await emit(final=False)
        except asyncio.CancelledError:
            pass
        await emit(final=True)  # flush the trailing partial window
        return errors

    def _start_stream(
        self,
        timed_results: List[_TimedResult],
        lock: asyncio.Lock,
        stop_event: asyncio.Event,
    ) -> Optional["asyncio.Task[int]"]:
        """0.5.2 — start the interval streamer, if a callback was supplied."""
        if self.on_interval is None:
            return None
        return asyncio.create_task(
            self._stream_intervals(timed_results, lock, stop_event)
        )

    async def _stop_stream(
        self, task: Optional["asyncio.Task[int]"], graceful_stop_s: float = 0.0
    ) -> int:
        """0.5.2 — stop the streamer and return its swallowed-error count.

        Bounded wait: the streamer only sleeps and calls user code, so it
        should end promptly, but it is not allowed to hold up the summary.
        """
        if task is None:
            return 0
        try:

            # return await asyncio.wait_for(task, timeout=self.interval_bucket_s * 3)
            # --- 0.5.2: the timeout is the larger of a few interval buckets
            # and the run's own graceful-stop budget. A synchronous
            # on_interval callback (a database write per interval, say) can
            # legitimately exceed three buckets, and cutting it off silently
            # discarded the final window. A timeout now counts as a stream
            # error rather than reporting 0, so a lost window is visible in
            # RunCounters.stream_errors.
            timeout = max(self.interval_bucket_s * 3, graceful_stop_s)
            return await asyncio.wait_for(task, timeout=timeout)
        except asyncio.TimeoutError:
            task.cancel()
            return 1
        except asyncio.CancelledError:
            return 0

    def _summary_identity(self) -> Dict[str, Any]:
        """--- 0.5.2: the run-invariant fields every _summarize() call passes.

        One helper rather than five repeated keyword arguments across three
        methods — the three run_* paths must never disagree about the bucket
        width or the worker labels they report, and per-call duplication is
        exactly how _build_intervals ended up on a different grid from
        _stream_intervals in the first place.
        """
        return {
            "interval_bucket_s": self.interval_bucket_s,
            "worker_id": self.worker_id,
            "region": self.region,
            "start_offset_s": self._start_offset_s,
            "clock_offset_s": self.clock_offset_s,
        }

    def _finish(self, summary: LoadTestSummary) -> LoadTestSummary:
        """0.5.2 — apply retain_results after stats/intervals are computed."""
        if not self.retain_results:
            summary.results = []
        return summary

    async def _drain(
        self,
        tasks: List["asyncio.Task[None]"],
        graceful_stop_s: float,
    ) -> Tuple[int, int]:
        """0.5.2: stop workers with a deadline. Returns
        (interrupted, worker_errors).

        Two problems this replaces. First, run_throughput awaited
        asyncio.gather(*in_flight) with no timeout, and run_ramp_up did the
        same with return_exceptions=True: a single request that never returned
        hung the entire run with no way out. Second, return_exceptions=True
        swallowed worker exceptions entirely, so a slot worker that died took
        its share of the concurrency with it and nothing reported that the run
        had quietly been executing at lower load than requested.
        """
        if not tasks:
            return 0, 0
        pending = [t for t in tasks if not t.done()]
        if pending and graceful_stop_s > 0:
            _, still_pending = await asyncio.wait(pending, timeout=graceful_stop_s)
            pending = list(still_pending)
        interrupted = len(pending)
        for t in pending:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        errors = 0
        for t in tasks:
            if t.cancelled():
                continue
            exc = t.exception()
            if exc is not None and not isinstance(exc, asyncio.CancelledError):
                errors += 1
        return interrupted, errors

    async def _connections_opened_since(self) -> int:
        """0.5.2: connections opened during THIS run only."""
        return max(0, await self._raw_connections_opened() - self._conn_baseline)

    async def close(self) -> None:
        await self.engine.close()

    # ------------------------------------------------------------------
    # Item 1 — RPS throughput measurement
    # ------------------------------------------------------------------

    @_exclusive  # --- 0.5.2
    async def run_throughput(
        self,
        duration_s: float = 10.0,
        max_concurrency: int = 200,
        graceful_stop_s: float = 30.0,
        # --- 0.5.2: shared wall-clock start epoch; see _begin_run. Appended
        # last and defaulted, so existing positional calls are unaffected.
        start_at: Optional[float] = None,
        warmup_requests: int = 0,  # --- 0.5.2: see warmup()
    ) -> LoadTestSummary:
        """Saturate the target with `max_concurrency` concurrent requests for
        `duration_s` and report the achieved RPS.

        0.5.2 (rewritten). The old driver loop was:

            while time.perf_counter() < stop_at:
                in_flight = [t for t in in_flight if not t.done()]
                if len(in_flight) < max_concurrency:
                    in_flight.append(asyncio.create_task(worker()))
                else:
                    await asyncio.sleep(0)

        Three problems. asyncio.sleep(0) yields and reschedules immediately, so
        the driver spun hot for the whole test, competing with the very
        requests it was measuring for event-loop time and inflating TTFB. The
        list comprehension ran once per iteration, making the loop O(n^2) in
        completed requests. And a fresh Task was allocated per request rather
        than reused.

        Now it uses the same fixed slot-worker pattern as run_ramp_up: exactly
        `max_concurrency` long-lived workers, each issuing back-to-back
        requests until stop_event is set. The worker count IS the concurrency
        bound, so the old per-worker semaphore is gone — it was a third
        redundant limit on top of the in_flight cap and the engine's own
        max_concurrent.
        """
        await self._begin_run(start_at, warmup_requests)
        timed_results: List[_TimedResult] = []
        lock = asyncio.Lock()
        stop_event = asyncio.Event()
        started = 0

        # --- 0.5.2: under an epoch the run ends at the ABSOLUTE instant
        # start_at + duration_s, matching run_sustained's stop_at. It used to
        # sleep duration_s from wherever the barrier released, so a worker that
        # joined 2s late ran 2s past everyone else; merge_summaries takes
        # max(duration_s) as the shared window, so that worker stretched the
        # window while contributing nothing to its tail and diluted the merged
        # achieved_rps. A late worker now runs shorter, which is the honest
        # reading of a synchronised run.
        #
        # max(0.0, ...): a worker more than duration_s late does no work and
        # reports it, rather than running a full-length shifted test that
        # cannot be merged meaningfully with anything.
        run_for = duration_s
        if self._epoch is not None:
            run_for = max(0.0, (self._start_time + duration_s) - time.perf_counter())

        async def slot_worker() -> None:
            nonlocal started
            while not stop_event.is_set():
                started += 1
                result = await self.engine.request_single(self.target)
                async with lock:
                    timed_results.append(_TimedResult(result, self._offset()))

        stream = self._start_stream(timed_results, lock, stop_event)
        slots = [asyncio.create_task(slot_worker()) for _ in range(max_concurrency)]
        try:
            await asyncio.sleep(run_for)  # --- 0.5.2: absolute under an epoch
        finally:
            stop_event.set()
        interrupted, errors = await self._drain(slots, graceful_stop_s)
        stream_errors = await self._stop_stream(stream, graceful_stop_s)

        actual_duration = self._offset()
        opened = await self._connections_opened_since()
        summary = _summarize(
            LoadTestMode.THROUGHPUT,
            self.target,
            actual_duration,
            timed_results,
            target_rps=None,
            connections_opened=opened,
            expected_statuses=self.expected_statuses,
            # Saturation mode has no schedule, so scheduled == started.
            counters=RunCounters(
                scheduled=started,
                started=started,
                interrupted=interrupted,
                worker_errors=errors,
                stream_errors=stream_errors,
            ),
            start_epoch=self._epoch,  # --- 0.5.2
            **self._summary_identity(),  # --- 0.5.2
        )
        return self._finish(summary)

    # ------------------------------------------------------------------
    # Item 2 — Sustained load: N requests over T seconds, at a fixed rate
    # ------------------------------------------------------------------

    @_exclusive  # --- 0.5.2
    async def run_sustained(
        self,
        target_rps: float,
        duration_s: float,
        max_concurrency: Optional[int] = None,
        max_backlog: Optional[int] = None,
        graceful_stop_s: float = 30.0,
        # --- 0.5.2: shared wall-clock start epoch; see _begin_run. Note that
        # under an epoch the run's end becomes an absolute deadline at
        # start_at + duration_s, so all workers stop together.
        start_at: Optional[float] = None,
        warmup_requests: int = 0,  # --- 0.5.2: see warmup()
    ) -> LoadTestSummary:
        """Fire requests at a fixed target_rps for duration_s.

        0.5.2 (rewritten). The old version did:

            in_flight.append(asyncio.create_task(worker()))
            next_fire += interval

        with `next_fire` advancing unconditionally and workers queueing on a
        semaphore. When the target slowed below target_rps this accumulated
        debt and then fired a catch-up burst as fast as the loop allowed,
        while in_flight grew without bound behind the semaphore — and the
        summary reported none of it. At 5k RPS it also allocated 5000 Tasks
        per second, competing with the requests being measured.

        Now: a fixed pool of `max_concurrency` workers pulls scheduled fire
        times off a bounded queue. When every worker is busy and the queue is
        full, the fire is DROPPED and counted rather than silently backlogged
        (this is k6's dropped_iterations). Each result also records how long
        it waited between its scheduled time and actually being sent, which is
        the coordinated-omission correction: without it, a degrading target
        produces better-looking percentiles because latency is measured from
        send rather than from when the request was due.
        """
        if target_rps <= 0:
            raise ValueError("target_rps must be > 0")

        cap = max_concurrency or max(int(target_rps * 2), 10)
        # Default backlog of one queued fire per worker: enough to absorb
        # normal jitter, small enough that sustained overload shows up as
        # `dropped` within a second or two instead of unbounded memory growth.
        backlog = cap if max_backlog is None else max_backlog

        timed_results: List[_TimedResult] = []
        lock = asyncio.Lock()
        stop_event = asyncio.Event()
        queue: "asyncio.Queue[float]" = asyncio.Queue(maxsize=max(1, backlog))
        scheduled = 0
        started = 0
        dropped = 0

        async def worker() -> None:
            nonlocal started
            while True:
                scheduled_at = await queue.get()
                try:
                    # --- 0.5.2: a sentinel retires this worker cleanly.
                    # Previously workers blocked forever on queue.get() after
                    # the run ended and were cancelled by _drain, so EVERY
                    # idle worker was counted as `interrupted`: a healthy
                    # 20-worker run reported interrupted=20 with dropped=0,
                    # while run_throughput reported 0 for the identical
                    # situation.
                    if scheduled_at == _STOP_SENTINEL or stop_event.is_set():
                        return
                    start_offset = self._offset()
                    started += 1
                    result = await self.engine.request_single(self.target)
                    async with lock:
                        timed_results.append(
                            _TimedResult(
                                result,
                                self._offset(),
                                scheduled_at_offset_s=scheduled_at,
                                queue_delay_ms=(start_offset - scheduled_at) * 1000,
                            )
                        )
                finally:
                    queue.task_done()

        await self._begin_run(start_at, warmup_requests)
        interval = 1.0 / target_rps
        # Under an epoch this is an absolute deadline (start_at + duration_s)
        # in perf_counter terms — see _begin_run.
        stop_at = self._start_time + duration_s
        stream = self._start_stream(timed_results, lock, stop_event)
        workers = [asyncio.create_task(worker()) for _ in range(cap)]

        next_fire = self._start_time
        # --- 0.5.2: a worker that joins a synchronised run late must NOT
        # replay the fires it missed. Without this, next_fire starts in the
        # past and the loop issues every elapsed slot back-to-back as fast as
        # the queue accepts them — the exact catch-up burst this method was
        # rewritten to remove, just sourced from clock skew instead of from a
        # slow target. Advance to the first slot that has not already passed.
        #
        # Guarded on _epoch: on the default path _start_time was read
        # microseconds ago, and flooring there would silently drop the run's
        # first fire.
        #
        # Slots skipped this way are NOT counted in `dropped`. `dropped` means
        # "the queue was full", i.e. the load could not be absorbed; these were
        # never offered at all. Conflating the two would repeat the
        # completed/responded mistake. The lateness stays visible as
        # start_epoch plus a first result offset well above zero.
        if self._epoch is not None:
            now = time.perf_counter()
            if next_fire < now:
                next_fire += math.floor((now - next_fire) / interval) * interval
        while next_fire < stop_at:
            now = time.perf_counter()
            if now < next_fire:
                await asyncio.sleep(next_fire - now)
            scheduled += 1
            try:
                queue.put_nowait(next_fire - self._start_time)
            except asyncio.QueueFull:
                dropped += 1
            next_fire += interval

        # Let already-queued work finish before pulling the plug.
        if graceful_stop_s > 0:
            try:
                await asyncio.wait_for(queue.join(), timeout=graceful_stop_s)
            except asyncio.TimeoutError:
                pass
        stop_event.set()

        # --- 0.5.2: retire idle workers with one sentinel each before
        # draining, so only genuinely in-flight requests land in
        # `interrupted`. Awaiting put() cannot deadlock: workers consume
        # sentinels and free queue slots as we go. The outer timeout guards
        # the case where every worker is stuck in a request that never
        # returns.
        async def _retire_workers() -> None:
            for _ in workers:
                await queue.put(_STOP_SENTINEL)

        try:
            await asyncio.wait_for(_retire_workers(), timeout=max(graceful_stop_s, 1.0))
        except asyncio.TimeoutError:
            pass
        interrupted, errors = await self._drain(
            workers, graceful_stop_s=max(graceful_stop_s, 1.0)
        )
        stream_errors = await self._stop_stream(stream, graceful_stop_s)

        actual_duration = self._offset()
        opened = await self._connections_opened_since()
        summary = _summarize(
            LoadTestMode.SUSTAINED,
            self.target,
            actual_duration,
            timed_results,
            target_rps=target_rps,
            connections_opened=opened,
            expected_statuses=self.expected_statuses,
            counters=RunCounters(
                scheduled=scheduled,
                started=started,
                dropped=dropped,
                paced=True,  # --- 0.5.2: only run_sustained has a schedule
                interrupted=interrupted,
                worker_errors=errors,
                stream_errors=stream_errors,
            ),
            start_epoch=self._epoch,  # --- 0.5.2
            **self._summary_identity(),  # --- 0.5.2
        )
        return self._finish(summary)

    # ------------------------------------------------------------------
    # Item 3 — Ramp-up mode: gradually increase concurrency, then hold
    # ------------------------------------------------------------------

    @_exclusive  # --- 0.5.2
    async def run_ramp_up(
        self,
        start_concurrency: int,
        max_concurrency: int,
        ramp_duration_s: float,
        hold_duration_s: float = 0.0,
        step_interval_s: float = 1.0,
        max_total_rps: Optional[float] = None,
        graceful_stop_s: float = 30.0,
        # --- 0.5.2: shared wall-clock start epoch; see _begin_run.
        start_at: Optional[float] = None,
        warmup_requests: int = 0,  # --- 0.5.2: see warmup()
    ) -> LoadTestSummary:
        """Step concurrency up linearly from start_concurrency to
        max_concurrency over ramp_duration_s, then hold at max_concurrency
        for hold_duration_s. Each concurrency "slot" keeps issuing
        back-to-back requests for as long as it's alive, so RPS scales with
        concurrency naturally rather than being separately paced.

        max_total_rps is a safety ceiling, not a target rate (use
        run_sustained for that). It exists because, unlike run_throughput
        (bounded by its semaphore) and run_sustained (bounded by its pacer),
        nothing here otherwise limits how fast slots fire against a very
        fast target (e.g. localhost, a CDN edge, or a mocked client in
        tests) — a single slot can spin as fast as the event loop allows.
        Default ceiling is generous (concurrency * 50 rps) so it only
        kicks in for genuinely pathological cases; pass None to disable.
        """
        if start_concurrency < 1:
            raise ValueError("start_concurrency must be >= 1")
        if max_concurrency < start_concurrency:
            raise ValueError("max_concurrency must be >= start_concurrency")

        await self._begin_run(start_at, warmup_requests)
        timed_results: List[_TimedResult] = []
        lock = asyncio.Lock()
        stop_event = asyncio.Event()

        # --- 0.5.2: absolute deadline under an epoch, for the same reason as
        # run_throughput — a late worker must run shorter, not later, or it
        # stretches merge_summaries' shared window past the point every other
        # worker stopped. In perf_counter terms; None means the unsynchronised
        # path, where the phase sleeps are used unmodified.
        deadline: Optional[float] = None
        if self._epoch is not None:
            deadline = self._start_time + ramp_duration_s + hold_duration_s

        async def _sleep_bounded(seconds: float) -> bool:
            """Sleep, but never past the shared deadline. Returns False once
            the deadline is reached, so the caller stops stepping."""
            if deadline is None:
                await asyncio.sleep(seconds)
                return True
            remaining = deadline - time.perf_counter()
            if remaining <= 0:
                return False
            await asyncio.sleep(min(seconds, remaining))
            return remaining > seconds

        num_steps = max(1, int(ramp_duration_s // step_interval_s))
        concurrency_delta = max_concurrency - start_concurrency

        # Safety ceiling: a simple shared token bucket. Default scales with
        # max_concurrency so normal (real-latency) runs never touch it —
        # it's only a backstop against a runaway fast target.
        effective_ceiling = (
            max_total_rps if max_total_rps is not None else max_concurrency * 50
        )
        ceiling_interval = 1.0 / effective_ceiling if effective_ceiling > 0 else 0.0
        _next_allowed_fire = time.perf_counter()
        _ceiling_lock = asyncio.Lock()

        async def _throttle() -> None:
            """Blocks until the shared rate ceiling allows another request.
            No-op (modulo the lock) once real request latency already keeps
            the aggregate rate under the ceiling.

            0.5.2: the slot is reserved inside the lock, but the
            sleep happens OUTSIDE it. The previous version awaited
            asyncio.sleep(wait) while still holding _ceiling_lock, which
            serialised every slot behind one waiter: slot B could not even
            compute its own deadline until slot A's sleep had finished, so N
            slots waiting produced N additive delays instead of N overlapping
            ones. The effective ceiling was therefore far below
            effective_ceiling at high concurrency, silently throttling runs
            that should never have touched the backstop at all.
            """
            nonlocal _next_allowed_fire
            if ceiling_interval <= 0:
                return
            async with _ceiling_lock:
                fire_at = max(time.perf_counter(), _next_allowed_fire)
                _next_allowed_fire = fire_at + ceiling_interval
            wait = fire_at - time.perf_counter()
            if wait > 0:
                await asyncio.sleep(wait)

        started = 0

        async def slot_worker() -> None:
            nonlocal started
            while not stop_event.is_set():
                await _throttle()
                started += 1
                result = await self.engine.request_single(self.target)
                async with lock:
                    timed_results.append(_TimedResult(result, self._offset()))

        stream = self._start_stream(timed_results, lock, stop_event)
        active_slots: List[asyncio.Task[None]] = []

        def target_concurrency_at_step(step: int) -> int:
            if num_steps <= 1:
                return max_concurrency
            frac = step / (num_steps - 1)
            return start_concurrency + int(round(concurrency_delta * frac))

        # --- 0.5.2: `ran_out` short-circuits the remaining ramp steps once the
        # shared deadline has passed. A late worker then ramps as far as the
        # time it has allows and stops with everyone else, rather than
        # completing a full-length ramp that finishes after the window closed.
        ran_out = False

        for step in range(num_steps):
            desired = target_concurrency_at_step(step)
            while len(active_slots) < desired:
                active_slots.append(asyncio.create_task(slot_worker()))
            if step < num_steps - 1:
                if not await _sleep_bounded(step_interval_s):
                    ran_out = True
                    break

        if not ran_out:
            while len(active_slots) < max_concurrency:
                active_slots.append(asyncio.create_task(slot_worker()))

            if hold_duration_s > 0:
                await _sleep_bounded(hold_duration_s)

        stop_event.set()
        # 0.5.2 — replaces asyncio.gather(..., return_exceptions=True), which
        # had no timeout (one hung request hung the run) and discarded worker
        # exceptions (a dead slot silently lowered concurrency).
        interrupted, errors = await self._drain(active_slots, graceful_stop_s)
        stream_errors = await self._stop_stream(stream, graceful_stop_s)
        actual_duration = self._offset()
        opened = await self._connections_opened_since()
        summary = _summarize(
            LoadTestMode.RAMP_UP,
            self.target,
            actual_duration,
            timed_results,
            target_rps=None,
            connections_opened=opened,
            expected_statuses=self.expected_statuses,
            counters=RunCounters(
                scheduled=started,
                started=started,
                interrupted=interrupted,
                worker_errors=errors,
                stream_errors=stream_errors,
            ),
            start_epoch=self._epoch,  # --- 0.5.2
            **self._summary_identity(),  # --- 0.5.2
        )
        return self._finish(summary)


# ---------------------------------------------------------------------------
# --- 0.5.2 — distributed aggregation
# ---------------------------------------------------------------------------

# Two workers are considered to share an epoch if their start_epoch values
# agree to within a millisecond. Not exact equality: the orchestrator
# broadcasts one float, but it may round-trip through Postgres `timestamptz`
# (microsecond precision) or JSON before coming back, and a sub-millisecond
# difference cannot misalign a bucket whose default width is one second. A
# difference LARGER than this means the workers were not actually
# synchronised, and their offsets are not comparable.
# --- 0.5.2: metric names LoadTestSummary.metric_namespace adds on top of the
# core set, for parse-time --threshold validation in the CLI. See
# analysis.core_metric_names for why the combined set is a superset rather than
# an exact per-run one.
LOAD_TEST_EXTRA_METRICS = frozenset(
    {
        "achieved_rps",
        "target_rps",
        "dropped",
        "dropped_rate",
        "interrupted",
        "worker_errors",
        "avg_queue_delay_ms",
        "max_queue_delay_ms",
        "avg_admission_wait_ms",
        "connection_reuse_rate_fraction",
        "received_bytes_per_s",
        "sent_bytes_per_s",
    }
)


def known_metric_names() -> FrozenSet[str]:
    """--- 0.5.2: core metrics plus the load-test-only ones. The set the CLI
    validates --threshold names against."""
    return core_metric_names() | LOAD_TEST_EXTRA_METRICS


_EPOCH_TOLERANCE_S = 1e-3

# --- 0.5.2: how far a worker's clock may sit from the coordinator's before the
# run is not a synchronised run at all. 50 ms is well inside a 1s interval
# bucket but far enough outside normal NTP discipline (single-digit ms on a
# datacentre host) that exceeding it means something is actually wrong.
_CLOCK_SKEW_TOLERANCE_S = 50e-3


@dataclass
class ClockCheck:
    """--- 0.5.2: one NTP-style clock comparison against a remote worker.

    offset_s  the worker's clock minus the coordinator's. Positive means the
              worker is ahead and will fire the barrier early.
    rtt_s     round trip of the probe. The offset is only trustworthy to about
              +/- rtt_s/2, so a large RTT means large uncertainty, not large
              skew — report both or neither.
    """

    offset_s: float
    rtt_s: float

    @property
    def within_tolerance(self) -> bool:
        return abs(self.offset_s) <= _CLOCK_SKEW_TOLERANCE_S


async def measure_clock_offset(
    remote_now: Callable[[], Awaitable[float]],
    samples: int = 5,
) -> ClockCheck:
    """--- 0.5.2: estimate a remote worker's clock offset, NTP-style.

    This is the check start_epoch agreement cannot perform. Every worker echoes
    back the epoch it was handed, so merge_summaries comparing those values only
    ever proves they were all told the same thing. A node whose clock runs
    200 ms fast genuinely starts 200 ms early, reports the agreed epoch, and
    passes the tolerance check with misaligned data.

    `remote_now` is a coroutine returning the worker's time.time(). It is
    supplied by the caller rather than implemented here on purpose: the OSS
    layer has no transport and should not grow one, while a SaaS layer already
    has a path to each node. Both then share this arithmetic instead of each
    writing their own.

        offset = t_remote - (t_before + t_after) / 2
        rtt    = t_after - t_before

    The best of `samples` probes is kept — lowest RTT, since RTT is the whole
    error term. Feed the result to LoadTestEngine(clock_offset_s=...) and it
    travels with every summary that worker produces.
    """
    best: Optional[ClockCheck] = None
    for _ in range(max(1, samples)):
        t_before = time.time()
        t_remote = await remote_now()
        t_after = time.time()
        check = ClockCheck(
            offset_s=t_remote - (t_before + t_after) / 2.0,
            rtt_s=t_after - t_before,
        )
        if best is None or check.rtt_s < best.rtt_s:
            best = check
    assert best is not None  # samples >= 1
    return best


def _weighted_mean(pairs: Sequence[Tuple[float, float]]) -> float:
    """--- 0.5.2: (value, weight) -> weighted mean; 0.0 if no usable weight.

    Averaging per-worker averages unweighted is the same class of error as
    averaging per-worker p95s: a worker that served 10 requests would count as
    much as one that served 10,000. Pairs with a non-positive weight are
    dropped rather than contributing zero, which is also what keeps a NaN
    latency mean from a zero-sample worker out of the result — that worker's
    weight is 0 by construction. NaN values are dropped defensively too.
    """
    usable = [(v, w) for v, w in pairs if w > 0 and not math.isnan(v)]
    total_weight = sum(w for _, w in usable)
    if total_weight <= 0:
        return 0.0
    return sum(v * w for v, w in usable) / total_weight


def _weighted_mode(pairs: Sequence[Tuple[Optional[str], float]]) -> Optional[str]:
    """--- 0.5.2: the most-represented string across workers.

    TargetStats fields like cdn_fingerprint are already a mode over one
    worker's requests, and the underlying per-request values are gone by the
    time summaries are merged. Weighting each worker's answer by its request
    count is the closest recoverable approximation to a mode over the union.
    """
    totals: Dict[str, float] = {}
    for value, weight in pairs:
        if value is None or weight <= 0:
            continue
        totals[value] = totals.get(value, 0.0) + weight
    if not totals:
        return None
    return max(totals.items(), key=lambda kv: kv[1])[0]


def _merge_status_distribution(
    distributions: Sequence[List[Dict[str, Any]]], total_requests: int
) -> List[Dict[str, Any]]:
    """--- 0.5.2: fold per-worker status-code breakdowns into one.

    Counts sum; `pct` is RECOMPUTED against the merged request total rather
    than averaged, since each worker's pct has a different denominator.
    """
    counts: Dict[int, int] = {}
    for dist in distributions:
        for row in dist:
            code = int(row["status_code"])
            counts[code] = counts.get(code, 0) + int(row["count"])
    merged = [
        {
            "status_code": code,
            "count": count,
            "pct": (
                round(count / total_requests * 100, 2) if total_requests > 0 else 0.0
            ),
        }
        for code, count in counts.items()
    ]
    # Same ordering as get_status_code_distribution(): most frequent first.
    merged.sort(key=lambda row: (-int(row["count"]), int(row["status_code"])))
    return merged


def _merge_target_stats(target: str, parts: Sequence[TargetStats]) -> TargetStats:
    """--- 0.5.2: combine per-worker TargetStats into one.

    Used for both the overall merged stats and for each aligned interval
    window, so the two can never disagree about how a field is combined.

    Three classes of field, treated differently on purpose:

      EXACT      Counts and byte totals are summed. Rates whose denominator is
                 also being summed (success_rate, transport_error_rate,
                 http2_rate, connection_reuse_rate, ...) are recovered exactly
                 by weighting each worker's rate by that same denominator:
                 sum(rate_i * n_i) / sum(n_i) == sum(count_i) / sum(n_i).
                 min/max latency and the mean come from the merged histogram,
                 which tracks them exactly rather than in buckets.

      APPROXIMATE  median/p95/p99 latency are recomputed from the MERGED
                 histogram — the whole reason LatencyHistogram exists. These
                 are correct in kind (a real percentile over the union) and
                 accurate to the histogram's bucket resolution, under 0.8% by
                 default. Some averages (avg_blocked_ms, avg_ttfb_ms,
                 avg_redirect_time_ms, avg_upload_throughput_mbps,
                 avg_compressed_size_bytes) have a narrower true denominator
                 than responded_requests — only the requests that actually had
                 that phase, redirect or upload — and that count is not carried
                 on TargetStats. They are weighted by responded_requests, which
                 is exact when every responded request contributed a sample and
                 slightly off otherwise.

      NOT MERGED  std_latency, jitter, consistency_score, p95_ttfb_ms,
                 p95_duration_ms, p95_blocked_ms and p95_waiting_ms are left at
                 0.0. Only total_ms has a mergeable histogram; there is no
                 arithmetic that recovers a phase percentile or a standard
                 deviation from per-worker summaries, and inventing one is
                 precisely the accuracy bug this whole mechanism exists to
                 avoid. Read them from the individual worker summaries, which
                 still carry exact values, or add per-phase histograms if they
                 need to survive a merge.

    CAUTION: 0.0 is the same value TargetStats uses for "no samples", so a
    threshold like `p95_waiting_ms<500` will PASS vacuously against a merged
    summary. Evaluate phase thresholds per worker, not on the merge.
    """
    total = sum(s.total_requests for s in parts)
    if total == 0:
        return _empty_target_stats(target)

    successful = sum(s.successful_requests for s in parts)
    responded = sum(s.responded_requests for s in parts)
    connections = sum(s.connections_measured for s in parts)
    dns_lookups = sum(s.dns_lookups_measured for s in parts)

    # The mergeable distribution. merge_all() raises on mismatched bucket
    # layouts; that propagates deliberately rather than being papered over.
    histograms = [s.latency_histogram for s in parts if s.latency_histogram is not None]
    histogram = LatencyHistogram.merge_all(histograms) if histograms else None

    if histogram is not None and histogram.count > 0:
        # min/max/mean are tracked exactly by the histogram, not bucketed.
        min_latency = histogram.min_ms if histogram.min_ms is not None else 0.0
        max_latency = histogram.max_ms if histogram.max_ms is not None else 0.0
        avg_latency = histogram.mean
        median_latency = histogram.quantile(0.5)
        p95_latency = histogram.quantile(0.95)
        p99_latency = histogram.quantile(0.99)
    else:
        # No histogram (older summaries, or no responded requests). Fall back
        # to what can still be combined honestly and leave percentiles unset
        # rather than averaging them.
        lat_mins = [
            s.min_latency
            for s in parts
            if s.responded_requests > 0 and not math.isnan(s.min_latency)
        ]
        lat_maxs = [
            s.max_latency
            for s in parts
            if s.responded_requests > 0 and not math.isnan(s.max_latency)
        ]
        min_latency = min(lat_mins) if lat_mins else 0.0
        max_latency = max(lat_maxs) if lat_maxs else 0.0
        avg_latency = _weighted_mean(
            [(s.avg_latency, s.responded_requests) for s in parts]
        )
        median_latency = 0.0
        p95_latency = 0.0
        p99_latency = 0.0

    def by_responded(getter: Any) -> float:
        return _weighted_mean([(getter(s), s.responded_requests) for s in parts])

    def by_total(getter: Any) -> float:
        return _weighted_mean([(getter(s), s.total_requests) for s in parts])

    cert_days = [
        s.cert_expiry_days_min for s in parts if s.cert_expiry_days_min is not None
    ]
    methods = [s.method for s in parts if s.method]

    return TargetStats(
        target=target,
        method=methods[0] if methods else "",
        total_requests=total,
        successful_requests=successful,
        success_rate=(successful / total * 100) if total > 0 else 0.0,
        min_latency=min_latency,
        max_latency=max_latency,
        avg_latency=avg_latency,
        median_latency=median_latency,
        # Not mergeable — see the docstring.
        std_latency=0.0,
        p95_latency=p95_latency,
        p99_latency=p99_latency,
        jitter=0.0,
        consistency_score=0.0,
        avg_ttfb_ms=by_responded(lambda s: s.avg_ttfb_ms),
        p95_ttfb_ms=0.0,
        http2_rate=by_responded(lambda s: s.http2_rate),
        redirect_rate=by_total(lambda s: s.redirect_rate),
        avg_response_size_bytes=by_responded(lambda s: s.avg_response_size_bytes),
        avg_duration_ms=by_responded(lambda s: s.avg_duration_ms),
        p95_duration_ms=0.0,
        avg_blocked_ms=by_responded(lambda s: s.avg_blocked_ms),
        p95_blocked_ms=0.0,
        avg_admission_wait_ms=by_responded(lambda s: s.avg_admission_wait_ms),
        avg_sending_ms=by_responded(lambda s: s.avg_sending_ms),
        avg_waiting_ms=by_responded(lambda s: s.avg_waiting_ms),
        p95_waiting_ms=0.0,
        avg_receiving_ms=by_responded(lambda s: s.avg_receiving_ms),
        connections_measured=connections,
        latency_overflow_count=sum(s.latency_overflow_count for s in parts),
        # Denominators of their own, not responded_requests.
        avg_dns_ms=_weighted_mean(
            [(s.avg_dns_ms, s.dns_lookups_measured) for s in parts]
        ),
        dns_lookups_measured=dns_lookups,
        avg_tcp_ms=_weighted_mean(
            [(s.avg_tcp_ms, s.connections_measured) for s in parts]
        ),
        avg_tls_ms=_weighted_mean(
            [(s.avg_tls_ms, s.connections_measured) for s in parts]
        ),
        avg_compressed_size_bytes=by_responded(lambda s: s.avg_compressed_size_bytes),
        avg_redirect_time_ms=by_responded(lambda s: s.avg_redirect_time_ms),
        http2_downgrade_rate=by_responded(lambda s: s.http2_downgrade_rate),
        cache_control_present=sum(s.cache_control_present for s in parts),
        etag_present=sum(s.etag_present for s in parts),
        last_modified_present=sum(s.last_modified_present for s in parts),
        age_present=sum(s.age_present for s in parts),
        hsts_present=sum(s.hsts_present for s in parts),
        csp_present=sum(s.csp_present for s in parts),
        cdn_fingerprint=_weighted_mode(
            [(s.cdn_fingerprint, s.responded_requests) for s in parts]
        ),
        server_header=_weighted_mode(
            [(s.server_header, s.responded_requests) for s in parts]
        ),
        cert_expiry_days_min=min(cert_days) if cert_days else None,
        alt_svc=_weighted_mode([(s.alt_svc, s.responded_requests) for s in parts]),
        ip_version=_weighted_mode(
            [(s.ip_version, s.responded_requests) for s in parts]
        ),
        connection_reuse_rate=by_responded(lambda s: s.connection_reuse_rate),
        tls_resumption_rate=by_responded(lambda s: s.tls_resumption_rate),
        http2_push_total=sum(s.http2_push_total for s in parts),
        avg_upload_throughput_mbps=by_responded(lambda s: s.avg_upload_throughput_mbps),
        latency_histogram=histogram,
        transport_error_rate=by_total(lambda s: s.transport_error_rate),
        unexpected_status_rate=by_total(lambda s: s.unexpected_status_rate),
        expected_response_rate=by_total(lambda s: s.expected_response_rate),
        responded_requests=responded,
        total_response_bytes=sum(s.total_response_bytes for s in parts),
        total_upload_bytes=sum(s.total_upload_bytes for s in parts),
    )


def merge_summaries(summaries: Sequence[LoadTestSummary]) -> LoadTestSummary:
    """--- 0.5.2: fold per-worker LoadTestSummary objects into one.

    This is the collector side of a distributed run: N LoadTestEngine
    instances, in separate processes or on separate machines, each given the
    same `start_at` epoch, each returning a LoadTestSummary. This turns those
    into a single summary that exporters, thresholds and the SaaS layer can
    consume unchanged.

    What it does NOT do, deliberately:

      * It does not average achieved_rps. Each worker's achieved_rps is over
        its own duration; summing or averaging them both give wrong answers
        when workers ran for different lengths. The merged summary instead
        carries summed requests and the synchronised wall window as
        duration_s, so the INHERITED achieved_rps property computes
        sum(total_requests) / window. There is no override — the existing
        property is already correct once its inputs are.

      * It does not average percentiles. p50/p95/p99 come from the merged
        LatencyHistogram. See _merge_target_stats for which fields survive a
        merge exactly, which are approximate, and which are not merged at all.

    The synchronised wall window is max(duration_s). Under a shared epoch each
    summary's duration_s is already "end offset since the epoch", so the union
    of the workers' activity is [0, max(end)) — this holds even when workers
    started late or ran for different lengths, which is exactly why item 1 is a
    prerequisite for item 2. With no epoch (all None, e.g. several engines in
    one process) max() is still the best available estimate, but it is an
    ESTIMATE: perf_counter origins differ per process, so the windows are only
    approximately aligned. Merging is allowed in that case because in-process
    engines really do start within microseconds of each other.

    Raises ValueError if the summaries do not describe one comparable run:
    mixed modes, mixed targets, or start epochs that disagree by more than a
    millisecond. This mirrors LatencyHistogram.merge refusing mismatched bucket
    layouts — a merge across incompatible inputs produces a plausible-looking
    number with no meaning, which is worse than an error.

    Merging a single summary returns it unchanged (identity), rather than
    round-tripping it through a lossy merge.
    """
    if not summaries:
        raise ValueError("merge_summaries requires at least one summary")
    if len(summaries) == 1:
        return summaries[0]

    modes = {s.mode for s in summaries}
    if len(modes) > 1:
        raise ValueError(
            "cannot merge LoadTestSummary objects from different modes "
            f"({sorted(m.value for m in modes)}) — dropped/scheduled are only "
            "meaningful for a paced run, so the combined counters would not "
            "describe anything"
        )
    targets = {s.target for s in summaries}
    if len(targets) > 1:
        raise ValueError(
            "cannot merge LoadTestSummary objects for different targets "
            f"({sorted(targets)}) — this is aggregation across targets, not a "
            "merge of one distributed run"
        )

    # --- 0.5.2: window_index is an INDEX, not a time. Folding intervals by
    # index across workers configured with different bucket widths lines up
    # "window 7" from a 1.0s grid with "window 7" from a 0.5s grid — two
    # different stretches of the run, silently averaged into a plausible
    # timeline. Same class of error as the epoch check below, and it was
    # missing.
    buckets = {round(s.interval_bucket_s, 9) for s in summaries}
    if len(buckets) > 1:
        raise ValueError(
            "cannot merge LoadTestSummary objects with different interval "
            f"bucket widths ({sorted(buckets)}) — window_index means a "
            "different number of seconds in each, so aligning by index folds "
            "unrelated slices of the run together"
        )

    # --- 0.5.2: the check start_epoch cannot perform. Every worker echoes the
    # epoch it was handed, so agreement there proves only that they were all
    # told the same thing; a worker whose clock is 200 ms fast starts 200 ms
    # early and still reports the agreed epoch. clock_offset_s is a MEASURED
    # quantity (see measure_clock_offset) and is checked when present. Absent
    # on every summary means unmeasured, not verified — merging stays allowed,
    # because refusing would break every local and in-process run, but nothing
    # here should be read as confirmation that the clocks agreed.
    skewed = [
        (s.worker_id or s.target, s.clock_offset_s)
        for s in summaries
        if s.clock_offset_s is not None
        and abs(s.clock_offset_s) > _CLOCK_SKEW_TOLERANCE_S
    ]
    if skewed:
        detail = ", ".join(
            f"{wid}: {off * 1000:+.1f} ms" for wid, off in skewed if off is not None
        )
        raise ValueError(
            f"measured clock skew exceeds {_CLOCK_SKEW_TOLERANCE_S * 1000:.0f} "
            f"ms ({detail}) — these workers agreed on a start_epoch but do not "
            "agree on what time it is, so they did not actually start together "
            "and their window_index values refer to different seconds"
        )

    epochs = [s.start_epoch for s in summaries]
    if any(e is None for e in epochs) and any(e is not None for e in epochs):
        raise ValueError(
            "cannot merge LoadTestSummary objects where some carry a "
            "start_epoch and some do not — their offsets are measured from "
            "different origins and their interval windows do not line up"
        )
    epoch: Optional[float] = None
    if epochs[0] is not None:
        known = [e for e in epochs if e is not None]
        spread = max(known) - min(known)
        if spread > _EPOCH_TOLERANCE_S:
            raise ValueError(
                f"start_epoch values disagree by {spread * 1000:.1f} ms "
                f"(tolerance {_EPOCH_TOLERANCE_S * 1000:.0f} ms) — these "
                "workers were not synchronised, so their window_index values "
                "refer to different seconds"
            )
        epoch = min(known)

    mode = summaries[0].mode
    target = summaries[0].target

    # The synchronised wall window — see the docstring.
    duration_s = max(s.duration_s for s in summaries)

    # Offered rate is additive: each worker was handed its share.
    offered = [s.target_rps for s in summaries if s.target_rps is not None]
    target_rps = sum(offered) if offered else None

    stats = _merge_target_stats(target, [s.stats for s in summaries])

    status_dist = _merge_status_distribution(
        [s.status_code_distribution for s in summaries], stats.total_requests
    )

    connection_reuse = ConnectionReuseStats(
        total_requests=sum(s.connection_reuse.total_requests for s in summaries),
        connections_opened=sum(
            s.connection_reuse.connections_opened for s in summaries
        ),
    )

    error_breakdown: Dict[str, int] = {}
    for s in summaries:
        for key, count in s.error_breakdown.items():
            error_breakdown[key] = error_breakdown.get(key, 0) + count

    # Queue delay: each result in a paced run carries one delay sample, so the
    # sample count per worker is its result count. Averaging the averages
    # unweighted would let a worker that completed 10 requests move the figure
    # as much as one that completed 10,000.
    counters = RunCounters(
        scheduled=sum(s.counters.scheduled for s in summaries),
        started=sum(s.counters.started for s in summaries),
        dropped=sum(s.counters.dropped for s in summaries),
        # all(), not any(): if even one worker was unpaced the combined
        # dropped denominator is not a schedule, and metric_namespace() should
        # omit dropped_rate so a threshold on it fails loudly rather than
        # passing against a denominator that cannot be non-zero.
        paced=all(s.counters.paced for s in summaries),
        interrupted=sum(s.counters.interrupted for s in summaries),
        worker_errors=sum(s.counters.worker_errors for s in summaries),
        stream_errors=sum(s.counters.stream_errors for s in summaries),
        avg_queue_delay_ms=_weighted_mean(
            [
                (s.counters.avg_queue_delay_ms, float(s.stats.total_requests))
                for s in summaries
            ]
        ),
        max_queue_delay_ms=max(
            (s.counters.max_queue_delay_ms for s in summaries), default=0.0
        ),
    )

    # Intervals aligned by window_index. Meaningful only because item 1 gave
    # every worker the same time origin: window 7 is the same second for all
    # of them. A window no worker reported stays absent rather than being
    # synthesised as a zero-dip, matching _build_intervals().
    by_window: Dict[int, List[IntervalStats]] = {}
    for s in summaries:
        for interval in s.intervals:
            by_window.setdefault(interval.window_index, []).append(interval)

    intervals: List[IntervalStats] = []
    for window_index in sorted(by_window):
        group = by_window[window_index]
        window_stats = _merge_target_stats(target, [iv.stats for iv in group])
        intervals.append(
            IntervalStats(
                window_index=window_index,
                stats=window_stats,
                status_code_distribution=_merge_status_distribution(
                    [iv.status_code_distribution for iv in group],
                    window_stats.total_requests,
                ),
            )
        )

    results: List[HTTPResult] = []
    for s in summaries:
        # Empty for any worker run with retain_results=False, which is the
        # expected setting for a distributed worker.
        results.extend(s.results)

    return LoadTestSummary(
        mode=mode,
        target=target,
        duration_s=duration_s,
        target_rps=target_rps,
        stats=stats,
        status_code_distribution=status_dist,
        connection_reuse=connection_reuse,
        intervals=intervals,
        results=results,
        counters=counters,
        error_breakdown=error_breakdown,
        start_epoch=epoch,
        merged=True,  # --- 0.5.2
        # --- 0.5.2
        interval_bucket_s=summaries[0].interval_bucket_s,  # validated equal above
        # A merged summary belongs to no single worker, so worker_id is
        # cleared. `region` is the exception: when every input came from one
        # region the merge is still that region's result, and dropping the
        # label would make a per-region roll-up unattributable.
        worker_id=None,
        region=(
            summaries[0].region if len({s.region for s in summaries}) == 1 else None
        ),
        # The worst lateness in the group. A merged window that starts at 0 but
        # whose slowest member joined at 2.4s is a run with a 2.4s hole in it,
        # and max() is what makes that a number instead of a shape.
        start_offset_s=max(s.start_offset_s for s in summaries),
        # Deliberately not propagated: offsets are per-worker and there is no
        # single value for the group. Read them from the individual summaries.
        clock_offset_s=None,
        # The merge is otherwise irrecoverably lossy about who contributed
        # what. This records at least the membership.
        merged_from=[s.worker_id or s.target for s in summaries],
    )
