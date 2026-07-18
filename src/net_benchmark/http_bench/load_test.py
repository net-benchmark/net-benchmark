"""
Load testing engine (0.5.1): throughput, sustained rate, ramp-up.
Stats reuse HTTPAnalyzer/TargetStats from analysis.py — no separate
percentile/latency implementation.
"""

import asyncio
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional

from net_benchmark.http_bench.analysis import HTTPAnalyzer, TargetStats
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
            "target_rps": self.target_rps,
            "achieved_rps": self.achieved_rps,
            "stats": vars(self.stats),
            "status_code_distribution": self.status_code_distribution,
            "connection_reuse": {
                "total_requests": self.connection_reuse.total_requests,
                "connections_opened": self.connection_reuse.connections_opened,
                "connections_reused": self.connection_reuse.connections_reused,
                "reuse_rate": self.connection_reuse.reuse_rate,
            },
            "intervals": [
                {
                    "window_index": iv.window_index,
                    "stats": vars(iv.stats),
                    "status_code_distribution": iv.status_code_distribution,
                }
                for iv in self.intervals
            ],
        }


@dataclass
class _TimedResult:
    result: HTTPResult
    completed_at_offset_s: float  # seconds since load test start


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
    timed_results: List[_TimedResult], bucket_s: float = 1.0
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
        analyzer = HTTPAnalyzer(bucket)
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
) -> LoadTestSummary:
    results = [tr.result for tr in timed_results]

    if results:
        analyzer = HTTPAnalyzer(results)
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
        intervals=_build_intervals(timed_results),
        results=results,
    )


# ---------------------------------------------------------------------------
# LoadTestEngine
# ---------------------------------------------------------------------------


class LoadTestEngine:
    """Wraps a single-target HTTPBenchmarkEngine with load-shaping strategies.

    One LoadTestEngine == one target. For multi-target load tests, construct
    one instance per target (each gets its own pooled client/transport via
    the underlying HTTPBenchmarkEngine, so origins never share connections).
    """

    def __init__(self, target: str, http_engine: Optional[HTTPBenchmarkEngine] = None):
        self.target = target
        # max_concurrent is set high by default here; individual run_* methods
        # bound actual in-flight concurrency themselves via their own
        # semaphores/pacing, so the engine-level cap just needs to not be the
        # bottleneck.
        self.engine = http_engine or HTTPBenchmarkEngine(max_concurrent=1000)
        self._start_time: float = 0.0

    def _offset(self) -> float:
        return time.perf_counter() - self._start_time

    async def _connections_opened(self) -> int:
        stats = self.engine.get_connection_stats(self.target)
        return int(stats["connections_opened"])

    async def close(self) -> None:
        await self.engine.close()

    # ------------------------------------------------------------------
    # Item 1 — RPS throughput measurement
    # ------------------------------------------------------------------

    async def run_throughput(
        self,
        duration_s: float = 10.0,
        max_concurrency: int = 200,
    ) -> LoadTestSummary:
        """Saturate the target with up to `max_concurrency` concurrent
        requests for `duration_s` and report the achieved RPS.
        """
        self._start_time = time.perf_counter()
        semaphore = asyncio.Semaphore(max_concurrency)
        timed_results: List[_TimedResult] = []
        lock = asyncio.Lock()
        stop_at = self._start_time + duration_s
        in_flight: List[asyncio.Task[None]] = []

        async def worker() -> None:
            async with semaphore:
                result = await self.engine.request_single(self.target)
                async with lock:
                    timed_results.append(_TimedResult(result, self._offset()))

        while time.perf_counter() < stop_at:
            in_flight = [t for t in in_flight if not t.done()]
            if len(in_flight) < max_concurrency:
                in_flight.append(asyncio.create_task(worker()))
            else:
                await asyncio.sleep(0)

        if in_flight:
            await asyncio.gather(*in_flight)

        actual_duration = self._offset()
        opened = await self._connections_opened()
        return _summarize(
            LoadTestMode.THROUGHPUT,
            self.target,
            actual_duration,
            timed_results,
            target_rps=None,
            connections_opened=opened,
        )

    # ------------------------------------------------------------------
    # Item 2 — Sustained load: N requests over T seconds, at a fixed rate
    # ------------------------------------------------------------------

    async def run_sustained(
        self,
        target_rps: float,
        duration_s: float,
        max_concurrency: Optional[int] = None,
    ) -> LoadTestSummary:
        """Fire requests at a fixed target_rps for duration_s using a simple
        token-bucket pacer.
        """
        if target_rps <= 0:
            raise ValueError("target_rps must be > 0")

        cap = max_concurrency or max(int(target_rps * 2), 10)
        semaphore = asyncio.Semaphore(cap)
        timed_results: List[_TimedResult] = []
        lock = asyncio.Lock()

        self._start_time = time.perf_counter()
        interval = 1.0 / target_rps
        stop_at = self._start_time + duration_s
        in_flight: List[asyncio.Task[None]] = []

        async def worker() -> None:
            async with semaphore:
                result = await self.engine.request_single(self.target)
                async with lock:
                    timed_results.append(_TimedResult(result, self._offset()))

        next_fire = self._start_time
        while next_fire < stop_at:
            now = time.perf_counter()
            if now < next_fire:
                await asyncio.sleep(next_fire - now)
            in_flight.append(asyncio.create_task(worker()))
            in_flight = [t for t in in_flight if not t.done()]
            next_fire += interval

        if in_flight:
            await asyncio.gather(*in_flight)

        actual_duration = self._offset()
        opened = await self._connections_opened()
        return _summarize(
            LoadTestMode.SUSTAINED,
            self.target,
            actual_duration,
            timed_results,
            target_rps=target_rps,
            connections_opened=opened,
        )

    # ------------------------------------------------------------------
    # Item 3 — Ramp-up mode: gradually increase concurrency, then hold
    # ------------------------------------------------------------------

    async def run_ramp_up(
        self,
        start_concurrency: int,
        max_concurrency: int,
        ramp_duration_s: float,
        hold_duration_s: float = 0.0,
        step_interval_s: float = 1.0,
        max_total_rps: Optional[float] = None,
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

        self._start_time = time.perf_counter()
        timed_results: List[_TimedResult] = []
        lock = asyncio.Lock()
        stop_event = asyncio.Event()

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
            the aggregate rate under the ceiling."""
            nonlocal _next_allowed_fire
            if ceiling_interval <= 0:
                return
            async with _ceiling_lock:
                now = time.perf_counter()
                wait = _next_allowed_fire - now
                if wait > 0:
                    await asyncio.sleep(wait)
                    now = time.perf_counter()
                _next_allowed_fire = max(now, _next_allowed_fire) + ceiling_interval

        async def slot_worker() -> None:
            while not stop_event.is_set():
                await _throttle()
                result = await self.engine.request_single(self.target)
                async with lock:
                    timed_results.append(_TimedResult(result, self._offset()))

        active_slots: List[asyncio.Task[None]] = []

        def target_concurrency_at_step(step: int) -> int:
            if num_steps <= 1:
                return max_concurrency
            frac = step / (num_steps - 1)
            return start_concurrency + int(round(concurrency_delta * frac))

        for step in range(num_steps):
            desired = target_concurrency_at_step(step)
            while len(active_slots) < desired:
                active_slots.append(asyncio.create_task(slot_worker()))
            if step < num_steps - 1:
                await asyncio.sleep(step_interval_s)

        while len(active_slots) < max_concurrency:
            active_slots.append(asyncio.create_task(slot_worker()))

        if hold_duration_s > 0:
            await asyncio.sleep(hold_duration_s)

        stop_event.set()
        await asyncio.gather(*active_slots, return_exceptions=True)

        actual_duration = self._offset()
        opened = await self._connections_opened()
        return _summarize(
            LoadTestMode.RAMP_UP,
            self.target,
            actual_duration,
            timed_results,
            target_rps=None,
            connections_opened=opened,
        )
