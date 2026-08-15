"""--- 0.5.2 — local multi-process load generation.

load_test.py already had both ends of a distributed run: `start_at` turns one
LoadTestEngine into a synchronised worker, and merge_summaries folds worker
results into one correct summary. What was missing was the middle — something
that actually spins up N of them. Without it a load test is one process, one
event loop, one GIL: the generator becomes the bottleneck long before the
target does.

This module is that thin layer, and nothing more. It does not touch
LoadTestEngine, which is already a correct worker; it starts several of them
in separate interpreters, hands them a shared start epoch, and merges what
comes back.

Scope, deliberately:

  * LOCAL processes only. Separate interpreters on this machine escape the GIL
    and the single-event-loop ceiling, which is usually the binding constraint
    and needs no network coordination at all. Cross-machine runs need a wire
    format (JSON) rather than pickle and a transport, which belongs in the
    SaaS layer; this module does not pretend to provide it.

  * No scheduler, node registry, or health checking. Those are SaaS concerns
    and would be dead weight in the CLI.

What multiple local processes do NOT fix: they still share one NIC, one CPU
and one ephemeral port range. Watch received_bytes_per_s against the link and
avg_blocked_ms against avg_waiting_ms — blocked rising while waiting stays
flat still means the generator is the ceiling, whatever the worker count.
"""

import asyncio
import json
import os
import time
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass, field, replace
from enum import Enum
from multiprocessing import get_context
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from net_benchmark.http_bench.core import HTTPBenchmarkEngine
from net_benchmark.http_bench.load_test import (
    IntervalStats,
    LoadTestEngine,
    LoadTestSummary,
    merge_summaries,
)

# --- 0.5.2: a per-target live-interval callback, supplied by the caller.
#
# Deliberately NOT a WorkerConfig field: a closure survives neither the pickle
# into a spawned child nor a JSON hop to a remote node, so this is an
# in-process-only argument. The factory takes the target because several
# targets run concurrently inside one worker and their interval lines
# interleave on one terminal.
IntervalCallbackFactory = Callable[[str], Optional[Callable[[IntervalStats], None]]]


class TargetDistribution(str, Enum):
    """--- 0.5.2: how targets are spread over workers.

    REPLICATE — every worker runs every target. N workers therefore offer N
    times the concurrency to EACH target, which is the natural reading of
    "concurrency options are per worker" and the right choice when you are
    trying to saturate one origin from a machine that cannot do it in a single
    process. This is the default because it is what the pre-existing
    single-process behaviour scales into.

    SHARD — targets are dealt round-robin, so each target is driven by one
    worker and the offered load per target is unchanged from a single-process
    run. The right choice when --workers exists to get MORE TARGETS done in
    parallel rather than more load onto one. Requires at least as many targets
    as workers to use every process; run_distributed reports it when it does
    not.
    """

    REPLICATE = "replicate"
    SHARD = "shard"


# --- 0.5.2: how much lead time to leave between choosing the start epoch and
# the barrier firing.
#
# Not arbitrary padding. This module uses the "spawn" start method (see
# run_distributed), so every child re-imports the package — and net_benchmark
# pulls in pandas and numpy, which is a second or more of interpreter startup
# on its own before a single request is issued. A lead time shorter than that
# means every worker joins late and the run measures process startup instead of
# the target. 5s sits comfortably above observed spawn cost with a warm page
# cache.
#
# A worker that misses the barrier anyway is not silently absorbed: under an
# epoch its offsets are measured from the shared origin, so its lateness shows
# up as a first interval well past window 0.
DEFAULT_LEAD_S = 5.0


def plan_start_epoch(lead_s: float = DEFAULT_LEAD_S) -> float:
    """--- 0.5.2: the wall-clock instant every worker should start at.

    Unix seconds in the time.time() domain. That is the only clock with a
    shared origin across processes — perf_counter() is monotonic but its ORIGIN
    is per-process, so offsets derived from it are not comparable between
    workers at all. See LoadTestEngine._begin_run.
    """
    return time.time() + lead_s


def split_rps(total_rps: float, workers: int) -> List[float]:
    """--- 0.5.2: divide an offered rate across N workers.

    merge_summaries sums each worker's target_rps back up, so the convention
    that a worker receives its SHARE rather than the run total was implicit and
    unenforced — get it wrong and a 4-worker run asked for 1000 RPS quietly
    offers 4000. This makes the convention a function.

    A float share, not an integer: run_sustained paces on 1.0 / target_rps and
    has no reason to round, so 1000 across 3 workers is 333.33... each.
    sum(split_rps(r, n)) == r to within float error, which is what keeps the
    merged target_rps equal to what was asked for.
    """
    if workers < 1:
        raise ValueError("workers must be >= 1")
    if total_rps <= 0:
        raise ValueError("total_rps must be > 0")
    return [total_rps / workers] * workers


@dataclass
class WorkerConfig:
    """--- 0.5.2: everything a worker process needs, in picklable primitives.

    Flat and primitive on purpose: under the spawn start method this crosses a
    process boundary by pickle. An HTTPBenchmarkEngine is constructed INSIDE
    the worker, never passed in — a live client with open sockets and a
    running event loop does not survive that trip.

    The field names mirror the CLI options they come from, so the mapping in
    cli.py stays a transcription rather than a translation.
    """

    targets: List[str]
    mode: str = "throughput"  # a LoadTestMode value: "ramp_up", not "ramp-up"
    duration_s: float = 10.0
    # This worker's SHARE of the offered rate, not the run total. run_distributed
    # applies split_rps; see its docstring.
    target_rps: Optional[float] = None
    max_concurrency: int = 200
    max_backlog: Optional[int] = None
    start_concurrency: int = 10
    ramp_concurrency: int = 200
    ramp_duration_s: float = 30.0
    hold_duration_s: float = 10.0
    max_total_rps: Optional[float] = None
    graceful_stop_s: float = 30.0

    # transport / request shape — mirrors what cli.py passes to
    # HTTPBenchmarkEngine on the single-process path.
    method: str = "GET"
    headers: Optional[Dict[str, str]] = None
    timeout: float = 10.0
    http2: bool = True
    verify_ssl: bool = True
    max_connections: Optional[int] = None
    enable_phase_trace: bool = True
    enable_tls_resumption: bool = False
    enable_push_detection: bool = False
    expected_statuses: Optional[List[int]] = None

    # identity labels, echoed onto each WorkerResult so a merged run stays
    # attributable to the processes (and, when the SaaS layer drives this, the
    # nodes) that produced it.
    worker_id: Optional[str] = None
    region: Optional[str] = None
    # Measured by the coordinator; see load_test.measure_clock_offset. Travels
    # onto every summary this worker produces so merge_summaries can check it.
    clock_offset_s: Optional[float] = None

    # run shape
    start_epoch: Optional[float] = None
    interval_bucket_s: float = 1.0
    # --- 0.5.2: requests issued per target BEFORE the start barrier, so the
    # epoch fires against established connections. See LoadTestEngine.warmup.
    warmup_requests: int = 0
    # Default False, unlike LoadTestEngine's own default. Per-request rows are
    # the one thing you do not want N processes each pickling back to the
    # parent; every statistic, interval and histogram survives without them.
    retain_results: bool = False


@dataclass
class WorkerResult:
    """--- 0.5.2: one worker's summary, with the labels that say where it came
    from.

    The labels live here rather than on LoadTestSummary so this module can be
    added without changing load_test.py's public dataclass. A merged summary
    cannot say which process served which requests — keeping the per-worker
    results alongside it is what preserves that, and it is also where the
    fields that do not survive a merge (std_latency, the phase p95s) still
    hold exact values.
    """

    worker_id: str
    summary: LoadTestSummary
    region: Optional[str] = None


@dataclass
class DistributedResult:
    """--- 0.5.2: the outcome of one distributed run, for one target."""

    target: str
    merged: LoadTestSummary
    workers: List[WorkerResult] = field(default_factory=list)
    # Workers that died outright. A run that lost two of its four processes
    # offered half the load it was asked to; reporting only the merged summary
    # would show that as a target coping comfortably.
    failures: List[str] = field(default_factory=list)

    @property
    def worker_count(self) -> int:
        return len(self.workers)


# ---------------------------------------------------------------------------
# worker side
# ---------------------------------------------------------------------------


async def _run_target(
    config: WorkerConfig,
    target: str,
    on_interval: Optional[Callable[[IntervalStats], None]] = None,
) -> LoadTestSummary:
    """One target inside one worker: one HTTPBenchmarkEngine and one
    LoadTestEngine, so origins never share a connection pool.

    --- 0.5.2: this is now the ONLY place the engine pair is constructed. cli.py
    used to build them inline in its own `_run_one`, which meant the mapping
    from CLI options to engine arguments existed twice as soon as a distributed
    path appeared — two copies that would drift, and the local run would drift
    away from what the workers actually did. cli.py now builds a WorkerConfig
    and calls in here for both paths.
    """
    engine_concurrency = (
        config.ramp_concurrency if config.mode == "ramp_up" else config.max_concurrency
    )
    http_engine = HTTPBenchmarkEngine(
        max_concurrent=engine_concurrency,
        timeout=config.timeout,
        method=config.method.upper(),
        headers=config.headers or {},
        http2=config.http2,
        verify_ssl=config.verify_ssl,
        enable_tls_resumption=config.enable_tls_resumption,
        enable_push_detection=config.enable_push_detection,
        max_connections=config.max_connections or engine_concurrency,
        enable_phase_trace=config.enable_phase_trace,
        expected_statuses=config.expected_statuses,
    )
    load_engine = LoadTestEngine(
        target,
        http_engine=http_engine,
        expected_statuses=config.expected_statuses,
        retain_results=config.retain_results,
        interval_bucket_s=config.interval_bucket_s,
        on_interval=on_interval,
        # --- 0.5.2: labels ride on the summary, so a result stays attributable
        # after it crosses a process boundary or a wire.
        worker_id=config.worker_id,
        region=config.region,
        clock_offset_s=config.clock_offset_s,
    )
    try:
        if config.mode == "sustained":
            if not config.target_rps:
                raise ValueError("sustained mode requires target_rps")
            return await load_engine.run_sustained(
                target_rps=config.target_rps,
                duration_s=config.duration_s,
                max_concurrency=config.max_concurrency,
                max_backlog=config.max_backlog,
                graceful_stop_s=config.graceful_stop_s,
                start_at=config.start_epoch,
                warmup_requests=config.warmup_requests,
            )
        if config.mode == "ramp_up":
            return await load_engine.run_ramp_up(
                start_concurrency=config.start_concurrency,
                max_concurrency=config.ramp_concurrency,
                ramp_duration_s=config.ramp_duration_s,
                hold_duration_s=config.hold_duration_s,
                max_total_rps=config.max_total_rps,
                graceful_stop_s=config.graceful_stop_s,
                start_at=config.start_epoch,
                warmup_requests=config.warmup_requests,
            )
        return await load_engine.run_throughput(
            duration_s=config.duration_s,
            max_concurrency=config.max_concurrency,
            graceful_stop_s=config.graceful_stop_s,
            start_at=config.start_epoch,
            warmup_requests=config.warmup_requests,
        )
    finally:
        await load_engine.close()


async def run_worker_async(
    config: WorkerConfig,
    on_interval_factory: Optional[IntervalCallbackFactory] = None,
) -> List[LoadTestSummary]:
    """--- 0.5.2: run every target in this worker, concurrently.

    Targets are gathered rather than run in sequence, matching the CLI.

    `on_interval_factory` is in-process only — see IntervalCallbackFactory. It
    is an argument rather than a WorkerConfig field precisely so that the
    thing which cannot cross a process boundary is not sitting inside the
    object that does.
    """
    return list(
        await asyncio.gather(
            *(
                _run_target(
                    config,
                    target,
                    on_interval_factory(target) if on_interval_factory else None,
                )
                for target in config.targets
            )
        )
    )


def run_worker(config: WorkerConfig) -> List[LoadTestSummary]:
    """--- 0.5.2: synchronous worker entry point.

    Module-level so it can be pickled by the spawn start method. Owns its own
    event loop via asyncio.run, which is correct for a freshly spawned child
    (it has none) and WRONG to call from inside a running loop — use
    run_worker_async there.
    """
    return asyncio.run(run_worker_async(config))


# ---------------------------------------------------------------------------
# collector side — cross-machine runs
# ---------------------------------------------------------------------------


def load_payload_files(paths: Sequence[str]) -> List[Dict[str, object]]:
    """--- 0.5.2: read worker payloads written by `load-test --emit-summary`.

    Accepts either shape a worker can emit: a bare list of summary dicts, or
    the `{"targets": [...]}` bundle the JSON exporter writes — so a collector
    can be pointed at raw worker output or at an ordinary JSON export without
    the person having to know which is which.
    """
    payloads: List[Dict[str, object]] = []
    for path in paths:
        with open(path, "r", encoding="utf-8") as fh:
            blob = json.load(fh)
        if isinstance(blob, dict):
            blob = blob.get("targets", [])
        if not isinstance(blob, list):
            raise ValueError(
                f"{path}: expected a list of summaries or a bundle with a "
                "'targets' key"
            )
        payloads.extend(blob)
    return payloads


def merge_payloads(payloads: Sequence[Dict[str, object]]) -> List[DistributedResult]:
    """--- 0.5.2: wire payloads -> one DistributedResult per target.

    Grouped by target before merging, because merge_summaries deliberately
    refuses to fold across targets — that is aggregation, not the merge of one
    distributed run.

    This is the far end of the cross-machine path: each node runs
    `load-test --start-at <shared epoch> --emit-summary node.json`, and the
    collector turns those files into exactly the summary a single-process run
    would have produced.
    """
    by_target: Dict[str, List[LoadTestSummary]] = {}
    for payload in payloads:
        summary = LoadTestSummary.from_dict(payload)
        by_target.setdefault(summary.target, []).append(summary)

    results: List[DistributedResult] = []
    for target, group in by_target.items():
        results.append(
            DistributedResult(
                target=target,
                merged=merge_summaries(group),
                workers=[
                    WorkerResult(
                        worker_id=s.worker_id or f"unlabelled-{i}",
                        summary=s,
                        region=s.region,
                    )
                    for i, s in enumerate(group)
                ],
            )
        )
    return results


# ---------------------------------------------------------------------------
# orchestration
# ---------------------------------------------------------------------------


def plan_target_distribution(
    targets: List[str],
    workers: int,
    distribution: TargetDistribution = TargetDistribution.REPLICATE,
) -> List[List[str]]:
    """--- 0.5.2: decide which targets each worker runs.

    Returns one target list per worker. An empty list means that worker has
    nothing to do and should not be spawned — run_distributed drops those and
    says so, rather than starting an interpreter to do nothing.

    REPLICATE gives every worker the full list. SHARD deals round-robin, so
    with 5 targets over 2 workers the split is [0,2,4] and [1,3] — even to
    within one, and adjacent targets land on different workers, which matters
    when a target list is ordered by expected cost.

    Sharding with more workers than targets cannot use every worker: a target
    is driven by exactly one worker by definition, so surplus workers get
    nothing. That is a real limit of the topology, not something to paper over
    by silently falling back to REPLICATE — which would quietly multiply the
    load the person asked to keep constant.
    """
    if workers < 1:
        raise ValueError("workers must be >= 1")
    if distribution is TargetDistribution.REPLICATE:
        return [list(targets) for _ in range(workers)]
    return [list(targets[index::workers]) for index in range(workers)]


def run_distributed(
    config: WorkerConfig,
    workers: int,
    lead_s: float = DEFAULT_LEAD_S,
    distribution: TargetDistribution = TargetDistribution.REPLICATE,
    on_warning: Optional[Callable[[str], None]] = None,
) -> List[DistributedResult]:
    """--- 0.5.2: run `workers` LoadTestEngines in separate local processes.

    `config.target_rps`, if set, is the TOTAL offered rate and is divided
    across workers by split_rps. Everything else is per-worker as written:
    concurrency is per process, so workers=4 with max_concurrency=50 is 200
    requests in flight overall.

    Returns one DistributedResult per target, each carrying the merged summary
    and the per-worker summaries behind it.

    Points worth knowing before trusting the numbers:

      * spawn, not fork. A forked child inherits the parent's event loop, its
        httpx client and its open sockets, none of which survive being forked
        into a second process — the classic symptom is a run that hangs on the
        first request rather than failing cleanly. spawn costs a full
        interpreter startup per worker, which is what lead_s absorbs.

      * The barrier is chosen ONCE in the parent, before any child starts, and
        every child receives the same epoch. This is what makes the workers'
        interval windows comparable and is the precondition merge_summaries
        checks. A child still importing pandas when the barrier fires joins
        late; its offsets are measured from the shared epoch, so the lateness
        stays visible rather than being re-zeroed away.

      * A worker that dies is recorded in DistributedResult.failures, never
        swallowed — see that field.

      * `distribution` decides whether N workers mean N times the load on each
        target (REPLICATE, the default) or the same load spread over more
        processes (SHARD). See TargetDistribution — the two answer different
        questions and neither is a safe default for the other.

    `on_warning` receives human-readable notes that are not failures — surplus
    workers under SHARD, for instance. The CLI passes its own printer; leave it
    None to discard them.
    """
    if workers < 1:
        raise ValueError("workers must be >= 1")

    start_epoch = (
        config.start_epoch
        if config.start_epoch is not None
        else plan_start_epoch(lead_s)
    )
    # --- 0.5.2: how the offered rate divides depends on the topology, and
    # getting this wrong is a silent accuracy bug in both directions.
    #
    # REPLICATE: every worker drives every target, so N workers each pacing
    # total/N add up to `total` per target — split.
    #
    # SHARD: each target is driven by exactly ONE worker, so that worker must
    # pace the full rate or the target is under-offered by a factor of N.
    # Splitting here would quietly turn `--rps 400 --workers 4` into 100 RPS
    # per target while still reporting 400 as the goal.
    if config.target_rps is None:
        shares: List[Optional[float]] = [None] * workers
    elif distribution is TargetDistribution.SHARD:
        shares = [config.target_rps] * workers
    else:
        shares = list(split_rps(config.target_rps, workers))

    assignments = plan_target_distribution(config.targets, workers, distribution)
    label = config.worker_id or f"local-{os.getpid()}"
    plans: List[Tuple[str, WorkerConfig]] = []
    for index in range(workers):
        if not assignments[index]:
            # Only reachable under SHARD with more workers than targets.
            continue
        worker_id = f"{label}-{index}"
        worker_config = replace(
            config,
            targets=assignments[index],
            start_epoch=start_epoch,
            target_rps=shares[index],
            # --- 0.5.2: stamped on the config so it reaches the engine and
            # ends up on the summary itself, not just on the WorkerResult
            # wrapper — a summary that crosses a wire has to carry its own
            # label or the collector cannot tell the workers apart.
            worker_id=worker_id,
        )
        plans.append((worker_id, worker_config))

    idle = workers - len(plans)
    if idle and on_warning is not None:
        on_warning(
            f"--target-distribution shard with {workers} workers and "
            f"{len(config.targets)} target(s): {idle} worker(s) have nothing to "
            "run and were not started. A target is driven by exactly one "
            "worker when sharding."
        )

    collected: List[Tuple[str, LoadTestSummary]] = []
    failures: List[str] = []
    ctx = get_context("spawn")
    with ProcessPoolExecutor(max_workers=workers, mp_context=ctx) as pool:
        futures = {
            pool.submit(run_worker, worker_config): worker_id
            for worker_id, worker_config in plans
        }
        for future, worker_id in futures.items():
            try:
                for summary in future.result():
                    collected.append((worker_id, summary))
            except Exception as exc:  # noqa: BLE001
                # Broad on purpose: whatever a child raises arrives here
                # already stripped of its traceback by the pickle round trip,
                # and one dead worker must not discard the results of the
                # others. Recorded, never silent.
                failures.append(f"{worker_id}: {type(exc).__name__}: {exc}")

    if not collected:
        raise RuntimeError(
            "every worker failed, so there is nothing to merge: " + "; ".join(failures)
        )

    by_target: Dict[str, List[Tuple[str, LoadTestSummary]]] = {}
    for worker_id, summary in collected:
        by_target.setdefault(summary.target, []).append((worker_id, summary))

    results: List[DistributedResult] = []
    for target, group in by_target.items():
        results.append(
            DistributedResult(
                target=target,
                # Percentiles come from the merged histogram, never from
                # averaging the workers' own p95s — see merge_summaries.
                merged=merge_summaries([summary for _, summary in group]),
                workers=[
                    WorkerResult(
                        worker_id=worker_id, summary=summary, region=config.region
                    )
                    for worker_id, summary in group
                ],
                failures=list(failures),
            )
        )
    return results
