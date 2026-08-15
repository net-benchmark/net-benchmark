"""--- 0.5.2 — unit tests for distributed.py and the merged-metric gate.

Follows the existing http_bench test patterns: class-based grouping,
monkeypatch, AsyncMock/MagicMock, @pytest.mark.asyncio, and summaries built
through _summarize rather than hand-assembled, so the inputs carry the same
TargetStats and LatencyHistogram objects the analyzer really produces.

The multi-process path itself (run_distributed) is exercised against a
monkeypatched pool rather than by spawning real interpreters: spawning would
re-import pandas per worker and make the suite slow and flaky, and what needs
testing here is the orchestration — shared epoch, rate splitting, grouping by
target, merge, failure capture — not that CPython can start a process.
"""

import asyncio
import json
import time
from unittest.mock import AsyncMock, MagicMock

import pytest

from net_benchmark.http_bench.analysis import (
    UNMERGEABLE_METRICS,
    TargetStats,
    parse_threshold,
)
from net_benchmark.http_bench.core import HTTPResult, QueryStatus
from net_benchmark.http_bench.distributed import (
    DEFAULT_LEAD_S,
    DistributedResult,
    TargetDistribution,
    WorkerConfig,
    WorkerResult,
    load_payload_files,
    merge_payloads,
    plan_start_epoch,
    plan_target_distribution,
    run_distributed,
    run_worker,
    run_worker_async,
    split_rps,
)
from net_benchmark.http_bench.load_test import (
    ClockCheck,
    LoadTestEngine,
    LoadTestMode,
    LoadTestSummary,
    RunCounters,
    _summarize,
    _TimedResult,
    known_metric_names,
    measure_clock_offset,
    merge_summaries,
)

# ---------------------------------------------------------------------------
# helpers (mirrors test_load_test.py so the two files stay comparable)
# ---------------------------------------------------------------------------


def fake_result(
    total_ms: float = 100.0,
    status: QueryStatus = QueryStatus.SUCCESS,
    target: str = "https://example.com",
) -> HTTPResult:
    now = time.time()
    return HTTPResult(
        target=target,
        method="GET",
        start_time=now,
        end_time=now + total_ms / 1000.0,
        total_ms=total_ms,
        status=status,
        iteration=1,
        http_status_code=200 if status == QueryStatus.SUCCESS else 500,
    )


def make_summary(
    latencies,
    target="https://example.com",
    duration_s=10.0,
    target_rps=None,
    start_epoch=1000.0,
    mode=LoadTestMode.THROUGHPUT,
):
    timed = [_TimedResult(fake_result(lat, target=target), 0.5) for lat in latencies]
    return _summarize(
        mode=mode,
        target=target,
        duration_s=duration_s,
        timed_results=timed,
        target_rps=target_rps,
        connections_opened=0,
        start_epoch=start_epoch,
    )


# ---------------------------------------------------------------------------
# item 3 — the CI gate
# ---------------------------------------------------------------------------


class TestMergedMetricNamespace:
    """_merge_target_stats leaves std/jitter/consistency and the phase p95s at
    0.0 because no arithmetic recovers them from per-worker summaries. 0.0 is
    also TargetStats' "no samples" value, so publishing them let a threshold
    PASS against a distributed run."""

    def _merged(self):
        return merge_summaries(
            [make_summary([100.0, 120.0]), make_summary([300.0, 320.0])]
        )

    def test_merge_sets_the_flag(self):
        assert self._merged().merged is True

    def test_plain_run_is_not_flagged(self):
        assert make_summary([100.0]).merged is False

    def test_single_summary_identity_is_not_flagged(self):
        # merge_summaries returns a lone input unchanged; it was never merged.
        single = make_summary([100.0])
        assert merge_summaries([single]).merged is False

    def test_unmergeable_metrics_are_absent(self):
        ns = self._merged().metric_namespace()
        for name in UNMERGEABLE_METRICS:
            assert name not in ns, f"{name} must not be thresholdable after a merge"

    def test_mergeable_percentiles_are_still_present(self):
        # The whole point of the histogram: these DO survive a merge.
        ns = self._merged().metric_namespace()
        for name in ("median_latency", "p95_latency", "p99_latency"):
            assert name in ns

    def test_phase_threshold_fails_loudly_instead_of_passing(self):
        results = self._merged().check_thresholds(
            [parse_threshold("p95_waiting_ms<500")]
        )
        assert len(results) == 1
        assert not results[0].passed  # would have passed vacuously against 0.0

    def test_unmerged_summary_can_still_threshold_its_own_phases(self):
        # The gate is on `merged`, not on the value — a single-worker run's
        # phase percentiles are exact and must stay usable.
        assert "p95_waiting_ms" in make_summary([100.0, 200.0]).metric_namespace()

    def test_flag_is_on_the_wire(self):
        assert self._merged().to_dict()["merged"] is True


# ---------------------------------------------------------------------------
# item 1 — coordination primitives
# ---------------------------------------------------------------------------


class TestSplitRps:
    def test_shares_sum_to_the_total(self):
        assert sum(split_rps(1000.0, 3)) == pytest.approx(1000.0)

    def test_one_worker_gets_everything(self):
        assert split_rps(500.0, 1) == [500.0]

    def test_shares_are_equal(self):
        assert split_rps(600.0, 4) == [150.0] * 4

    def test_rejects_zero_workers(self):
        with pytest.raises(ValueError, match="workers must be"):
            split_rps(100.0, 0)

    def test_rejects_non_positive_rate(self):
        with pytest.raises(ValueError, match="total_rps must be"):
            split_rps(0.0, 2)

    def test_merged_target_rps_equals_what_was_asked_for(self):
        """The reason split_rps exists: merge_summaries sums target_rps back
        up, so handing each worker the full figure would report — and offer —
        N times the intended rate."""
        parts = [
            make_summary([100.0], target_rps=share) for share in split_rps(600.0, 3)
        ]
        assert merge_summaries(parts).target_rps == pytest.approx(600.0)


class TestPlanStartEpoch:
    def test_is_in_the_future_by_the_lead(self):
        before = time.time()
        epoch = plan_start_epoch(lead_s=2.0)
        assert 2.0 <= epoch - before <= 2.5

    def test_default_lead_absorbs_spawn_cost(self):
        # Spawn re-imports pandas/numpy per child; a short lead means every
        # worker joins late and the run measures interpreter startup.
        assert DEFAULT_LEAD_S >= 5.0
        assert plan_start_epoch() - time.time() == pytest.approx(
            DEFAULT_LEAD_S, abs=0.5
        )


# ---------------------------------------------------------------------------
# item 1 — worker side
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_engine(monkeypatch):
    """Patched where distributed.py looks it up, not where it is defined.

    The mock awaits 2 ms rather than returning instantly: a zero-latency mock
    lets the slot workers spin as fast as the event loop allows, which both
    generates six-figure result counts in a 0.2s test and hides any pacing
    problem the real code might have.
    """
    instance = MagicMock()

    async def _request(target=None, *_a, **_k):
        await asyncio.sleep(0.002)
        return fake_result(2.0, target=target or "https://example.com")

    instance.request_single = AsyncMock(side_effect=_request)
    instance.close = AsyncMock()
    instance.get_connection_stats = MagicMock(return_value={"connections_opened": 1})
    monkeypatch.setattr(
        "net_benchmark.http_bench.distributed.HTTPBenchmarkEngine",
        MagicMock(return_value=instance),
    )
    return instance


class TestRunWorker:
    @pytest.mark.asyncio
    async def test_throughput_mode(self, mock_engine):
        config = WorkerConfig(
            targets=["https://example.com"], duration_s=0.2, max_concurrency=2
        )
        summaries = await run_worker_async(config)
        assert len(summaries) == 1
        assert summaries[0].mode is LoadTestMode.THROUGHPUT
        assert summaries[0].stats.total_requests > 0

    @pytest.mark.asyncio
    async def test_sustained_mode_requires_a_rate(self, mock_engine):
        config = WorkerConfig(
            targets=["https://example.com"], mode="sustained", duration_s=0.2
        )
        with pytest.raises(ValueError, match="requires target_rps"):
            await run_worker_async(config)

    @pytest.mark.asyncio
    async def test_sustained_mode_is_paced(self, mock_engine):
        config = WorkerConfig(
            targets=["https://example.com"],
            mode="sustained",
            target_rps=50.0,
            duration_s=0.3,
        )
        summary = (await run_worker_async(config))[0]
        assert summary.mode is LoadTestMode.SUSTAINED
        assert summary.counters.paced is True

    @pytest.mark.asyncio
    async def test_ramp_up_mode(self, mock_engine):
        config = WorkerConfig(
            targets=["https://example.com"],
            mode="ramp_up",
            start_concurrency=1,
            ramp_concurrency=3,
            ramp_duration_s=0.2,
            hold_duration_s=0.1,
            graceful_stop_s=1.0,
        )
        summary = (await run_worker_async(config))[0]
        assert summary.mode is LoadTestMode.RAMP_UP

    @pytest.mark.asyncio
    async def test_every_target_gets_its_own_summary(self, mock_engine):
        config = WorkerConfig(
            targets=["https://a.test", "https://b.test"],
            duration_s=0.2,
            max_concurrency=2,
        )
        summaries = await run_worker_async(config)
        assert {s.target for s in summaries} == {"https://a.test", "https://b.test"}

    @pytest.mark.asyncio
    async def test_start_epoch_is_carried_onto_the_summary(self, mock_engine):
        """The precondition merge_summaries checks: without a shared epoch the
        workers' window indices refer to different seconds."""
        epoch = time.time()
        config = WorkerConfig(
            targets=["https://example.com"],
            duration_s=0.2,
            max_concurrency=2,
            start_epoch=epoch,
        )
        assert (await run_worker_async(config))[0].start_epoch == epoch

    @pytest.mark.asyncio
    async def test_workers_do_not_retain_raw_results_by_default(self, mock_engine):
        config = WorkerConfig(
            targets=["https://example.com"], duration_s=0.2, max_concurrency=2
        )
        summary = (await run_worker_async(config))[0]
        assert summary.results == []
        # Statistics are computed before the drop, so they survive.
        assert summary.stats.total_requests > 0

    def test_sync_entry_point_owns_its_loop(self, mock_engine):
        # run_worker is what a spawned child calls; it must work with no loop
        # already running.
        config = WorkerConfig(
            targets=["https://example.com"], duration_s=0.1, max_concurrency=2
        )
        assert len(run_worker(config)) == 1


# ---------------------------------------------------------------------------
# item 1 — orchestration
# ---------------------------------------------------------------------------


class _FakeFuture:
    def __init__(self, value=None, exc=None):
        self._value = value
        self._exc = exc

    def result(self):
        if self._exc is not None:
            raise self._exc
        return self._value


class _FakePool:
    """Stands in for ProcessPoolExecutor: runs the submitted callable inline.

    Deliberately inline rather than spawning: spawning re-imports pandas per
    child, which would make this suite slow and flaky, and what is under test
    is the orchestration around the pool — one shared epoch, rate splitting,
    grouping by target, merging, failure capture — not process creation.
    """

    instances: list = []

    def __init__(self, max_workers=None, mp_context=None):
        self.max_workers = max_workers
        self.mp_context = mp_context
        self.submitted = []
        _FakePool.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return False

    def submit(self, fn, config):
        self.submitted.append(config)
        try:
            return _FakeFuture(value=fn(config))
        except Exception as exc:  # noqa: BLE001
            return _FakeFuture(exc=exc)


@pytest.fixture
def fake_pool(monkeypatch):
    _FakePool.instances = []
    monkeypatch.setattr(
        "net_benchmark.http_bench.distributed.ProcessPoolExecutor", _FakePool
    )
    return _FakePool


class TestRunDistributed:
    def _config(self, **kwargs):
        base = dict(targets=["https://example.com"], duration_s=0.15, max_concurrency=2)
        base.update(kwargs)
        return WorkerConfig(**base)

    def test_rejects_zero_workers(self, mock_engine, fake_pool):
        with pytest.raises(ValueError, match="workers must be"):
            run_distributed(self._config(), workers=0)

    def test_every_worker_gets_the_same_epoch(self, mock_engine, fake_pool):
        """The single most important property: one barrier, chosen once in the
        parent. Per-worker epochs would leave the timelines unmergeable."""
        run_distributed(self._config(), workers=3, lead_s=0.2)
        submitted = fake_pool.instances[0].submitted
        assert len(submitted) == 3
        epochs = {c.start_epoch for c in submitted}
        assert len(epochs) == 1
        assert epochs.pop() is not None

    def test_epoch_is_in_the_future(self, mock_engine, fake_pool):
        before = time.time()
        run_distributed(self._config(), workers=2, lead_s=0.3)
        assert fake_pool.instances[0].submitted[0].start_epoch >= before + 0.3

    def test_an_explicit_epoch_is_respected(self, mock_engine, fake_pool):
        epoch = time.time() + 0.2
        run_distributed(self._config(start_epoch=epoch), workers=2, lead_s=99.0)
        assert all(c.start_epoch == epoch for c in fake_pool.instances[0].submitted)

    def test_rate_is_split_not_duplicated(self, mock_engine, fake_pool):
        run_distributed(
            self._config(mode="sustained", target_rps=400.0), workers=4, lead_s=0.2
        )
        shares = [c.target_rps for c in fake_pool.instances[0].submitted]
        assert shares == [100.0] * 4
        assert sum(shares) == pytest.approx(400.0)

    def test_no_rate_stays_none(self, mock_engine, fake_pool):
        run_distributed(self._config(), workers=2, lead_s=0.2)
        assert all(c.target_rps is None for c in fake_pool.instances[0].submitted)

    def test_worker_labels_are_unique_and_prefixed(self, mock_engine, fake_pool):
        results = run_distributed(self._config(worker_id="hel1"), workers=3, lead_s=0.2)
        ids = [w.worker_id for w in results[0].workers]
        assert len(set(ids)) == 3
        assert all(i.startswith("hel1-") for i in ids)

    def test_region_is_carried_onto_each_worker(self, mock_engine, fake_pool):
        results = run_distributed(self._config(region="hel1"), workers=2, lead_s=0.2)
        assert all(w.region == "hel1" for w in results[0].workers)

    def test_result_is_merged_and_flagged(self, mock_engine, fake_pool):
        results = run_distributed(self._config(), workers=2, lead_s=0.2)
        assert len(results) == 1
        assert results[0].merged.merged is True
        assert results[0].worker_count == 2

    def test_workers_are_kept_alongside_the_merge(self, mock_engine, fake_pool):
        """merge_summaries cannot say which process served which requests, and
        the un-mergeable fields are still exact per worker."""
        results = run_distributed(self._config(), workers=2, lead_s=0.2)
        assert all(not w.summary.merged for w in results[0].workers)

    def test_merged_totals_are_the_sum_of_the_workers(self, mock_engine, fake_pool):
        results = run_distributed(self._config(), workers=3, lead_s=0.2)
        result = results[0]
        assert result.merged.stats.total_requests == sum(
            w.summary.stats.total_requests for w in result.workers
        )

    def test_results_are_grouped_by_target(self, mock_engine, fake_pool):
        results = run_distributed(
            self._config(targets=["https://a.test", "https://b.test"]),
            workers=2,
            lead_s=0.2,
        )
        by_target = {r.target: r for r in results}
        assert set(by_target) == {"https://a.test", "https://b.test"}
        # Each target was run by both workers.
        assert all(r.worker_count == 2 for r in by_target.values())

    def test_uses_the_spawn_context(self, mock_engine, fake_pool):
        """fork would hand the child the parent's event loop, httpx client and
        open sockets — none of which survive being forked, and the symptom is
        a hang on the first request rather than a clean failure."""
        run_distributed(self._config(), workers=2, lead_s=0.2)
        assert fake_pool.instances[0].mp_context.get_start_method() == "spawn"

    def test_a_dead_worker_is_recorded_not_swallowed(self, monkeypatch, fake_pool):
        calls = {"n": 0}
        real_summary = make_summary([100.0])

        def _flaky(config):
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("worker exploded")
            return [real_summary]

        monkeypatch.setattr("net_benchmark.http_bench.distributed.run_worker", _flaky)
        results = run_distributed(self._config(), workers=2, lead_s=0.2)
        assert len(results[0].failures) == 1
        assert "worker exploded" in results[0].failures[0]
        # The surviving worker's data is kept.
        assert results[0].worker_count == 1

    def test_total_failure_raises_rather_than_reporting_an_empty_run(
        self, monkeypatch, fake_pool
    ):
        def _dead(config):
            raise RuntimeError("nope")

        monkeypatch.setattr("net_benchmark.http_bench.distributed.run_worker", _dead)
        with pytest.raises(RuntimeError, match="every worker failed"):
            run_distributed(self._config(), workers=2, lead_s=0.2)


class TestWorkerConfigDefaults:
    def test_workers_drop_raw_results_by_default(self):
        # N processes pickling per-request rows back to the parent is the one
        # thing you never want; every statistic survives without them.
        assert WorkerConfig(targets=["https://example.com"]).retain_results is False

    def test_original_config_is_not_mutated(self, mock_engine, fake_pool):
        config = WorkerConfig(
            targets=["https://example.com"],
            duration_s=0.15,
            max_concurrency=2,
            mode="sustained",
            target_rps=400.0,
        )
        run_distributed(config, workers=4, lead_s=0.2)
        assert config.target_rps == 400.0  # still the total, not a share
        assert config.start_epoch is None


class TestDistributedResult:
    def test_worker_count(self):
        summary = make_summary([100.0])
        result = DistributedResult(
            target="https://example.com",
            merged=summary,
            workers=[
                WorkerResult(worker_id="a", summary=summary),
                WorkerResult(worker_id="b", summary=summary),
            ],
        )
        assert result.worker_count == 2


# ---------------------------------------------------------------------------
# item 2 — CLI wiring
# ---------------------------------------------------------------------------


class TestLoadTestCliFlags:
    """The routing contract only: at one worker the original in-process path
    runs untouched, above one it goes to distributed.py with the right
    arguments. The load test itself is covered above and in test_load_test.py.
    """

    def _invoke(self, monkeypatch, args, distributed=None):
        from click.testing import CliRunner

        from net_benchmark.http_bench import cli as cli_module

        calls = {}

        def _fake_run_distributed(config, workers, distribution=None, **kwargs):
            calls["config"] = config
            calls["workers"] = workers
            calls["distribution"] = distribution
            summary = make_summary([100.0], target="https://example.com")
            merged = merge_summaries([summary, make_summary([120.0])])
            return [
                DistributedResult(
                    target="https://example.com",
                    merged=merged,
                    workers=[
                        WorkerResult(worker_id=f"w{i}", summary=summary)
                        for i in range(workers)
                    ],
                )
            ]

        monkeypatch.setattr(
            cli_module, "run_distributed", distributed or _fake_run_distributed
        )
        runner = CliRunner()
        with runner.isolated_filesystem():
            # Isolated so the exporters write into a temp dir rather than the
            # working tree; --formats is left at its default so the export path
            # is exercised rather than skipped.
            result = runner.invoke(
                cli_module.http,
                ["load-test", "-t", "https://example.com", *args],
            )
        return result, calls

    def test_zero_workers_is_rejected_before_anything_runs(self, monkeypatch):
        result, calls = self._invoke(monkeypatch, ["--workers", "0"])
        assert "workers must be >= 1" in result.output
        assert "config" not in calls

    def test_one_worker_does_not_use_the_distributed_path(
        self, monkeypatch, mock_engine
    ):
        def _must_not_be_called(*_a, **_k):
            raise AssertionError("single-worker runs must stay in-process")

        # mock_engine patches distributed's lookup; patch the CLI's too so the
        # in-process path uses the same mock.
        from net_benchmark.http_bench import cli as cli_module

        monkeypatch.setattr(
            cli_module, "HTTPBenchmarkEngine", MagicMock(return_value=mock_engine)
        )
        result, _ = self._invoke(
            monkeypatch,
            ["--duration", "0.2", "--max-concurrency", "2"],
            distributed=_must_not_be_called,
        )
        assert result.exit_code == 0

    def test_multiple_workers_route_to_distributed(self, monkeypatch):
        result, calls = self._invoke(monkeypatch, ["--workers", "3", "--duration", "1"])
        assert result.exit_code == 0
        assert calls["workers"] == 3
        assert calls["config"].targets == ["https://example.com"]

    def test_rate_is_passed_as_the_run_total(self, monkeypatch):
        # split_rps divides it inside run_distributed; the CLI must not
        # pre-divide or the rate would be applied twice.
        _, calls = self._invoke(
            monkeypatch,
            [
                "--workers",
                "4",
                "--mode",
                "sustained",
                "--rps",
                "400",
                "--duration",
                "1",
            ],
        )
        assert calls["config"].target_rps == 400.0

    def test_labels_reach_the_worker_config(self, monkeypatch):
        _, calls = self._invoke(
            monkeypatch,
            [
                "--workers",
                "2",
                "--worker-id",
                "hel1",
                "--region",
                "eu",
                "--duration",
                "1",
            ],
        )
        assert calls["config"].worker_id == "hel1"
        assert calls["config"].region == "eu"

    def test_live_is_refused_not_silently_ignored(self, monkeypatch):
        result, _ = self._invoke(
            monkeypatch, ["--workers", "2", "--live", "--duration", "1"]
        )
        assert "--live has no effect" in result.output

    def test_merged_provenance_is_printed(self, monkeypatch):
        result, _ = self._invoke(monkeypatch, ["--workers", "2", "--duration", "1"])
        assert "Workers merged:" in result.output
        assert "Not merged:" in result.output

    def test_shard_reaches_the_orchestrator(self, monkeypatch):
        _, calls = self._invoke(
            monkeypatch,
            ["--workers", "2", "--target-distribution", "shard", "--duration", "1"],
        )
        assert calls["distribution"] is TargetDistribution.SHARD

    def test_replicate_is_the_default(self, monkeypatch):
        _, calls = self._invoke(monkeypatch, ["--workers", "2", "--duration", "1"])
        assert calls["distribution"] is TargetDistribution.REPLICATE

    def test_an_invalid_distribution_is_rejected_by_click(self, monkeypatch):
        result, calls = self._invoke(
            monkeypatch, ["--workers", "2", "--target-distribution", "nonsense"]
        )
        assert result.exit_code != 0
        assert "config" not in calls

    def test_orchestrator_warnings_are_printed(self, monkeypatch):
        def _warns(config, workers, distribution=None, on_warning=None, **kwargs):
            if on_warning:
                on_warning("3 worker(s) have nothing to run")
            summary = make_summary([100.0])
            return [
                DistributedResult(
                    target="https://example.com",
                    merged=merge_summaries([summary, make_summary([120.0])]),
                    workers=[WorkerResult(worker_id="w0", summary=summary)],
                )
            ]

        result, _ = self._invoke(
            monkeypatch,
            ["--workers", "4", "--target-distribution", "shard", "--duration", "1"],
            distributed=_warns,
        )
        assert "nothing to run" in result.output

    def test_local_run_still_streams_live_intervals(self, monkeypatch, mock_engine):
        # The unified path must not have dropped --live on the way through
        # WorkerConfig; the callback is passed as an argument, not a field.
        def _must_not_be_called(*_a, **_k):
            raise AssertionError("single-worker runs must stay in-process")

        result, _ = self._invoke(
            monkeypatch,
            ["--live", "--duration", "0.4", "--max-concurrency", "2"],
            distributed=_must_not_be_called,
        )
        assert result.exit_code == 0
        assert "req=" in result.output


# ---------------------------------------------------------------------------
# item 1 (cont.) — target distribution
# ---------------------------------------------------------------------------


class TestPlanTargetDistribution:
    def test_replicate_gives_every_worker_everything(self):
        plan = plan_target_distribution(["a", "b"], 3, TargetDistribution.REPLICATE)
        assert plan == [["a", "b"]] * 3

    def test_replicate_hands_out_independent_lists(self):
        # A shared list would be mutated for every worker at once.
        plan = plan_target_distribution(["a"], 2, TargetDistribution.REPLICATE)
        plan[0].append("b")
        assert plan[1] == ["a"]

    def test_shard_deals_round_robin(self):
        plan = plan_target_distribution(
            ["a", "b", "c", "d", "e"], 2, TargetDistribution.SHARD
        )
        assert plan == [["a", "c", "e"], ["b", "d"]]

    def test_shard_is_a_partition(self):
        targets = [f"t{i}" for i in range(7)]
        plan = plan_target_distribution(targets, 3, TargetDistribution.SHARD)
        flat = [t for group in plan for t in group]
        assert sorted(flat) == sorted(targets)
        assert len(flat) == len(set(flat))  # no target driven twice

    def test_shard_leaves_surplus_workers_empty(self):
        # A target is driven by exactly one worker, so surplus workers get
        # nothing. Falling back to replicate here would quietly multiply the
        # load the person asked to keep constant.
        plan = plan_target_distribution(["a"], 3, TargetDistribution.SHARD)
        assert plan == [["a"], [], []]

    def test_rejects_zero_workers(self):
        with pytest.raises(ValueError, match="workers must be"):
            plan_target_distribution(["a"], 0)


class TestShardedRun:
    def _config(self, **kwargs):
        base = dict(
            targets=["https://a.test", "https://b.test"],
            duration_s=0.15,
            max_concurrency=2,
        )
        base.update(kwargs)
        return WorkerConfig(**base)

    def test_each_target_is_driven_by_one_worker(self, mock_engine, fake_pool):
        results = run_distributed(
            self._config(),
            workers=2,
            lead_s=0.2,
            distribution=TargetDistribution.SHARD,
        )
        assert {r.target for r in results} == {"https://a.test", "https://b.test"}
        assert all(r.worker_count == 1 for r in results)

    def test_replicate_drives_each_target_from_every_worker(
        self, mock_engine, fake_pool
    ):
        results = run_distributed(self._config(), workers=2, lead_s=0.2)
        assert all(r.worker_count == 2 for r in results)

    def test_shard_does_not_divide_the_rate(self, mock_engine, fake_pool):
        """Under SHARD one worker is the only source for its targets, so
        splitting would under-offer each target by a factor of N while still
        reporting the full rate as the goal."""
        run_distributed(
            self._config(mode="sustained", target_rps=400.0),
            workers=2,
            lead_s=0.2,
            distribution=TargetDistribution.SHARD,
        )
        assert [c.target_rps for c in fake_pool.instances[0].submitted] == [
            400.0,
            400.0,
        ]

    def test_replicate_still_divides_the_rate(self, mock_engine, fake_pool):
        run_distributed(
            self._config(mode="sustained", target_rps=400.0), workers=2, lead_s=0.2
        )
        assert [c.target_rps for c in fake_pool.instances[0].submitted] == [
            200.0,
            200.0,
        ]

    def test_surplus_workers_are_not_started(self, mock_engine, fake_pool):
        run_distributed(
            self._config(targets=["https://a.test"]),
            workers=4,
            lead_s=0.2,
            distribution=TargetDistribution.SHARD,
        )
        # One target, so one process — not four idling.
        assert len(fake_pool.instances[0].submitted) == 1

    def test_surplus_workers_are_reported(self, mock_engine, fake_pool):
        warnings = []
        run_distributed(
            self._config(targets=["https://a.test"]),
            workers=4,
            lead_s=0.2,
            distribution=TargetDistribution.SHARD,
            on_warning=warnings.append,
        )
        assert len(warnings) == 1
        assert "3 worker(s) have nothing to run" in warnings[0]

    def test_replicate_never_warns(self, mock_engine, fake_pool):
        warnings = []
        run_distributed(
            self._config(targets=["https://a.test"]),
            workers=4,
            lead_s=0.2,
            on_warning=warnings.append,
        )
        assert warnings == []

    def test_each_worker_only_gets_its_own_targets(self, mock_engine, fake_pool):
        run_distributed(
            self._config(),
            workers=2,
            lead_s=0.2,
            distribution=TargetDistribution.SHARD,
        )
        assigned = [c.targets for c in fake_pool.instances[0].submitted]
        assert assigned == [["https://a.test"], ["https://b.test"]]

    def test_original_config_targets_are_not_mutated(self, mock_engine, fake_pool):
        config = self._config()
        run_distributed(
            config, workers=2, lead_s=0.2, distribution=TargetDistribution.SHARD
        )
        assert config.targets == ["https://a.test", "https://b.test"]


# ---------------------------------------------------------------------------
# item 1 (cont.) — the in-process callback hook that replaced cli._run_one
# ---------------------------------------------------------------------------


class TestIntervalCallback:
    @pytest.mark.asyncio
    async def test_callback_receives_intervals(self, mock_engine):
        seen = []
        config = WorkerConfig(
            targets=["https://example.com"],
            duration_s=0.4,
            max_concurrency=2,
            interval_bucket_s=0.1,
        )
        await run_worker_async(config, lambda _target: seen.append)
        assert seen  # the streamer fired at least one window
        assert all(hasattr(iv, "window_index") for iv in seen)

    @pytest.mark.asyncio
    async def test_factory_is_called_once_per_target(self, mock_engine):
        asked = []

        def _factory(target):
            asked.append(target)
            return None

        config = WorkerConfig(
            targets=["https://a.test", "https://b.test"],
            duration_s=0.15,
            max_concurrency=2,
        )
        await run_worker_async(config, _factory)
        assert sorted(asked) == ["https://a.test", "https://b.test"]

    @pytest.mark.asyncio
    async def test_no_factory_is_fine(self, mock_engine):
        config = WorkerConfig(
            targets=["https://example.com"], duration_s=0.15, max_concurrency=2
        )
        assert len(await run_worker_async(config)) == 1


# ---------------------------------------------------------------------------
# wire format — cross-machine runs
# ---------------------------------------------------------------------------


class TestWireRoundTrip:
    def _summary(self):
        s = make_summary([100.0, 250.0, 400.0], target_rps=50.0, start_epoch=1000.0)
        s.worker_id, s.region = "hel1", "eu"
        s.start_offset_s, s.clock_offset_s = 0.25, 0.004
        s.counters = RunCounters(scheduled=10, started=9, dropped=1, paced=True)
        return s

    def test_json_serialisable(self):
        json.dumps(self._summary().to_dict())  # must not raise

    def test_round_trip_preserves_merge_inputs(self):
        original = self._summary()
        restored = LoadTestSummary.from_dict(json.loads(json.dumps(original.to_dict())))
        assert restored.mode is original.mode
        assert restored.start_epoch == original.start_epoch
        assert restored.interval_bucket_s == original.interval_bucket_s
        assert restored.worker_id == "hel1"
        assert restored.region == "eu"
        assert restored.start_offset_s == pytest.approx(0.25)
        assert restored.clock_offset_s == pytest.approx(0.004)

    def test_round_trip_preserves_paced(self):
        """to_dict used to omit `paced`, so dropped_rate silently changed from
        a real metric to an absent one just by crossing the wire."""
        restored = LoadTestSummary.from_dict(self._summary().to_dict())
        assert restored.counters.paced is True
        assert "dropped_rate" in restored.metric_namespace()

    def test_round_trip_preserves_the_histogram(self):
        original = self._summary()
        restored = LoadTestSummary.from_dict(original.to_dict())
        assert restored.latency_histogram is not None
        assert restored.latency_histogram.count == original.latency_histogram.count
        assert restored.latency_histogram.quantile(0.95) == pytest.approx(
            original.latency_histogram.quantile(0.95)
        )

    def test_results_are_dropped_not_faked(self):
        assert LoadTestSummary.from_dict(self._summary().to_dict()).results == []

    def test_intervals_survive(self):
        original = self._summary()
        restored = LoadTestSummary.from_dict(original.to_dict())
        assert [iv.window_index for iv in restored.intervals] == [
            iv.window_index for iv in original.intervals
        ]

    def test_percentiles_survive_a_wire_merge(self):
        """The end-to-end claim: worker JSON in, correct global percentile out
        — and never an average of the workers' own p95s."""
        fast = make_summary([10.0] * 100, start_epoch=1000.0)
        slow = make_summary([1000.0] * 100, start_epoch=1000.0)
        direct = merge_summaries([fast, slow])
        viawire = merge_summaries(
            [
                LoadTestSummary.from_dict(json.loads(json.dumps(s.to_dict())))
                for s in (fast, slow)
            ]
        )
        assert viawire.stats.p95_latency == pytest.approx(direct.stats.p95_latency)
        naive_average = (fast.stats.p95_latency + slow.stats.p95_latency) / 2
        assert viawire.stats.p95_latency != pytest.approx(naive_average)

    def test_target_stats_from_dict_ignores_unknown_keys(self):
        # A newer worker reporting to an older collector must not crash it.
        d = json.loads(json.dumps(make_summary([100.0]).to_dict()))["stats"]
        d["some_future_field"] = 1.23
        assert TargetStats.from_dict(d).total_requests == 1


class TestCollector:
    def test_merge_payloads_groups_by_target(self):
        a = make_summary([100.0], target="https://a.test", start_epoch=1000.0)
        b = make_summary([200.0], target="https://b.test", start_epoch=1000.0)
        c = make_summary([300.0], target="https://a.test", start_epoch=1000.0)
        results = {
            r.target: r for r in merge_payloads([s.to_dict() for s in (a, b, c)])
        }
        assert results["https://a.test"].worker_count == 2
        assert results["https://b.test"].worker_count == 1

    def test_workers_are_kept_alongside_the_merge(self):
        a = make_summary([100.0], start_epoch=1000.0)
        b = make_summary([200.0], start_epoch=1000.0)
        result = merge_payloads([a.to_dict(), b.to_dict()])[0]
        assert result.merged.merged is True
        assert all(not w.summary.merged for w in result.workers)

    def test_load_payload_files_reads_a_bare_list(self, tmp_path):
        path = tmp_path / "w.json"
        path.write_text(json.dumps([make_summary([100.0]).to_dict()]), "utf-8")
        assert len(load_payload_files([str(path)])) == 1

    def test_load_payload_files_reads_an_export_bundle(self, tmp_path):
        path = tmp_path / "bundle.json"
        path.write_text(
            json.dumps({"targets": [make_summary([100.0]).to_dict()]}), "utf-8"
        )
        assert len(load_payload_files([str(path)])) == 1

    def test_load_payload_files_rejects_nonsense(self, tmp_path):
        path = tmp_path / "bad.json"
        path.write_text(json.dumps("not a summary"), "utf-8")
        with pytest.raises(ValueError, match="expected a list"):
            load_payload_files([str(path)])

    def test_end_to_end_across_files(self, tmp_path):
        """What a cross-machine run actually does: two nodes emit, one
        collector merges."""
        paths = []
        for name, latencies in (("hel1", [100.0] * 50), ("ash", [400.0] * 50)):
            summary = make_summary(latencies, start_epoch=1000.0)
            summary.worker_id = name
            path = tmp_path / f"{name}.json"
            path.write_text(json.dumps([summary.to_dict()]), "utf-8")
            paths.append(str(path))
        result = merge_payloads(load_payload_files(paths))[0]
        assert result.merged.stats.total_requests == 100
        assert sorted(result.merged.merged_from) == ["ash", "hel1"]


# ---------------------------------------------------------------------------
# merge validation
# ---------------------------------------------------------------------------


class TestMergeValidation:
    def test_mismatched_interval_bucket_is_refused(self):
        """window_index is an index, not a time: window 7 on a 1.0s grid and
        window 7 on a 0.5s grid are different slices of the run."""
        a = make_summary([100.0], start_epoch=1000.0)
        b = make_summary([100.0], start_epoch=1000.0)
        b.interval_bucket_s = 0.5
        with pytest.raises(ValueError, match="interval bucket widths"):
            merge_summaries([a, b])

    def test_measured_clock_skew_is_refused(self):
        """Agreeing on start_epoch only proves the workers were told the same
        thing. A measured offset is what actually detects skew."""
        a = make_summary([100.0], start_epoch=1000.0)
        b = make_summary([100.0], start_epoch=1000.0)
        a.worker_id, b.worker_id = "hel1", "ash"
        b.clock_offset_s = 0.2  # 200 ms ahead
        with pytest.raises(ValueError, match="clock skew"):
            merge_summaries([a, b])

    def test_small_measured_skew_is_accepted(self):
        a = make_summary([100.0], start_epoch=1000.0)
        b = make_summary([100.0], start_epoch=1000.0)
        a.clock_offset_s, b.clock_offset_s = 0.001, -0.002
        assert merge_summaries([a, b]).stats.total_requests == 2

    def test_unmeasured_skew_does_not_block_merging(self):
        # None means unmeasured, not verified — merging stays allowed so local
        # and in-process runs keep working.
        a = make_summary([100.0], start_epoch=1000.0)
        b = make_summary([100.0], start_epoch=1000.0)
        assert merge_summaries([a, b]).clock_offset_s is None


class TestMergeProvenance:
    def test_merged_from_records_membership(self):
        a = make_summary([100.0], start_epoch=1000.0)
        b = make_summary([100.0], start_epoch=1000.0)
        a.worker_id, b.worker_id = "hel1", "ash"
        assert merge_summaries([a, b]).merged_from == ["hel1", "ash"]

    def test_region_survives_when_unanimous(self):
        a = make_summary([100.0], start_epoch=1000.0)
        b = make_summary([100.0], start_epoch=1000.0)
        a.region = b.region = "hel1"
        assert merge_summaries([a, b]).region == "hel1"

    def test_region_cleared_when_mixed(self):
        a = make_summary([100.0], start_epoch=1000.0)
        b = make_summary([100.0], start_epoch=1000.0)
        a.region, b.region = "hel1", "ash"
        assert merge_summaries([a, b]).region is None

    def test_worst_start_skew_is_carried(self):
        a = make_summary([100.0], start_epoch=1000.0)
        b = make_summary([100.0], start_epoch=1000.0)
        a.start_offset_s, b.start_offset_s = 0.1, 2.4
        assert merge_summaries([a, b]).start_offset_s == pytest.approx(2.4)


# ---------------------------------------------------------------------------
# clock offset
# ---------------------------------------------------------------------------


class TestMeasureClockOffset:
    @pytest.mark.asyncio
    async def test_detects_a_fast_remote_clock(self):
        async def remote_now() -> float:
            return time.time() + 0.2

        check = await measure_clock_offset(remote_now, samples=3)
        assert check.offset_s == pytest.approx(0.2, abs=0.05)
        assert not check.within_tolerance

    @pytest.mark.asyncio
    async def test_a_synced_clock_is_within_tolerance(self):
        async def remote_now() -> float:
            return time.time()

        assert (await measure_clock_offset(remote_now, samples=3)).within_tolerance

    def test_tolerance_is_on_magnitude_not_sign(self):
        assert not ClockCheck(offset_s=-0.2, rtt_s=0.001).within_tolerance


# ---------------------------------------------------------------------------
# engine behaviour
# ---------------------------------------------------------------------------


@pytest.fixture
def engine_mock(monkeypatch):
    """Patched where load_test looks it up, for direct LoadTestEngine tests."""
    instance = MagicMock()

    async def _request(target=None, *_a, **_k):
        await asyncio.sleep(0.002)
        return fake_result(2.0, target=target or "https://example.com")

    instance.request_single = AsyncMock(side_effect=_request)
    instance.close = AsyncMock()
    instance.get_connection_stats = MagicMock(return_value={"connections_opened": 1})
    monkeypatch.setattr(
        "net_benchmark.http_bench.load_test.HTTPBenchmarkEngine",
        MagicMock(return_value=instance),
    )
    return instance


class TestExclusiveRuns:
    """_start_time/_epoch/_conn_baseline are per-run state on the instance; two
    concurrent runs interleave writes to all of them and both come out with
    nonsense offsets, silently."""

    @pytest.mark.asyncio
    async def test_concurrent_runs_on_one_engine_are_rejected(self, engine_mock):
        engine = LoadTestEngine("https://example.com")
        first = asyncio.create_task(
            engine.run_throughput(duration_s=0.3, max_concurrency=2)
        )
        await asyncio.sleep(0.05)
        with pytest.raises(RuntimeError, match="already running"):
            await engine.run_throughput(duration_s=0.1, max_concurrency=2)
        await first

    @pytest.mark.asyncio
    async def test_sequential_reuse_still_works(self, engine_mock):
        engine = LoadTestEngine("https://example.com")
        await engine.run_throughput(duration_s=0.1, max_concurrency=2)
        second = await engine.run_throughput(duration_s=0.1, max_concurrency=2)
        assert second.stats.total_requests > 0

    @pytest.mark.asyncio
    async def test_a_failed_run_releases_the_guard(self, engine_mock):
        engine = LoadTestEngine("https://example.com")
        with pytest.raises(ValueError):
            await engine.run_ramp_up(
                start_concurrency=0, max_concurrency=5, ramp_duration_s=0.1
            )
        await engine.run_throughput(duration_s=0.1, max_concurrency=2)


class TestAbsoluteDeadlines:
    """Under an epoch a late worker must run SHORTER, not later. Running later
    stretches merge_summaries' max(duration_s) window past the point every
    other worker stopped, diluting the merged achieved_rps."""

    @pytest.mark.asyncio
    async def test_throughput_truncates_for_a_late_worker(self, engine_mock):
        engine = LoadTestEngine("https://example.com")
        began = time.perf_counter()
        summary = await engine.run_throughput(
            duration_s=1.0,
            max_concurrency=2,
            start_at=time.time() - 0.7,
            graceful_stop_s=0.5,
        )
        assert time.perf_counter() - began < 0.9  # only ~0.3s of window left
        assert summary.duration_s < 1.4  # measured from the epoch, not 1.7

    @pytest.mark.asyncio
    async def test_throughput_past_deadline_does_almost_nothing(self, engine_mock):
        engine = LoadTestEngine("https://example.com")
        summary = await engine.run_throughput(
            duration_s=0.2,
            max_concurrency=2,
            start_at=time.time() - 5.0,
            graceful_stop_s=0.5,
        )
        # Reported honestly as an empty run rather than a shifted full one.
        assert summary.stats.total_requests <= 2

    @pytest.mark.asyncio
    async def test_ramp_up_truncates_for_a_late_worker(self, engine_mock):
        engine = LoadTestEngine("https://example.com")
        began = time.perf_counter()
        await engine.run_ramp_up(
            start_concurrency=1,
            max_concurrency=4,
            ramp_duration_s=1.0,
            hold_duration_s=1.0,
            step_interval_s=0.2,
            start_at=time.time() - 1.5,
            graceful_stop_s=0.5,
        )
        assert time.perf_counter() - began < 1.2

    @pytest.mark.asyncio
    async def test_no_epoch_keeps_the_relative_duration(self, engine_mock):
        engine = LoadTestEngine("https://example.com")
        began = time.perf_counter()
        await engine.run_throughput(duration_s=0.3, max_concurrency=2)
        assert time.perf_counter() - began >= 0.3


class TestStartOffset:
    @pytest.mark.asyncio
    async def test_lateness_is_a_number_not_a_shape(self, engine_mock):
        engine = LoadTestEngine("https://example.com")
        summary = await engine.run_throughput(
            duration_s=2.0,
            max_concurrency=2,
            start_at=time.time() - 1.0,
            graceful_stop_s=0.5,
        )
        assert summary.start_offset_s == pytest.approx(1.0, abs=0.2)

    @pytest.mark.asyncio
    async def test_zero_without_an_epoch(self, engine_mock):
        engine = LoadTestEngine("https://example.com")
        summary = await engine.run_throughput(duration_s=0.1, max_concurrency=2)
        assert summary.start_offset_s == 0.0


class TestWarmup:
    @pytest.mark.asyncio
    async def test_warmup_runs_before_the_barrier(self, engine_mock):
        """The point: connections must already be open when the epoch fires,
        or a synchronised start is a synchronised handshake storm."""
        seen = []

        async def _request(*_a, **_k):
            seen.append(time.time())
            await asyncio.sleep(0.002)
            return fake_result(2.0)

        engine_mock.request_single = AsyncMock(side_effect=_request)
        start_at = time.time() + 0.5
        engine = LoadTestEngine("https://example.com")
        await engine.run_throughput(
            duration_s=0.2,
            max_concurrency=2,
            start_at=start_at,
            warmup_requests=3,
            graceful_stop_s=0.5,
        )
        assert len(seen) > 3
        assert seen[2] < start_at  # the first three predate the barrier

    @pytest.mark.asyncio
    async def test_warmup_results_are_not_measured(self, engine_mock):
        engine = LoadTestEngine("https://example.com")
        summary = await engine.run_throughput(
            duration_s=0.0, max_concurrency=1, warmup_requests=5, graceful_stop_s=0.2
        )
        assert summary.stats.total_requests < 5

    @pytest.mark.asyncio
    async def test_warmup_connections_excluded_from_the_baseline(self, engine_mock):
        opened = {"n": 0}

        async def _request(*_a, **_k):
            opened["n"] += 1
            await asyncio.sleep(0.002)
            return fake_result(2.0)

        engine_mock.get_connection_stats = MagicMock(
            side_effect=lambda _t: {"connections_opened": opened["n"]}
        )
        engine_mock.request_single = AsyncMock(side_effect=_request)
        engine = LoadTestEngine("https://example.com")
        summary = await engine.run_throughput(
            duration_s=0.1, max_concurrency=1, warmup_requests=4, graceful_stop_s=0.2
        )
        # The 4 warmup connections predate the snapshot, so the run's own count
        # is strictly smaller than the total opened.
        assert summary.connection_reuse.connections_opened < opened["n"]

    @pytest.mark.asyncio
    async def test_zero_warmup_is_a_no_op(self, engine_mock):
        engine = LoadTestEngine("https://example.com")
        assert await engine.warmup(0) == 0


class TestIntervalBucketConsistency:
    """_summarize used _build_intervals' default 1.0 while the streamer used
    self.interval_bucket_s, so a non-default bucket put the streamed intervals
    and summary.intervals on two different grids."""

    @pytest.mark.asyncio
    async def test_summary_uses_the_engine_bucket_width(self, engine_mock):
        streamed = []
        engine = LoadTestEngine(
            "https://example.com",
            interval_bucket_s=0.25,
            on_interval=streamed.append,
        )
        summary = await engine.run_throughput(
            duration_s=0.8, max_concurrency=2, graceful_stop_s=0.5
        )
        assert summary.interval_bucket_s == 0.25
        # A 0.8s run on a 0.25s grid has more than one window; on the old
        # default grid it would have had exactly one.
        assert len(summary.intervals) > 1
        assert {iv.window_index for iv in streamed} <= {
            iv.window_index for iv in summary.intervals
        }


# ---------------------------------------------------------------------------
# --- 0.5.2 display and validation fixes
# ---------------------------------------------------------------------------


class TestUnmergeableThresholdMessage:
    """A merged run reporting an un-mergeable metric was explained with the
    SAMPLE_DEPENDENT message — "the run had no successful requests" — on runs
    that had thousands. Right verdict, wrong reason, and it sends the reader to
    debug a failure that never happened."""

    def _merged(self):
        return merge_summaries([make_summary([100.0] * 20), make_summary([120.0] * 20)])

    def test_still_fails(self):
        results = self._merged().check_thresholds(
            [parse_threshold("p95_waiting_ms<500")]
        )
        assert not results[0].passed

    def test_reason_names_the_merge_not_a_failed_run(self):
        result = self._merged().check_thresholds(
            [parse_threshold("p95_waiting_ms<500")]
        )[0]
        assert "merged run" in result.error
        assert "no successful requests" not in result.error

    def test_reason_suggests_the_way_out(self):
        result = self._merged().check_thresholds(
            [parse_threshold("p95_waiting_ms<500")]
        )[0]
        assert "per worker" in result.error or "--workers 1" in result.error

    def test_failed_run_still_gets_the_sample_dependent_reason(self):
        # The other branch must not have been swallowed by the new one.
        result = make_summary([]).check_thresholds(
            [parse_threshold("p95_waiting_ms<500")]
        )[0]
        assert "no successful requests" in result.error

    def test_a_real_typo_still_reads_as_a_typo(self):
        result = self._merged().check_thresholds([parse_threshold("p95_latenci<500")])[
            0
        ]
        assert "unknown metric" in result.error


class TestKnownMetricNames:
    """--threshold used to validate only the SHAPE of the expression, so a
    mistyped metric name parsed fine and failed after the load had run."""

    def test_real_metrics_are_known(self):
        known = known_metric_names()
        for name in (
            "p95_latency",
            "p99_latency",
            "success_rate",
            "achieved_rps",
            "dropped_rate",
            "cert_expiry_days",
        ):
            assert name in known

    def test_conditional_metrics_are_in_the_superset(self):
        """Deliberately a superset: these are real names absent from SOME runs,
        and must reach evaluate_thresholds so the failure explains what
        actually happened rather than "unknown metric"."""
        known = known_metric_names()
        assert UNMERGEABLE_METRICS <= known
        assert "dropped_rate" in known  # absent on unpaced runs

    def test_typos_are_not_known(self):
        known = known_metric_names()
        for typo in ("p95_latenci", "sucess_rate", "rps_achieved", ""):
            assert typo not in known

    def test_superset_covers_what_a_real_run_emits(self):
        """Drift guard: if a metric is added to build_metric_namespace but not
        to the superset, the CLI would reject a valid threshold."""
        summary = make_summary(
            [100.0, 200.0], target_rps=50.0, mode=LoadTestMode.SUSTAINED
        )
        assert set(summary.metric_namespace()) <= known_metric_names()

    def test_superset_covers_a_merged_run_too(self):
        merged = merge_summaries([make_summary([100.0]), make_summary([200.0])])
        assert set(merged.metric_namespace()) <= known_metric_names()


class TestMergedSummaryDisplay:
    def test_p95_duration_is_not_printed_as_zero(self, monkeypatch):
        """It was shown as "P95 duration: 0.0 ms" directly above the line
        saying the phase p95s are not merged — the same misleading zero the
        namespace gate exists to prevent, one layer up."""
        from click.testing import CliRunner

        from net_benchmark.http_bench import cli as cli_module

        def _fake(config, workers, distribution=None, on_warning=None, **kwargs):
            summary = make_summary([100.0] * 10)
            return [
                DistributedResult(
                    target="https://example.com",
                    merged=merge_summaries([summary, make_summary([120.0] * 10)]),
                    workers=[WorkerResult(worker_id="w0", summary=summary)],
                )
            ]

        monkeypatch.setattr(cli_module, "run_distributed", _fake)
        runner = CliRunner()
        with runner.isolated_filesystem():
            result = runner.invoke(
                cli_module.http,
                [
                    "load-test",
                    "-t",
                    "https://example.com",
                    "--workers",
                    "2",
                    "--duration",
                    "1",
                ],
            )
        assert "P95 duration:     n/a" in result.output
        assert "P95 duration:     0.0 ms" not in result.output

    def test_typo_is_rejected_before_the_run(self, monkeypatch):
        from click.testing import CliRunner

        from net_benchmark.http_bench import cli as cli_module

        def _must_not_run(*_a, **_k):
            raise AssertionError("the load must not start on a mistyped metric")

        monkeypatch.setattr(cli_module, "run_distributed", _must_not_run)
        monkeypatch.setattr(cli_module, "run_worker_async", _must_not_run)
        runner = CliRunner()
        with runner.isolated_filesystem():
            result = runner.invoke(
                cli_module.http,
                [
                    "load-test",
                    "-t",
                    "https://example.com",
                    "--threshold",
                    "p95_latenci<500",
                ],
            )
        assert result.exit_code != 0
        assert "unknown metric" in result.output
        assert "p95_latency" in result.output  # the suggestion


# ---------------------------------------------------------------------------
# merge-load-test command
# ---------------------------------------------------------------------------


class TestMergeLoadTestCommand:
    """End-to-end coverage of the collector: it is the only path a
    cross-machine run takes, and its inputs arrive off disk from machines that
    may disagree — so the refusals matter as much as the happy path."""

    def _write(self, tmp_path, name, summaries):
        path = tmp_path / f"{name}.json"
        path.write_text(json.dumps([s.to_dict() for s in summaries]), "utf-8")
        return str(path)

    def _nodes(self, tmp_path):
        a = make_summary([100.0] * 50)
        b = make_summary([400.0] * 50)
        a.worker_id, b.worker_id = "hel1", "ash"
        return self._write(tmp_path, "a", [a]), self._write(tmp_path, "b", [b])

    def _run(self, args):
        from click.testing import CliRunner

        from net_benchmark.http_bench import cli as cli_module

        return CliRunner().invoke(cli_module.http, ["merge-load-test", *args])

    # -- happy path --------------------------------------------------------

    def test_merges_two_nodes(self, tmp_path):
        a, b = self._nodes(tmp_path)
        result = self._run([a, b, "-o", str(tmp_path / "out")])
        assert result.exit_code == 0
        assert "Workers merged:   2" in result.output
        assert "hel1" in result.output and "ash" in result.output

    def test_totals_are_the_sum(self, tmp_path):
        a, b = self._nodes(tmp_path)
        result = self._run([a, b, "-o", str(tmp_path / "out")])
        assert "Total requests:   100" in result.output

    def test_percentiles_come_from_the_merged_histogram(self, tmp_path):
        """50 requests at 100ms and 50 at 400ms: the union's p95 is ~400, not
        the ~250 an average of the two workers' p95s would give."""
        a, b = self._nodes(tmp_path)
        result = self._run([a, b, "-o", str(tmp_path / "out")])
        line = next(ln for ln in result.output.splitlines() if "P95 latency" in ln)
        value = float(line.split("P95 latency:")[1].split("ms")[0].strip())
        assert value > 350  # the union, not the midpoint
        assert "from merged histogram" in line

    def test_success_rate_is_reported(self, tmp_path):
        """The box reported volume and latency but no OUTCOME, so a run where a
        third of the requests were rejected read as clean."""
        a, b = self._nodes(tmp_path)
        result = self._run([a, b, "-o", str(tmp_path / "out")])
        assert "Successful:" in result.output

    def test_unexpected_status_is_surfaced(self, tmp_path):
        good = make_summary([100.0] * 10)
        bad = make_summary([100.0] * 10)
        # Set directly: this asserts the CLI DISPLAYS the rate; the analyzer's
        # computation of it is covered in test_analysis.py.
        bad.stats.unexpected_status_rate = 30.0
        good.worker_id, bad.worker_id = "ok", "limited"
        path = self._write(tmp_path, "mixed", [good, bad])
        result = self._run([path, "-o", str(tmp_path / "out")])
        assert result.exit_code == 0
        assert "Unexpected status" in result.output

    def test_groups_by_target(self, tmp_path):
        one = make_summary([100.0], target="https://a.test")
        two = make_summary([200.0], target="https://b.test")
        path = self._write(tmp_path, "both", [one, two])
        result = self._run([path, "-o", str(tmp_path / "out")])
        assert "https://a.test" in result.output
        assert "https://b.test" in result.output

    def test_quiet_suppresses_the_box(self, tmp_path):
        a, b = self._nodes(tmp_path)
        result = self._run([a, b, "-o", str(tmp_path / "out"), "--quiet"])
        assert result.exit_code == 0
        assert "Workers merged" not in result.output

    def test_a_single_payload_merges_to_itself(self, tmp_path):
        a, _ = self._nodes(tmp_path)
        result = self._run([a, "-o", str(tmp_path / "out")])
        assert result.exit_code == 0
        assert "Workers merged:   1" in result.output

    # -- exports -----------------------------------------------------------

    def test_writes_merged_and_per_worker_csv(self, tmp_path):
        a, b = self._nodes(tmp_path)
        out = tmp_path / "out"
        assert self._run([a, b, "-o", str(out), "-f", "csv"]).exit_code == 0
        names = [p.name for p in out.iterdir()]
        for suffix in ("_summary.csv", "_workers.csv", "_timeline.csv", "_errors.csv"):
            assert any(n.endswith(suffix) for n in names), suffix
        assert any("histogram" in n for n in names)

    def test_json_flag_writes_a_bundle(self, tmp_path):
        a, b = self._nodes(tmp_path)
        out = tmp_path / "out"
        result = self._run([a, b, "-o", str(out), "-f", "csv", "--json"])
        assert result.exit_code == 0
        assert any(p.suffix == ".json" for p in out.iterdir())

    def test_json_in_formats_also_writes_a_bundle(self, tmp_path):
        a, b = self._nodes(tmp_path)
        out = tmp_path / "out"
        assert self._run([a, b, "-o", str(out), "-f", "json"]).exit_code == 0
        assert any(p.suffix == ".json" for p in out.iterdir())

    def test_output_directory_is_created(self, tmp_path):
        a, b = self._nodes(tmp_path)
        out = tmp_path / "deep" / "nested"
        assert self._run([a, b, "-o", str(out)]).exit_code == 0
        assert out.is_dir()

    def test_invalid_format_is_rejected(self, tmp_path):
        a, b = self._nodes(tmp_path)
        assert "Invalid format" in self._run([a, b, "-f", "parquet"]).output

    # -- input handling ----------------------------------------------------

    def test_accepts_an_export_bundle_shape(self, tmp_path):
        path = tmp_path / "bundle.json"
        path.write_text(
            json.dumps({"targets": [make_summary([100.0]).to_dict()]}), "utf-8"
        )
        assert self._run([str(path), "-o", str(tmp_path / "out")]).exit_code == 0

    def test_missing_file_is_rejected_by_click(self, tmp_path):
        assert self._run([str(tmp_path / "nope.json")]).exit_code != 0

    def test_malformed_json_blames_the_file_not_the_merge(self, tmp_path):
        """json.JSONDecodeError subclasses ValueError, so a single combined
        handler with the merge branch first reported a truncated file as
        "Cannot merge" — pointing at the merge logic for a bad file."""
        path = tmp_path / "bad.json"
        path.write_text("{not json", "utf-8")
        result = self._run([str(path)])
        assert result.exit_code == 2
        assert "Could not read payloads" in result.output
        assert "Cannot merge" not in result.output

    def test_wrong_shape_exits_two(self, tmp_path):
        path = tmp_path / "wrong.json"
        path.write_text(json.dumps("a string"), "utf-8")
        assert self._run([str(path)]).exit_code == 2

    def test_at_least_one_payload_is_required(self):
        assert self._run([]).exit_code != 0

    # -- refusals: inputs that do not describe one run ---------------------

    def test_mismatched_modes_exit_two(self, tmp_path):
        a = make_summary([100.0], mode=LoadTestMode.THROUGHPUT)
        b = make_summary([100.0], mode=LoadTestMode.SUSTAINED, target_rps=10.0)
        result = self._run(
            [self._write(tmp_path, "a", [a]), self._write(tmp_path, "b", [b])]
        )
        assert result.exit_code == 2
        assert "different modes" in result.output

    def test_mismatched_bucket_widths_exit_two(self, tmp_path):
        a = make_summary([100.0])
        b = make_summary([100.0])
        b.interval_bucket_s = 0.5
        result = self._run(
            [self._write(tmp_path, "a", [a]), self._write(tmp_path, "b", [b])]
        )
        assert result.exit_code == 2
        assert "interval bucket widths" in result.output

    def test_disagreeing_epochs_exit_two(self, tmp_path):
        a = make_summary([100.0], start_epoch=1000.0)
        b = make_summary([100.0], start_epoch=2000.0)
        result = self._run(
            [self._write(tmp_path, "a", [a]), self._write(tmp_path, "b", [b])]
        )
        assert result.exit_code == 2

    def test_measured_clock_skew_exits_two(self, tmp_path):
        a = make_summary([100.0])
        b = make_summary([100.0])
        a.worker_id, b.worker_id = "hel1", "ash"
        b.clock_offset_s = 0.25
        result = self._run(
            [self._write(tmp_path, "a", [a]), self._write(tmp_path, "b", [b])]
        )
        assert result.exit_code == 2
        assert "clock skew" in result.output

    def test_a_refusal_writes_nothing(self, tmp_path):
        """A half-written output directory after a refused merge is worse than
        none — someone would read the stale files."""
        a = make_summary([100.0], start_epoch=1000.0)
        b = make_summary([100.0], start_epoch=2000.0)
        out = tmp_path / "out"
        self._run(
            [
                self._write(tmp_path, "a", [a]),
                self._write(tmp_path, "b", [b]),
                "-o",
                str(out),
            ]
        )
        assert not out.exists() or not list(out.iterdir())

    # -- thresholds --------------------------------------------------------

    def test_passing_threshold_exits_zero(self, tmp_path):
        a, b = self._nodes(tmp_path)
        result = self._run(
            [a, b, "-o", str(tmp_path / "out"), "--threshold", "p95_latency<5000"]
        )
        assert result.exit_code == 0
        assert "PASS" in result.output

    def test_failing_threshold_exits_one(self, tmp_path):
        a, b = self._nodes(tmp_path)
        result = self._run(
            [a, b, "-o", str(tmp_path / "out"), "--threshold", "p95_latency<1"]
        )
        assert result.exit_code == 1
        assert "Thresholds failed" in result.output

    def test_unmergeable_threshold_fails_with_the_merge_reason(self, tmp_path):
        a, b = self._nodes(tmp_path)
        result = self._run(
            [a, b, "-o", str(tmp_path / "out"), "--threshold", "p95_waiting_ms<500"]
        )
        assert result.exit_code == 1
        assert "merged run" in result.output

    def test_typo_is_rejected_before_any_payload_is_read(self, tmp_path):
        a, _ = self._nodes(tmp_path)
        result = self._run([a, "--threshold", "p95_latenci<500"])
        assert result.exit_code != 0
        assert "unknown metric" in result.output
