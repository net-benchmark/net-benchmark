"""Unit tests for the load test engine (load_test.py)."""

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock

import pytest

from net_benchmark.http_bench.analysis import LatencyHistogram, Threshold
from net_benchmark.http_bench.core import HTTPResult, QueryStatus
from net_benchmark.http_bench.load_test import (
    LoadTestEngine,
    LoadTestMode,
    RunCounters,
    _build_intervals,
    _merge_target_stats,
    _summarize,
    _TimedResult,
    _weighted_mean,
    merge_summaries,
)

# ---------------------------------------------------------------------------
# Helper to create a fake HTTPResult
# ---------------------------------------------------------------------------


def fake_result(
    total_ms: float = 100.0, status: QueryStatus = QueryStatus.SUCCESS
) -> HTTPResult:
    """Build a minimal HTTPResult for load-test engine tests."""
    now = time.time()
    return HTTPResult(
        target="https://example.com",
        method="GET",
        start_time=now,
        end_time=now + total_ms / 1000.0,
        total_ms=total_ms,
        status=status,
        iteration=1,
        http_status_code=200 if status == QueryStatus.SUCCESS else 500,
    )


# ---------------------------------------------------------------------------
# Tests for helper functions
# ---------------------------------------------------------------------------


class TestHelpers:
    def test_empty_timed_results(self):
        assert _build_intervals([]) == []

    def test_single_bucket(self):
        r = fake_result(100.0)
        tr = _TimedResult(result=r, completed_at_offset_s=0.5)
        intervals = _build_intervals([tr])
        assert len(intervals) == 1
        assert intervals[0].window_index == 0
        assert intervals[0].stats.total_requests == 1

    def test_multiple_buckets(self):
        results = [
            _TimedResult(fake_result(100.0), 0.3),
            _TimedResult(fake_result(200.0), 1.2),
            _TimedResult(fake_result(150.0), 2.7),
        ]
        intervals = _build_intervals(results, bucket_s=1.0)
        assert len(intervals) == 3
        assert intervals[0].window_index == 0
        assert intervals[0].stats.total_requests == 1
        assert intervals[1].window_index == 1
        assert intervals[1].stats.total_requests == 1
        assert intervals[2].window_index == 2
        assert intervals[2].stats.total_requests == 1

    def test_empty_summarize(self):
        summary = _summarize(
            mode=LoadTestMode.THROUGHPUT,
            target="https://example.com",
            duration_s=1.0,
            timed_results=[],
            target_rps=None,
            connections_opened=0,
        )
        assert summary.stats.total_requests == 0


# ---------------------------------------------------------------------------
# Tests for LoadTestEngine
# ---------------------------------------------------------------------------


class TestLoadTestEngine:
    @pytest.fixture
    def mock_engine(self, monkeypatch):
        """Replace HTTPBenchmarkEngine in load_test with a fully controllable mock."""
        instance = MagicMock()
        instance.request_single = AsyncMock()
        instance.close = AsyncMock()
        instance.get_connection_stats = MagicMock(
            return_value={"connections_opened": 2}
        )

        # Patch the class inside load_test.py so LoadTestEngine gets our mock
        monkeypatch.setattr(
            "net_benchmark.http_bench.load_test.HTTPBenchmarkEngine",
            MagicMock(return_value=instance),
        )
        return instance

    @pytest.mark.asyncio
    async def test_throughput_normal(self, mock_engine):
        """run_throughput is latency-bound, so the fake must have latency.

        The fake used to return immediately. run_throughput's slot workers
        then looped as fast as the CPU allowed for the full duration and
        appended a _TimedResult each time — hundreds of thousands of ~60-field
        dataclasses, which exhausts memory on a modest machine before the run
        ends. That is a property of a zero-latency mock, not of the engine:
        in production the request itself paces the loop.

        MOCKED_LATENCY_S below restores that pacing, which also makes the
        result count predictable enough to assert on.
        """
        MOCKED_LATENCY_S = 0.01
        DURATION_S = 0.5
        CONCURRENCY = 10

        call_count = 0

        async def request_single(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            await asyncio.sleep(MOCKED_LATENCY_S)
            return fake_result(100.0 + call_count)

        mock_engine.request_single.side_effect = request_single

        # --- 0.5.2: connections_opened is now a PER-RUN delta, not the
        # transport's cumulative counter. The fixture returns a constant 2, so
        # under the new semantics the correct answer is 0 — the engine arrived
        # with 2 connections already open and this run opened none. Returning
        # 2 then 5 exercises the baseline subtraction properly: 3 opened here.
        # (The old assertion of 2 was the pre-0.5.2 cumulative behaviour; it
        # was never reached because the unpaced fake exhausted memory first.)
        stats_calls = 0

        def get_connection_stats(_target):
            nonlocal stats_calls
            stats_calls += 1
            return {"connections_opened": 2 if stats_calls == 1 else 5}

        mock_engine.get_connection_stats.side_effect = get_connection_stats

        engine = LoadTestEngine("https://example.com")
        summary = await engine.run_throughput(
            duration_s=DURATION_S, max_concurrency=CONCURRENCY
        )

        assert summary.mode == LoadTestMode.THROUGHPUT
        assert summary.stats.total_requests > 0
        assert summary.achieved_rps > 0
        assert summary.connection_reuse.connections_opened == 3

        # Roughly DURATION_S / MOCKED_LATENCY_S * CONCURRENCY requests, i.e.
        # ~500 here. The bounds are deliberately loose so scheduler jitter and
        # slow CI cannot flake this, but tight enough that an unpaced spin
        # (which produced six figures) fails instead of quietly passing.
        theoretical = int(DURATION_S / MOCKED_LATENCY_S) * CONCURRENCY
        assert 0 < summary.stats.total_requests < theoretical * 3

        await engine.close()

    @pytest.mark.asyncio
    async def test_sustained_mode(self, mock_engine):
        target_rps = 50
        duration_s = 1.0

        async def fast_response(*args, **kwargs):
            return fake_result(10.0)

        mock_engine.request_single.side_effect = fast_response

        engine = LoadTestEngine("https://example.com")
        summary = await engine.run_sustained(
            target_rps=target_rps, duration_s=duration_s
        )

        assert summary.mode == LoadTestMode.SUSTAINED
        assert abs(summary.achieved_rps - target_rps) < target_rps * 0.2
        assert summary.target_rps == target_rps

    @pytest.mark.asyncio
    async def test_sustained_zero_rps_raises(self, mock_engine):
        engine = LoadTestEngine("https://example.com")
        with pytest.raises(ValueError, match="target_rps must be > 0"):
            await engine.run_sustained(target_rps=0, duration_s=1.0)

    @pytest.mark.asyncio
    async def test_ramp_up_mode(self, mock_engine):
        async def slow_response(*args, **kwargs):
            await asyncio.sleep(0.05)
            return fake_result(50.0)

        mock_engine.request_single.side_effect = slow_response

        engine = LoadTestEngine("https://example.com")
        summary = await engine.run_ramp_up(
            start_concurrency=1,
            max_concurrency=5,
            ramp_duration_s=2.0,
            hold_duration_s=1.0,
        )
        assert summary.mode == LoadTestMode.RAMP_UP
        assert summary.stats.total_requests > 0

    @pytest.mark.asyncio
    async def test_ramp_up_invalid_args(self, mock_engine):
        engine = LoadTestEngine("https://example.com")
        with pytest.raises(ValueError):
            await engine.run_ramp_up(
                start_concurrency=0, max_concurrency=10, ramp_duration_s=1
            )
        with pytest.raises(ValueError):
            await engine.run_ramp_up(
                start_concurrency=10, max_concurrency=5, ramp_duration_s=1
            )

    @pytest.mark.asyncio
    async def test_engine_close(self, mock_engine):
        engine = LoadTestEngine("https://example.com")
        await engine.close()
        mock_engine.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_raw_connections_opened(self, mock_engine):
        """0.5.2: _connections_opened() was split into a raw cumulative read
        and a per-run delta. This covers the raw read."""
        engine = LoadTestEngine("https://example.com")
        opened = await engine._raw_connections_opened()
        assert opened == 2
        mock_engine.get_connection_stats.assert_called_once_with("https://example.com")

    @pytest.mark.asyncio
    async def test_connections_opened_since_subtracts_baseline(self, mock_engine):
        """0.5.2: the transport's counter is cumulative for the life of the
        transport and never reset, so an injected engine can start a run with
        it already non-zero (warmup, an earlier run_* call, or the SaaS layer
        reusing one engine). Without the baseline the raw count leaks into
        ConnectionReuseStats, where max(0, total - opened) clamps the
        overcount to zero and yields a plausible but wrong reuse rate."""
        engine = LoadTestEngine("https://example.com")

        engine._conn_baseline = 0
        assert await engine._connections_opened_since() == 2

        # Engine arrived with 2 connections already open: this run opened none.
        engine._conn_baseline = 2
        assert await engine._connections_opened_since() == 0

        # Never negative, even if the counter somehow regresses.
        engine._conn_baseline = 5
        assert await engine._connections_opened_since() == 0

    @pytest.mark.asyncio
    async def test_intervals_populated(self, mock_engine):
        async def response_with_delay(*args, **kwargs):
            await asyncio.sleep(0.1)
            return fake_result(50.0)

        mock_engine.request_single.side_effect = response_with_delay

        engine = LoadTestEngine("https://example.com")
        summary = await engine.run_throughput(duration_s=0.5, max_concurrency=5)
        assert len(summary.intervals) > 0

    @pytest.mark.asyncio
    async def test_ramp_up_max_total_rps_ceiling(self, mock_engine):
        """Instant-response mock + a low max_total_rps should keep achieved
        RPS near the ceiling instead of exploding, proving the shared
        token bucket in slot_worker actually throttles aggregate rate."""

        async def instant_response(*args, **kwargs):
            return fake_result(1.0)

        mock_engine.request_single.side_effect = instant_response

        engine = LoadTestEngine("https://example.com")
        summary = await engine.run_ramp_up(
            start_concurrency=5,
            max_concurrency=20,
            ramp_duration_s=0.5,
            hold_duration_s=0.5,
            max_total_rps=50,
        )

        # Allow generous slack for scheduling jitter over a ~1s run —
        # this asserts "bounded near the ceiling", not "exactly 50".
        assert summary.achieved_rps < 50 * 1.5
        assert summary.stats.total_requests > 0


class TestLoadTestSummaryToDict:
    def test_to_dict_structure(self):
        r1 = fake_result(100.0, QueryStatus.SUCCESS)
        r2 = fake_result(200.0, QueryStatus.TIMEOUT)
        timed_results = [
            _TimedResult(r1, 0.2),
            _TimedResult(r2, 0.4),
        ]
        summary = _summarize(
            mode=LoadTestMode.SUSTAINED,
            target="https://example.com",
            duration_s=1.0,
            timed_results=timed_results,
            target_rps=50.0,
            connections_opened=2,
        )

        d = summary.to_dict()

        # Top-level scalar fields
        assert d["mode"] == "sustained"  # enum -> .value, not the Enum member
        assert d["target"] == "https://example.com"
        assert d["duration_s"] == 1.0
        assert d["target_rps"] == 50.0
        assert d["achieved_rps"] == summary.achieved_rps

        # stats: vars(TargetStats) -> plain dict
        assert isinstance(d["stats"], dict)
        assert d["stats"]["total_requests"] == 2

        # status_code_distribution passed through as-is
        assert isinstance(d["status_code_distribution"], list)

        # connection_reuse: hand-built dict, not vars(dataclass), so check
        # each derived property was materialized as a plain value
        conn = d["connection_reuse"]
        assert conn["total_requests"] == 2
        assert conn["connections_opened"] == 2
        assert conn["connections_reused"] == summary.connection_reuse.connections_reused
        assert conn["reuse_rate"] == pytest.approx(summary.connection_reuse.reuse_rate)

        # intervals: list of dicts, each with vars(stats) nested
        assert isinstance(d["intervals"], list)
        assert len(d["intervals"]) == len(summary.intervals)
        for iv_dict, iv in zip(d["intervals"], summary.intervals):
            assert iv_dict["window_index"] == iv.window_index
            assert isinstance(iv_dict["stats"], dict)
            assert iv_dict["status_code_distribution"] == iv.status_code_distribution

    def test_to_dict_empty_summary_is_json_safe(self):
        summary = _summarize(
            mode=LoadTestMode.THROUGHPUT,
            target="https://example.com",
            duration_s=1.0,
            timed_results=[],
            target_rps=None,
            connections_opened=0,
        )

        d = summary.to_dict()

        assert d["target_rps"] is None
        assert d["achieved_rps"] == 0.0
        assert d["intervals"] == []
        assert d["stats"]["total_requests"] == 0

        # Round-trips through json without error (this is what JSON export
        # actually relies on) — enums, dataclasses, etc. must already be
        # plain values by the time to_dict() returns.
        import json

        json.dumps(d)


# ---------------------------------------------------------------------------
# --- 0.5.2: shared wall-clock start epoch (item 1)
# ---------------------------------------------------------------------------


class TestStartAtEpoch:
    """start_at anchors offsets to a shared epoch so separate processes
    produce comparable window_index / completed_at_offset_s values."""

    @pytest.fixture
    def mock_engine(self, monkeypatch):
        instance = MagicMock()
        instance.request_single = AsyncMock()
        instance.close = AsyncMock()
        instance.get_connection_stats = MagicMock(
            return_value={"connections_opened": 1}
        )
        monkeypatch.setattr(
            "net_benchmark.http_bench.load_test.HTTPBenchmarkEngine",
            MagicMock(return_value=instance),
        )
        return instance

    @staticmethod
    def _paced(latency_s=0.01):
        async def request_single(*args, **kwargs):
            await asyncio.sleep(latency_s)
            return fake_result(latency_s * 1000)

        return request_single

    @pytest.mark.asyncio
    async def test_default_is_unchanged(self, mock_engine):
        """No start_at -> no epoch, and offsets stay perf_counter-relative."""
        mock_engine.request_single.side_effect = self._paced()
        engine = LoadTestEngine("https://example.com")
        summary = await engine.run_throughput(duration_s=0.2, max_concurrency=3)

        assert summary.start_epoch is None
        # perf_counter-relative: the run's own elapsed time, near duration_s.
        assert summary.duration_s < 1.0
        assert summary.intervals[0].window_index == 0

    @pytest.mark.asyncio
    async def test_future_epoch_waits_for_the_barrier(self, mock_engine):
        """A start_at in the future is the synchronisation point: the run
        sleeps until it, so all workers begin together."""
        mock_engine.request_single.side_effect = self._paced()
        engine = LoadTestEngine("https://example.com")

        delay_s = 0.3
        start_at = time.time() + delay_s
        began = time.perf_counter()
        summary = await engine.run_throughput(
            duration_s=0.2, max_concurrency=3, start_at=start_at
        )
        elapsed = time.perf_counter() - began

        # Waited out the barrier before issuing anything.
        assert elapsed >= delay_s
        assert summary.start_epoch == start_at
        # Offsets restart from the epoch, so the barrier wait is NOT counted
        # as run time.
        assert summary.duration_s < delay_s + 0.5
        assert summary.intervals[0].window_index == 0

    @pytest.mark.asyncio
    async def test_past_epoch_records_lateness_rather_than_re_zeroing(
        self, mock_engine
    ):
        """A worker that joins late must show up as late. Re-zeroing would
        fabricate overlap with the workers that started on time."""
        mock_engine.request_single.side_effect = self._paced()
        engine = LoadTestEngine("https://example.com")

        lateness_s = 2.5
        start_at = time.time() - lateness_s
        summary = await engine.run_throughput(
            duration_s=0.2, max_concurrency=3, start_at=start_at
        )

        assert summary.start_epoch == start_at
        # Every result landed at least `lateness_s` into the shared window.
        assert summary.intervals[0].window_index >= 2
        assert summary.duration_s >= lateness_s

    @pytest.mark.asyncio
    async def test_two_workers_share_a_window_index(self, mock_engine):
        """The point of item 1: a worker that starts a second late reports
        window 1+, not window 0, so merging by index cannot misalign."""
        mock_engine.request_single.side_effect = self._paced()
        start_at = time.time()

        on_time = LoadTestEngine("https://example.com")
        first = await on_time.run_throughput(
            duration_s=0.3, max_concurrency=3, start_at=start_at
        )

        # Second worker joins more than a bucket later, same epoch. Its own
        # perf_counter would call this window 0; the epoch must not.
        await asyncio.sleep(1.1)
        late = LoadTestEngine("https://example.com")
        second = await late.run_throughput(
            duration_s=0.3, max_concurrency=3, start_at=start_at
        )

        assert first.intervals[0].window_index == 0
        # Its own clock would say 0; the shared epoch says otherwise.
        assert second.intervals[0].window_index > first.intervals[0].window_index

    @pytest.mark.asyncio
    async def test_sustained_records_epoch(self, mock_engine):
        mock_engine.request_single.side_effect = self._paced(0.005)
        engine = LoadTestEngine("https://example.com")
        start_at = time.time()
        summary = await engine.run_sustained(
            target_rps=50.0, duration_s=0.2, start_at=start_at
        )
        assert summary.start_epoch == start_at

    @pytest.mark.asyncio
    async def test_sustained_deadline_is_absolute_under_an_epoch(self, mock_engine):
        """stop_at derives from the epoch, so every worker stops at the same
        wall-clock instant and a late worker simply runs shorter."""
        mock_engine.request_single.side_effect = self._paced(0.005)
        engine = LoadTestEngine("https://example.com")

        # Epoch already 1.0s old against a 1.2s run: only ~0.2s of the shared
        # window is left, so far fewer fires are scheduled than 50 * 1.2.
        summary = await engine.run_sustained(
            target_rps=50.0, duration_s=1.2, start_at=time.time() - 1.0
        )
        assert summary.counters.scheduled < 50

    @pytest.mark.asyncio
    async def test_late_worker_does_not_replay_missed_fires_as_a_burst(
        self, mock_engine
    ):
        """Regression: next_fire starting in the past made the pacer issue
        every elapsed slot back-to-back — the same catch-up burst run_sustained
        was rewritten to eliminate, just sourced from clock skew. A late worker
        should join the schedule where it is, not where it would have been."""
        mock_engine.request_single.side_effect = self._paced(0.005)
        engine = LoadTestEngine("https://example.com")

        summary = await engine.run_sustained(
            target_rps=50.0, duration_s=1.5, start_at=time.time() - 1.0
        )

        # Only the ~0.5s of window that was left gets scheduled...
        assert summary.counters.scheduled < 40
        # ...and no request carries a queue delay anywhere near the 1.0s of
        # skew, which is what a replayed burst would have produced.
        assert summary.counters.max_queue_delay_ms < 500.0

    @pytest.mark.asyncio
    async def test_default_sustained_does_not_skip_its_first_fire(self, mock_engine):
        """The skip above is guarded on _epoch: on the default path
        _start_time was read microseconds ago, and flooring there would drop
        the run's first scheduled request."""
        mock_engine.request_single.side_effect = self._paced(0.005)
        engine = LoadTestEngine("https://example.com")
        summary = await engine.run_sustained(target_rps=20.0, duration_s=0.5)
        # 20 rps over 0.5s is 10 slots (11 when `next_fire += interval`
        # accumulates just under the deadline — that drift is pre-existing and
        # not what this asserts). The property under test is that none are
        # skipped at the front.
        assert summary.counters.scheduled >= 10

    @pytest.mark.asyncio
    async def test_ramp_up_records_epoch(self, mock_engine):
        mock_engine.request_single.side_effect = self._paced(0.005)
        engine = LoadTestEngine("https://example.com")
        start_at = time.time()
        summary = await engine.run_ramp_up(
            start_concurrency=2,
            max_concurrency=4,
            ramp_duration_s=0.2,
            hold_duration_s=0.1,
            step_interval_s=0.1,
            start_at=start_at,
        )
        assert summary.start_epoch == start_at

    def test_to_dict_carries_start_epoch(self):
        summary = _summarize(
            mode=LoadTestMode.THROUGHPUT,
            target="https://example.com",
            duration_s=1.0,
            timed_results=[_TimedResult(fake_result(100.0), 0.5)],
            target_rps=None,
            connections_opened=0,
            start_epoch=1234567890.5,
        )
        assert summary.to_dict()["start_epoch"] == 1234567890.5


# ---------------------------------------------------------------------------
# --- 0.5.2: merge_summaries (item 2)
# ---------------------------------------------------------------------------


def make_summary(
    latencies,
    duration_s=10.0,
    offsets=None,
    mode=LoadTestMode.THROUGHPUT,
    target="https://example.com",
    target_rps=None,
    connections_opened=0,
    counters=None,
    start_epoch=None,
    statuses=None,
):
    """Build a real LoadTestSummary via _summarize, so the merged inputs carry
    genuine TargetStats and LatencyHistogram objects rather than hand-built
    ones that could drift from what the analyzer actually produces."""
    if offsets is None:
        offsets = [0.5] * len(latencies)
    if statuses is None:
        statuses = [QueryStatus.SUCCESS] * len(latencies)
    timed = [
        _TimedResult(fake_result(lat, status), off)
        for lat, off, status in zip(latencies, offsets, statuses)
    ]
    return _summarize(
        mode=mode,
        target=target,
        duration_s=duration_s,
        timed_results=timed,
        target_rps=target_rps,
        connections_opened=connections_opened,
        counters=counters,
        start_epoch=start_epoch,
    )


class TestMergeSummariesValidation:
    def test_empty_raises(self):
        with pytest.raises(ValueError, match="at least one summary"):
            merge_summaries([])

    def test_single_summary_is_identity(self):
        s = make_summary([100.0, 200.0])
        assert merge_summaries([s]) is s

    def test_mixed_modes_raise(self):
        a = make_summary([100.0], mode=LoadTestMode.THROUGHPUT)
        b = make_summary([100.0], mode=LoadTestMode.SUSTAINED)
        with pytest.raises(ValueError, match="different modes"):
            merge_summaries([a, b])

    def test_mixed_targets_raise(self):
        a = make_summary([100.0], target="https://a.example")
        b = make_summary([100.0], target="https://b.example")
        with pytest.raises(ValueError, match="different targets"):
            merge_summaries([a, b])

    def test_partial_epoch_raises(self):
        a = make_summary([100.0], start_epoch=1000.0)
        b = make_summary([100.0], start_epoch=None)
        with pytest.raises(ValueError, match="some carry a start_epoch"):
            merge_summaries([a, b])

    def test_disagreeing_epochs_raise(self):
        a = make_summary([100.0], start_epoch=1000.0)
        b = make_summary([100.0], start_epoch=1000.5)
        with pytest.raises(ValueError, match="disagree by"):
            merge_summaries([a, b])

    def test_epochs_within_tolerance_merge(self):
        """Sub-millisecond drift from a Postgres/JSON round trip cannot
        misalign a one-second bucket, so it must not block the merge."""
        a = make_summary([100.0], start_epoch=1000.0)
        b = make_summary([100.0], start_epoch=1000.0 + 5e-4)
        merged = merge_summaries([a, b])
        assert merged.stats.total_requests == 2
        assert merged.start_epoch == 1000.0

    def test_no_epoch_anywhere_still_merges(self):
        """Several engines in one process share an origin closely enough."""
        merged = merge_summaries([make_summary([100.0]), make_summary([200.0])])
        assert merged.start_epoch is None
        assert merged.stats.total_requests == 2


class TestMergeSummariesArithmetic:
    def test_counts_and_bytes_sum(self):
        a = make_summary([100.0, 110.0, 120.0])
        b = make_summary([200.0, 210.0])
        merged = merge_summaries([a, b])

        assert merged.stats.total_requests == 5
        assert merged.stats.successful_requests == 5
        assert merged.stats.responded_requests == 5
        assert merged.stats.total_response_bytes == (
            a.stats.total_response_bytes + b.stats.total_response_bytes
        )

    def test_achieved_rps_is_requests_over_window_not_an_average(self):
        """The specific accuracy bug this exists to avoid.

        Worker A: 100 requests over the full 10s window.
        Worker B: 100 requests but only the last 5s of it (joined late).
        Correct answer is 200 / 10 = 20 rps. Averaging the two achieved_rps
        (10 and 20) gives 15; summing them gives 30. Both are wrong.
        """
        a = make_summary([100.0] * 100, duration_s=10.0, start_epoch=1000.0)
        b = make_summary([100.0] * 100, duration_s=5.0, start_epoch=1000.0)
        assert a.achieved_rps == pytest.approx(10.0)
        assert b.achieved_rps == pytest.approx(20.0)

        merged = merge_summaries([a, b])

        assert merged.duration_s == pytest.approx(10.0)  # synchronised window
        assert merged.achieved_rps == pytest.approx(20.0)
        assert merged.achieved_rps != pytest.approx(15.0)  # not the average
        assert merged.achieved_rps != pytest.approx(30.0)  # not the sum

    def test_percentiles_come_from_the_merged_histogram(self):
        """Averaging p95s is the bug; recomputing from merged buckets is the
        fix. A 50/50 mix of fast and slow puts the true p95 in the slow half,
        nowhere near the midpoint of the two workers' p95s."""
        fast = make_summary([10.0] * 100)
        slow = make_summary([1000.0] * 100)
        naive_average = (fast.stats.p95_latency + slow.stats.p95_latency) / 2

        merged = merge_summaries([fast, slow])

        assert merged.stats.p95_latency == pytest.approx(1000.0, rel=0.01)
        assert merged.stats.p95_latency > naive_average * 1.5
        # And it agrees with folding the histograms directly.
        direct = LatencyHistogram.merge_all(
            [fast.stats.latency_histogram, slow.stats.latency_histogram]
        )
        assert merged.stats.p95_latency == pytest.approx(direct.quantile(0.95))

    def test_histogram_is_merged_and_exact_where_it_claims_to_be(self):
        a = make_summary([10.0, 20.0, 30.0])
        b = make_summary([40.0, 50.0])
        merged = merge_summaries([a, b])

        hist = merged.stats.latency_histogram
        assert hist is not None
        assert hist.count == 5
        # count/total/min/max are tracked exactly, not bucketed.
        assert hist.min_ms == pytest.approx(10.0)
        assert hist.max_ms == pytest.approx(50.0)
        assert hist.mean == pytest.approx(30.0)
        assert merged.stats.avg_latency == pytest.approx(30.0)
        assert merged.stats.min_latency == pytest.approx(10.0)
        assert merged.stats.max_latency == pytest.approx(50.0)

    def test_rates_are_weighted_by_their_own_denominator(self):
        """A worker with 1 request must not move a rate as much as one with
        99. 1 failure in 100 total is 1%, not the mean of 0% and 100%."""
        big = make_summary([100.0] * 99)
        small = make_summary([100.0], statuses=[QueryStatus.TIMEOUT])

        merged = merge_summaries([big, small])

        assert merged.stats.total_requests == 100
        assert merged.stats.success_rate == pytest.approx(99.0)
        # fake_result always carries an http_status_code, so the failure DID
        # get a response: it is an unexpected status, not a transport error.
        # Both rates share the /total denominator and the same weighting path.
        assert merged.stats.unexpected_status_rate == pytest.approx(1.0)
        assert merged.stats.transport_error_rate == pytest.approx(0.0)

    def test_unmergeable_phase_percentiles_are_left_unset(self):
        """Documents the known limitation: only total_ms has a mergeable
        histogram, so phase percentiles and dispersion are NOT recovered.
        They are zeroed rather than invented."""
        a = make_summary([100.0] * 10)
        b = make_summary([500.0] * 10)
        merged = merge_summaries([a, b])

        assert merged.stats.p95_waiting_ms == 0.0
        assert merged.stats.p95_duration_ms == 0.0
        assert merged.stats.p95_blocked_ms == 0.0
        assert merged.stats.p95_ttfb_ms == 0.0
        assert merged.stats.std_latency == 0.0
        assert merged.stats.jitter == 0.0
        # But the total_ms percentiles ARE recovered.
        assert merged.stats.p95_latency > 0.0


class TestMergeSummariesFields:
    def test_target_rps_sums(self):
        a = make_summary([100.0], target_rps=250.0, mode=LoadTestMode.SUSTAINED)
        b = make_summary([100.0], target_rps=250.0, mode=LoadTestMode.SUSTAINED)
        assert merge_summaries([a, b]).target_rps == pytest.approx(500.0)

    def test_target_rps_none_when_unpaced(self):
        a = make_summary([100.0])
        b = make_summary([100.0])
        assert merge_summaries([a, b]).target_rps is None

    def test_connection_reuse_sums(self):
        a = make_summary([100.0] * 10, connections_opened=2)
        b = make_summary([100.0] * 10, connections_opened=3)
        merged = merge_summaries([a, b])
        assert merged.connection_reuse.total_requests == 20
        assert merged.connection_reuse.connections_opened == 5
        assert merged.connection_reuse.connections_reused == 15

    def test_error_breakdown_unions(self):
        a = make_summary(
            [100.0, 100.0],
            statuses=[QueryStatus.TIMEOUT, QueryStatus.SUCCESS],
        )
        b = make_summary([100.0], statuses=[QueryStatus.TIMEOUT])
        merged = merge_summaries([a, b])
        assert sum(merged.error_breakdown.values()) == 2

    def test_counters_sum(self):
        a = make_summary(
            [100.0] * 10,
            mode=LoadTestMode.SUSTAINED,
            counters=RunCounters(
                scheduled=100, started=90, dropped=10, paced=True, worker_errors=1
            ),
        )
        b = make_summary(
            [100.0] * 10,
            mode=LoadTestMode.SUSTAINED,
            counters=RunCounters(
                scheduled=100, started=95, dropped=5, paced=True, interrupted=2
            ),
        )
        merged = merge_summaries([a, b])

        assert merged.counters.scheduled == 200
        assert merged.counters.started == 185
        assert merged.counters.dropped == 15
        assert merged.counters.worker_errors == 1
        assert merged.counters.interrupted == 2
        assert merged.counters.paced is True
        assert merged.dropped_rate == pytest.approx(7.5)

    def test_paced_requires_all_not_any(self):
        """A mixed merge must not expose dropped_rate: its denominator would
        not be a schedule. metric_namespace then omits it, so a threshold on
        it fails loudly instead of passing vacuously."""
        a = make_summary(
            [100.0],
            counters=RunCounters(scheduled=10, started=10, paced=True),
        )
        b = make_summary(
            [100.0],
            counters=RunCounters(scheduled=10, started=10, paced=False),
        )
        merged = merge_summaries([a, b])
        assert merged.counters.paced is False
        assert "dropped_rate" not in merged.metric_namespace()

    def test_queue_delay_is_weighted_by_sample_count(self):
        """Averaging the averages would let 1 request outvote 99."""
        big = make_summary(
            [100.0] * 99,
            mode=LoadTestMode.SUSTAINED,
            counters=RunCounters(avg_queue_delay_ms=1.0, max_queue_delay_ms=2.0),
        )
        small = make_summary(
            [100.0],
            mode=LoadTestMode.SUSTAINED,
            counters=RunCounters(avg_queue_delay_ms=101.0, max_queue_delay_ms=500.0),
        )
        merged = merge_summaries([big, small])

        # (1.0 * 99 + 101.0 * 1) / 100 == 2.0, not the unweighted mean of 51.0
        assert merged.counters.avg_queue_delay_ms == pytest.approx(2.0)
        assert merged.counters.max_queue_delay_ms == pytest.approx(500.0)

    def test_intervals_align_by_window_index(self):
        """Only meaningful because item 1 gave both workers one time origin."""
        a = make_summary(
            [100.0, 100.0], offsets=[0.5, 1.5], duration_s=2.0, start_epoch=1000.0
        )
        b = make_summary(
            [100.0, 100.0], offsets=[1.5, 2.5], duration_s=3.0, start_epoch=1000.0
        )
        merged = merge_summaries([a, b])

        windows = {iv.window_index: iv.stats.total_requests for iv in merged.intervals}
        assert windows == {0: 1, 1: 2, 2: 1}
        # Ordered, and gaps stay absent rather than becoming zero-dips.
        assert [iv.window_index for iv in merged.intervals] == [0, 1, 2]

    def test_interval_stats_use_the_same_merge_as_the_overall_stats(self):
        a = make_summary([10.0] * 50, offsets=[0.5] * 50, start_epoch=1000.0)
        b = make_summary([1000.0] * 50, offsets=[0.5] * 50, start_epoch=1000.0)
        merged = merge_summaries([a, b])

        assert len(merged.intervals) == 1
        window = merged.intervals[0].stats
        assert window.total_requests == 100
        assert window.p95_latency == pytest.approx(merged.stats.p95_latency)

    def test_status_distribution_pct_recomputed_against_merged_total(self):
        a = make_summary([100.0] * 3)
        b = make_summary([100.0], statuses=[QueryStatus.TIMEOUT])
        merged = merge_summaries([a, b])

        total_pct = sum(row["pct"] for row in merged.status_code_distribution)
        assert total_pct == pytest.approx(100.0)
        by_code = {row["status_code"]: row for row in merged.status_code_distribution}
        assert by_code[200]["count"] == 3
        assert by_code[200]["pct"] == pytest.approx(75.0)

    def test_results_concatenate_and_survive_retain_results_false(self):
        a = make_summary([100.0, 110.0])
        b = make_summary([200.0])
        b.results = []  # what retain_results=False leaves behind

        merged = merge_summaries([a, b])
        assert len(merged.results) == 2
        # Statistics are unaffected by the dropped raw results.
        assert merged.stats.total_requests == 3

    def test_merged_summary_is_json_safe(self):
        import json

        a = make_summary([100.0, 200.0], start_epoch=1000.0)
        b = make_summary([300.0], start_epoch=1000.0)
        merged = merge_summaries([a, b])

        d = merged.to_dict()
        json.dumps(d)
        assert d["start_epoch"] == 1000.0
        assert d["latency_histogram"]["count"] == 3

    def test_merged_summary_supports_thresholds(self):
        """The merged object must be usable by the existing CI-gate path."""
        a = make_summary([100.0] * 10)
        b = make_summary([100.0] * 10)
        merged = merge_summaries([a, b])

        ns = merged.metric_namespace()
        assert ns["achieved_rps"] == pytest.approx(merged.achieved_rps)
        assert merged.passed([Threshold("p95_latency", "<", 500.0)])


class TestMergeTargetStatsHelpers:
    def test_weighted_mean_ignores_zero_weight_and_nan(self):
        assert _weighted_mean([(10.0, 1.0), (20.0, 3.0)]) == pytest.approx(17.5)
        assert _weighted_mean([(10.0, 0.0), (20.0, 1.0)]) == pytest.approx(20.0)
        assert _weighted_mean([(float("nan"), 5.0), (20.0, 1.0)]) == pytest.approx(20.0)
        assert _weighted_mean([]) == 0.0

    def test_merge_target_stats_of_empty_parts(self):
        empty = make_summary([])
        merged = _merge_target_stats("https://example.com", [empty.stats, empty.stats])
        assert merged.total_requests == 0
        assert merged.target == "https://example.com"

    def test_merge_refuses_mismatched_histogram_layouts(self):
        """Propagated from LatencyHistogram.merge on purpose — a merge across
        incompatible bucket layouts is meaningless, not recoverable."""
        a = make_summary([100.0])
        b = make_summary([100.0])
        b.stats.latency_histogram = LatencyHistogram.from_values(
            [100.0], sub_buckets=64
        )
        with pytest.raises(ValueError, match="cannot merge LatencyHistograms"):
            merge_summaries([a, b])
