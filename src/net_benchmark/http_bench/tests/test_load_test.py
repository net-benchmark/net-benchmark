"""Unit tests for the load test engine (load_test.py)."""

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock

import pytest

from net_benchmark.http_bench.core import HTTPResult, QueryStatus
from net_benchmark.http_bench.load_test import (
    LoadTestEngine,
    LoadTestMode,
    _build_intervals,
    _summarize,
    _TimedResult,
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
        call_count = 0

        async def request_single(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            return fake_result(100.0 + call_count)

        mock_engine.request_single.side_effect = request_single

        engine = LoadTestEngine("https://example.com")
        summary = await engine.run_throughput(duration_s=1.0, max_concurrency=10)

        assert summary.mode == LoadTestMode.THROUGHPUT
        assert summary.stats.total_requests > 0
        assert summary.achieved_rps > 0
        assert summary.connection_reuse.connections_opened == 2
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
    async def test_connections_opened(self, mock_engine):
        engine = LoadTestEngine("https://example.com")
        opened = await engine._connections_opened()
        assert opened == 2
        mock_engine.get_connection_stats.assert_called_once_with("https://example.com")

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
