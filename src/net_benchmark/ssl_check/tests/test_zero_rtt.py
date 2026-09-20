"""Tests for `net_benchmark.ssl_check.zero_rtt`.

Runs a real `openssl s_server` subprocess as the test target and a real
`measure_zero_rtt_timing` call against it — there is no meaningful way to
mock "does the openssl CLI's early-data output parsing work" without
losing the point of the test. Skipped entirely when the `openssl` binary
isn't present in the test environment.
"""

from __future__ import annotations

import asyncio

import pytest

from net_benchmark.ssl_check.zero_rtt import (
    ZeroRttTimingResult,
    measure_zero_rtt_timing,
    openssl_available,
)

from .conftest import make_key

pytestmark = pytest.mark.skipif(
    not openssl_available(), reason="zero_rtt.py tests require the system openssl CLI"
)

# Generous CI margin; not related to the CLI's own 10.0s timeout.
_TEST_TIMEOUT_S = 25.0


@pytest.fixture
async def openssl_server(cert_factory, unused_tcp_port):
    """Starts a real `openssl s_server` with early-data support, on a
    free port, for the duration of one test. `-naccept 3` keeps it alive
    for the three connections `measure_zero_rtt_timing` makes.
    """
    cert_path, key_path, _ = cert_factory(
        common_name="localhost", key=make_key("rsa2048")
    )
    process = await asyncio.create_subprocess_exec(
        "openssl",
        "s_server",
        "-accept",
        str(unused_tcp_port),
        "-cert",
        str(cert_path),
        "-key",
        str(key_path),
        "-tls1_3",
        "-early_data",
        "-max_early_data",
        "16384",
        "-naccept",
        "3",
        "-quiet",
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )
    await asyncio.sleep(1)  # let the listener come up
    try:
        yield unused_tcp_port
    finally:
        # The server exits on its own once it's handled its -naccept 3
        # quota — which is exactly what a successful test run causes, so
        # "already exited" here is the normal case, not a fixture bug.
        if process.returncode is None:
            process.kill()
            await process.wait()


class TestMeasureZeroRttTiming:
    async def test_real_server_produces_all_three_timings(self, openssl_server) -> None:
        result = await measure_zero_rtt_timing(
            "localhost", openssl_server, timeout=_TEST_TIMEOUT_S
        )
        assert result.attempted is True
        assert result.available is True
        assert result.error is None
        assert result.full_handshake_ms is not None
        assert result.resumed_no_early_data_ms is not None
        assert result.resumed_with_early_data_ms is not None
        assert result.early_data_status in (
            "accepted",
            "rejected",
            "not_sent",
            "unknown",
        )

    async def test_savings_computed_from_real_timings(self, openssl_server) -> None:
        result = await measure_zero_rtt_timing(
            "localhost", openssl_server, timeout=_TEST_TIMEOUT_S
        )
        assert result.resumption_savings_ms == pytest.approx(
            result.full_handshake_ms - result.resumed_no_early_data_ms
        )
        assert result.early_data_savings_ms == pytest.approx(
            result.resumed_no_early_data_ms - result.resumed_with_early_data_ms
        )

    async def test_unreachable_target_reports_error_not_exception(self) -> None:
        result = await measure_zero_rtt_timing("localhost", 1, timeout=3)
        assert result.attempted is True
        assert result.available is True
        assert result.error is not None
        assert result.resumed_no_early_data_ms is None

    async def test_connection_3_failure_does_not_discard_earlier_savings(
        self, openssl_server, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Regression coverage for a real bug: connections 1 and 2 succeed
        for real against a real server, but connection 3 is forced to
        raise TimeoutError — resumption_savings_ms (computed entirely from
        connections 1 and 2's real data) must still be populated. An
        earlier version of this function computed it after connection 3's
        own block, inside the same try connection 3's exception unwound
        past, silently discarding perfectly good data whenever only the
        third connection failed.
        """
        import net_benchmark.ssl_check.zero_rtt as zero_rtt_module

        real_run_openssl = zero_rtt_module._run_openssl
        call_count = {"n": 0}

        async def _flaky_run_openssl(*args, **kwargs):
            call_count["n"] += 1
            # Connection 3 is the final `_run_openssl` call in the sequence.
            if call_count["n"] == 2:
                raise asyncio.TimeoutError()
            return await real_run_openssl(*args, **kwargs)

        monkeypatch.setattr(zero_rtt_module, "_run_openssl", _flaky_run_openssl)

        result = await measure_zero_rtt_timing(
            "localhost", openssl_server, timeout=_TEST_TIMEOUT_S
        )
        assert result.full_handshake_ms is not None
        assert result.resumed_no_early_data_ms is not None
        assert result.resumption_savings_ms is not None
        assert result.resumed_with_early_data_ms is None
        assert result.early_data_savings_ms is None
        assert result.error is not None


class TestOpensslAvailability:
    def test_available_when_installed(self) -> None:
        assert openssl_available() is True


class TestParseEarlyDataStatus:
    def test_accepted(self) -> None:
        from net_benchmark.ssl_check.zero_rtt import _parse_early_data_status

        assert (
            _parse_early_data_status("...\nEarly data was accepted\n...") == "accepted"
        )

    def test_rejected(self) -> None:
        from net_benchmark.ssl_check.zero_rtt import _parse_early_data_status

        assert (
            _parse_early_data_status("...\nEarly data was rejected\n...") == "rejected"
        )

    def test_not_sent(self) -> None:
        from net_benchmark.ssl_check.zero_rtt import _parse_early_data_status

        assert (
            _parse_early_data_status("...\nEarly data was not sent\n...") == "not_sent"
        )

    def test_unrecognised_format_is_unknown(self) -> None:
        from net_benchmark.ssl_check.zero_rtt import _parse_early_data_status

        assert _parse_early_data_status("some unrelated openssl output") == "unknown"


def test_to_dict_shape() -> None:
    result = ZeroRttTimingResult(
        attempted=True,
        available=True,
        full_handshake_ms=10.0,
        resumed_no_early_data_ms=8.0,
        resumed_with_early_data_ms=7.0,
        early_data_status="accepted",
    )
    d = result.to_dict()
    assert d["attempted"] is True
    assert d["early_data_status"] == "accepted"


def test_unavailable_when_binary_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    import shutil

    monkeypatch.setattr(shutil, "which", lambda name: None)

    async def _run() -> ZeroRttTimingResult:
        return await measure_zero_rtt_timing("example.com", 443)

    result = asyncio.run(_run())
    assert result.available is False
    assert result.attempted is True
    assert result.error is not None
