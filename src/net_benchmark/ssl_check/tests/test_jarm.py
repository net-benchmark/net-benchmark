"""Tests for `net_benchmark.ssl_check.jarm`.

Requires the `[crypto]` extra (pyjarm) to exercise the real probe path.
"""

from __future__ import annotations

import pytest

pytest.importorskip("jarm", reason="jarm.py tests require the [crypto] extra (pyjarm)")

from net_benchmark.ssl_check.jarm import (  # noqa: E402
    JarmAvailability,
    jarm_availability,
    probe_jarm,
)


class TestAvailability:
    def test_available_when_installed(self) -> None:
        assert jarm_availability() is JarmAvailability.AVAILABLE


class TestProbeJarm:
    async def test_real_local_server_produces_fingerprint(self, tls_server) -> None:
        from .conftest import make_key

        handle = await tls_server(key=make_key("rsa2048"))
        result = await probe_jarm("localhost", handle.port, timeout=10)
        assert result.attempted is True
        assert result.error is None
        assert result.fingerprint is not None
        assert len(result.fingerprint) == 62

    async def test_unreachable_target_returns_zero_fingerprint_not_error(
        self,
    ) -> None:
        # JARM's own semantics: a target that never completes any of the
        # ten probe handshakes yields an all-zero fingerprint -- that is
        # the correct, meaningful JARM result for "not a TLS server here",
        # not a probe failure. Confirmed directly rather than assumed
        # before writing this assertion.
        result = await probe_jarm("localhost", 1, timeout=5)
        assert result.attempted is True
        assert result.fingerprint is not None
        assert set(result.fingerprint) == {"0"}

    def test_to_dict_shape(self) -> None:
        from net_benchmark.ssl_check.jarm import JarmResult

        r = JarmResult(attempted=True, fingerprint="0" * 62)
        d = r.to_dict()
        assert d["attempted"] is True
        assert d["fingerprint"] == "0" * 62
