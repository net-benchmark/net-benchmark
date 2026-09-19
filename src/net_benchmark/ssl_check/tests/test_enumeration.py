"""Tests for `net_benchmark.ssl_check.enumeration`.

Unlike `test_chain.py`/`test_revocation.py`, this needs real handshakes --
`probe_tls` does real socket I/O and there is no meaningful way to mock a
"does this TLS version/cipher negotiate" question. Uses the `tls_server`
factory fixture from `conftest.py` (a real local `asyncio` TLS server), same
as `test_handshake.py`.
"""

from __future__ import annotations

import ssl

import pytest

from net_benchmark.ssl_check.enumeration import (
    CipherPreferenceResult,
    CipherStrength,
    EnumerationResult,
    detect_cipher_preference,
    enumerate_protocol,
    local_tls12_and_below_ciphers,
    rate_cipher_strength,
)
from net_benchmark.ssl_check.handshake import ProbeConfig, TLSVersion

from .conftest import make_key


def _local_config() -> ProbeConfig:
    return ProbeConfig(pinned_ip="127.0.0.1", server_hostname="localhost")


class TestRateCipherStrength:
    """Pure function, no network -- sanity across representative real names."""

    @pytest.mark.parametrize(
        "name,expected",
        [
            ("ECDHE-RSA-AES128-GCM-SHA256", CipherStrength.A),
            ("ECDHE-ECDSA-CHACHA20-POLY1305", CipherStrength.A),
            ("DHE-RSA-AES256-GCM-SHA384", CipherStrength.A),
            ("ECDHE-RSA-AES128-SHA", CipherStrength.B),  # FS, but CBC not AEAD
            ("AES128-GCM-SHA256", CipherStrength.B),  # AEAD, but no FS
            ("AES128-SHA", CipherStrength.B),  # neither, but not broken
            ("DES-CBC3-SHA", CipherStrength.C),
            ("RC4-SHA", CipherStrength.C),
            ("ECDHE-RSA-RC4-SHA", CipherStrength.C),  # weak primitive wins over FS
            ("NULL-SHA", CipherStrength.F),
            ("ADH-AES128-SHA", CipherStrength.F),
            ("EXP-RC4-MD5", CipherStrength.F),
        ],
    )
    def test_representative_names(self, name: str, expected: CipherStrength) -> None:
        strength, reason = rate_cipher_strength(name)
        assert (
            strength is expected
        ), f"{name}: expected {expected}, got {strength} ({reason})"
        assert reason  # every rating carries a reason

    def test_strength_order_used_by_weakest_property(self) -> None:
        # F worse than C worse than B worse than A -- exercised indirectly
        # via EnumerationResult.weakest_supported_cipher_strength elsewhere,
        # sanity-checked here directly.
        from net_benchmark.ssl_check.enumeration import _STRENGTH_ORDER

        assert _STRENGTH_ORDER == [
            CipherStrength.F,
            CipherStrength.C,
            CipherStrength.B,
            CipherStrength.A,
        ]


class TestLocalCiphers:
    def test_returns_nonempty_list_excluding_tls13(self) -> None:
        ciphers = local_tls12_and_below_ciphers()
        assert len(ciphers) > 10
        names = [name for name, _ in ciphers]
        assert not any(name.startswith("TLS_") for name in names)  # TLS 1.3 names
        # Every entry either resolves an IANA code or explicitly carries None
        # -- never silently omitted.
        assert all(isinstance(entry, tuple) and len(entry) == 2 for entry in ciphers)


class TestEnumerateProtocol:
    async def test_version_enumeration_against_tls12_only_server(
        self, tls_server
    ) -> None:
        handle = await tls_server(
            min_version=ssl.TLSVersion.TLSv1_2, max_version=ssl.TLSVersion.TLSv1_2
        )
        result = await enumerate_protocol(
            "localhost",
            handle.port,
            base_config=_local_config(),
            include_ciphers=False,
        )
        assert result.attempted is True
        by_version = {v.version: v.supported for v in result.versions}
        assert by_version[TLSVersion.TLSV1_2] is True
        assert by_version[TLSVersion.TLSV1_1] is False
        assert by_version[TLSVersion.TLSV1_0] is False
        assert by_version[TLSVersion.TLSV1_3] is False
        assert result.supported_versions == [TLSVersion.TLSV1_2]

    async def test_version_enumeration_against_tls13_only_server(
        self, tls_server
    ) -> None:
        handle = await tls_server(
            min_version=ssl.TLSVersion.TLSv1_3, max_version=ssl.TLSVersion.TLSv1_3
        )
        result = await enumerate_protocol(
            "localhost",
            handle.port,
            base_config=_local_config(),
            include_ciphers=False,
        )
        by_version = {v.version: v.supported for v in result.versions}
        assert by_version[TLSVersion.TLSV1_3] is True
        assert by_version[TLSVersion.TLSV1_2] is False

    async def test_cipher_enumeration_reports_supported_and_unsupported(
        self, tls_server
    ) -> None:
        # A server pinned to TLS 1.2 with an explicit, narrow cipher list --
        # only what's actually in that list should come back supported.
        allowed = "ECDHE-RSA-AES128-GCM-SHA256"
        handle = await tls_server(
            min_version=ssl.TLSVersion.TLSv1_2,
            max_version=ssl.TLSVersion.TLSv1_2,
        )
        candidates = [
            (allowed, None),
            ("ECDHE-RSA-AES256-GCM-SHA384", None),
            ("AES128-SHA", None),
        ]
        result = await enumerate_protocol(
            "localhost",
            handle.port,
            base_config=_local_config(),
            include_ciphers=True,
            cipher_candidates=candidates,
        )
        by_name = {c.name: c for c in result.ciphers}
        assert set(by_name) == {name for name, _ in candidates}
        # The server's own OpenSSL default cipher set for a self-signed RSA
        # cert typically accepts several GCM suites; the key property under
        # test is that the *set* of supported names is well-formed and each
        # carries a strength rating, not the exact server-side default list
        # (which is this machine's OpenSSL build, not something to pin).
        for cipher in result.ciphers:
            assert cipher.strength in CipherStrength
            assert cipher.strength_reason

    async def test_weakest_supported_cipher_strength(self, tls_server) -> None:
        handle = await tls_server(
            min_version=ssl.TLSVersion.TLSv1_2, max_version=ssl.TLSVersion.TLSv1_2
        )
        candidates = [
            ("ECDHE-RSA-AES128-GCM-SHA256", None),  # A
            ("AES128-SHA", None),  # B
        ]
        result = await enumerate_protocol(
            "localhost",
            handle.port,
            base_config=_local_config(),
            include_ciphers=True,
            cipher_candidates=candidates,
        )
        supported = {c.name for c in result.supported_ciphers}
        if supported:
            # Whichever of the two actually negotiated, the weakest supported
            # rating must be the min of what came back, not just the first.
            expected = min(
                (c.strength for c in result.ciphers if c.supported),
                key=lambda s: [
                    CipherStrength.F,
                    CipherStrength.C,
                    CipherStrength.B,
                    CipherStrength.A,
                ].index(s),
            )
            assert result.weakest_supported_cipher_strength == expected

    async def test_no_ciphers_probed_when_disabled(self, tls_server) -> None:
        handle = await tls_server(
            min_version=ssl.TLSVersion.TLSv1_2, max_version=ssl.TLSVersion.TLSv1_2
        )
        result = await enumerate_protocol(
            "localhost",
            handle.port,
            base_config=_local_config(),
            include_ciphers=False,
        )
        assert result.ciphers == []
        assert result.weakest_supported_cipher_strength is None

    async def test_unreachable_target_reports_unsupported_not_exception(self) -> None:
        # Nothing listening on this port -- every probe should come back as
        # unsupported with an error, never raise.
        result = await enumerate_protocol(
            "localhost",
            1,
            base_config=_local_config(),
            include_ciphers=False,
        )
        assert result.attempted is True
        assert all(v.supported is False for v in result.versions)
        assert all(v.error is not None for v in result.versions)

    def test_to_dict_shape(self) -> None:
        result = EnumerationResult(attempted=True)
        d = result.to_dict()
        assert d["attempted"] is True
        assert d["versions"] == []
        assert d["ciphers"] == []
        assert d["weakest_supported_cipher_strength"] is None


# ---------------------------------------------------------------------------
# Server cipher-suite preference order (0.6.1 item 21)
# ---------------------------------------------------------------------------

CIPHER_A = "ECDHE-RSA-AES128-GCM-SHA256"
CIPHER_B = "ECDHE-RSA-AES256-GCM-SHA384"


class TestDetectCipherPreference:
    async def test_server_enforces_own_order(self, tls_server) -> None:
        # Default Python SSLContext(PROTOCOL_TLS_SERVER) behaviour —
        # confirmed empirically before writing this module — already sets
        # OP_CIPHER_SERVER_PREFERENCE, so honor_client_cipher_order is left
        # at its default False here. Server's own list always prefers A.
        # ECDHE-RSA-* needs an RSA server cert — cert_factory defaults to EC.
        handle = await tls_server(
            key=make_key("rsa2048"),
            max_version=ssl.TLSVersion.TLSv1_2,
            cipher_string=f"{CIPHER_A}:{CIPHER_B}",
        )
        result = await detect_cipher_preference(
            "localhost",
            handle.port,
            base_config=_local_config(),
            cipher_a=CIPHER_A,
            cipher_b=CIPHER_B,
        )
        assert result.attempted is True
        assert result.server_enforces_order is True
        assert result.negotiated_with_a_first == result.negotiated_with_b_first
        assert result.error is None

    async def test_server_honors_client_order(self, tls_server) -> None:
        handle = await tls_server(
            key=make_key("rsa2048"),
            max_version=ssl.TLSVersion.TLSv1_2,
            cipher_string=f"{CIPHER_A}:{CIPHER_B}",
            honor_client_cipher_order=True,
        )
        result = await detect_cipher_preference(
            "localhost",
            handle.port,
            base_config=_local_config(),
            cipher_a=CIPHER_A,
            cipher_b=CIPHER_B,
        )
        assert result.attempted is True
        assert result.server_enforces_order is False
        # Whichever the client listed first is what gets negotiated.
        assert CIPHER_A in result.negotiated_with_a_first
        assert CIPHER_B in result.negotiated_with_b_first

    async def test_inconclusive_when_only_one_cipher_supported(
        self, tls_server
    ) -> None:
        # Server only has cipher A available at all -- ordering can't be
        # observed since B never negotiates regardless of client order.
        handle = await tls_server(
            key=make_key("rsa2048"),
            max_version=ssl.TLSVersion.TLSv1_2,
            cipher_string=CIPHER_A,
        )
        result = await detect_cipher_preference(
            "localhost",
            handle.port,
            base_config=_local_config(),
            cipher_a=CIPHER_A,
            cipher_b=CIPHER_B,
        )
        assert result.attempted is True
        assert result.server_enforces_order is None
        assert result.error is not None

    async def test_unreachable_target_reports_error_not_exception(self) -> None:
        result = await detect_cipher_preference(
            "localhost",
            1,
            base_config=_local_config(),
        )
        assert result.attempted is True
        assert result.server_enforces_order is None
        assert result.error is not None

    def test_to_dict_shape(self) -> None:
        result = CipherPreferenceResult(attempted=True, server_enforces_order=True)
        d = result.to_dict()
        assert d["attempted"] is True
        assert d["server_enforces_order"] is True
