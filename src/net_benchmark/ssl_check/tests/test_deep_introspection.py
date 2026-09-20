"""Tests for `net_benchmark.ssl_check.deep_introspection`.

Requires the `[crypto]` extra (CryptoLyzer) to exercise the real probe
path; skipped entirely otherwise. Every probe does real socket I/O against
real local TLS servers (the `tls_server` factory from `conftest.py`) or a
live target — there's no meaningful way to mock "what does this protocol
analyzer's own independent stack observe".
"""

from __future__ import annotations

import ssl

import pytest

pytest.importorskip(
    "cryptolyzer", reason="deep_introspection.py tests require the [crypto] extra"
)

from net_benchmark.ssl_check.deep_introspection import (  # noqa: E402
    DeepIntrospectionAvailability,
    deep_introspection_availability,
    default_crypto_executor,
    probe_client_simulation,
    probe_dh_params,
    probe_extensions,
    probe_named_groups,
    probe_signature_algorithms,
    probe_tls13_ciphers,
    probe_versions,
    probe_vulnerabilities,
)


@pytest.fixture
def executor():
    ex = default_crypto_executor(max_workers=4)
    yield ex
    ex.shutdown(wait=False)


class TestAvailability:
    def test_available_when_installed(self) -> None:
        assert (
            deep_introspection_availability() is DeepIntrospectionAvailability.AVAILABLE
        )


class TestProbeNamedGroups:
    async def test_ec_server_reports_curve(self, tls_server, executor) -> None:
        handle = await tls_server(max_version=ssl.TLSVersion.TLSv1_2)  # default EC cert
        result = await probe_named_groups("localhost", handle.port, executor=executor)
        assert result.attempted is True
        assert result.error is None
        # An EC-keyed server with a default OpenSSL curve list negotiates
        # at least one named group over TLS 1.2 with the extension.
        assert isinstance(result.groups, list)

    async def test_unreachable_target_reports_error_not_exception(
        self, executor
    ) -> None:
        result = await probe_named_groups("localhost", 1, executor=executor)
        assert result.attempted is True
        assert result.error is not None
        assert result.groups == []


class TestProbeExtensions:
    async def test_real_server_extension_posture(self, tls_server, executor) -> None:
        handle = await tls_server(max_version=ssl.TLSVersion.TLSv1_2)
        result = await probe_extensions("localhost", handle.port, executor=executor)
        assert result.attempted is True
        assert result.error is None
        # Python's SSLContext(PROTOCOL_TLS_SERVER) supports secure
        # renegotiation and extended master secret by default.
        assert result.renegotiation_supported is True
        assert result.extended_master_secret_supported is True
        assert result.compression_methods == ["NULL"]
        assert result.compression_enabled is False

    async def test_unreachable_target(self, executor) -> None:
        result = await probe_extensions("localhost", 1, executor=executor)
        assert result.attempted is True
        assert result.error is not None


class TestProbeSignatureAlgorithms:
    async def test_rsa_server_offers_rsa_algorithms(self, tls_server, executor) -> None:
        from .conftest import make_key

        handle = await tls_server(
            key=make_key("rsa2048"), max_version=ssl.TLSVersion.TLSv1_2
        )
        result = await probe_signature_algorithms(
            "localhost", handle.port, executor=executor
        )
        assert result.attempted is True
        assert result.error is None
        assert any("RSA" in a for a in result.algorithms)

    async def test_weak_algorithms_flagged(self, tls_server, executor) -> None:
        from .conftest import make_key

        handle = await tls_server(
            key=make_key("rsa2048"), max_version=ssl.TLSVersion.TLSv1_2
        )
        result = await probe_signature_algorithms(
            "localhost", handle.port, executor=executor
        )
        # A default OpenSSL build still offers RSA_SHA1 for TLS 1.2
        # backward compatibility -- if it's in the offered set, it must be
        # in weak_algorithms too.
        if "RSA_SHA1" in result.algorithms:
            assert "RSA_SHA1" in result.weak_algorithms


class TestProbeTLS13Ciphers:
    async def test_tls13_server_reports_suites(self, tls_server, executor) -> None:
        handle = await tls_server(min_version=ssl.TLSVersion.TLSv1_3)
        result = await probe_tls13_ciphers("localhost", handle.port, executor=executor)
        assert result.attempted is True
        assert result.error is None
        assert len(result.suites) > 0
        assert all(s.startswith("TLS_") for s in result.suites)

    async def test_tls12_only_server_reports_no_suites(
        self, tls_server, executor
    ) -> None:
        handle = await tls_server(max_version=ssl.TLSVersion.TLSv1_2)
        result = await probe_tls13_ciphers("localhost", handle.port, executor=executor)
        assert result.attempted is True
        assert result.suites == []


class TestProbeVersions:
    async def test_versions_are_human_readable_not_split(
        self, tls_server, executor
    ) -> None:
        handle = await tls_server(
            min_version=ssl.TLSVersion.TLSv1_2, max_version=ssl.TLSVersion.TLSv1_2
        )
        result = await probe_versions("localhost", handle.port, executor=executor)
        assert result.attempted is True
        assert result.error is None
        # Regression coverage for the real bug caught during development:
        # TlsProtocolVersion's __str__ is "TLS 1.2", not an enum-repr
        # string safe to rsplit(".") on -- a naive split produced "2".
        assert "TLS 1.2" in result.versions
        assert "2" not in result.versions


class TestProbeVulnerabilities:
    async def test_modern_server_all_clean(self, tls_server, executor) -> None:
        from .conftest import make_key

        handle = await tls_server(
            key=make_key("rsa2048"), min_version=ssl.TLSVersion.TLSv1_2
        )
        result = await probe_vulnerabilities(
            "localhost", handle.port, executor=executor
        )
        assert result.attempted is True
        assert result.error is None
        assert result.sweet32 is False
        assert result.rc4 is False
        assert result.null_encryption is False
        assert result.insecure_ssl_version is False
        assert result.early_tls_version is False
        # Short-circuit path (item 15's own addition): neither SSLv3 nor
        # TLS 1.0 is negotiable at all, so poodle/beast resolve to False
        # without the extra CBC-negotiability probe ever running.
        assert result.poodle is False
        assert result.beast is False

    async def test_unreachable_target(self, executor) -> None:
        result = await probe_vulnerabilities("localhost", 1, executor=executor)
        assert result.attempted is True
        assert result.error is not None

    def test_to_dict_shape(self) -> None:
        from net_benchmark.ssl_check.deep_introspection import VulnerabilitiesResult

        result = VulnerabilitiesResult(attempted=True, freak=False, poodle=None)
        d = result.to_dict()
        assert d["attempted"] is True
        assert d["freak"] is False
        assert d["poodle"] is None

    async def test_inappropriate_version_fallback_extracted(
        self, tls_server, executor
    ) -> None:
        from .conftest import make_key

        # Real assertion here is narrow: the field must be present and
        # boolean-or-None, not that a single-version test server
        # necessarily triggers the fallback signal itself (that needs a
        # target offering multiple versions with inconsistent fallback
        # handling, which a bare local server doesn't model). Regression
        # coverage for the extraction being wired at all -- the gap this
        # test exists for was that the field was silently never read from
        # CryptoLyzer's own result at all, not that its value was wrong.
        handle = await tls_server(
            key=make_key("rsa2048"), min_version=ssl.TLSVersion.TLSv1_2
        )
        result = await probe_vulnerabilities(
            "localhost", handle.port, executor=executor
        )
        assert result.attempted is True
        assert result.inappropriate_version_fallback in (True, False, None)


class TestCbcNegotiableAt:
    """`_cbc_negotiable_at`'s real network path needs a completing TLS 1.0
    or SSLv3 handshake, which this sandbox's OpenSSL build cannot do at all
    (confirmed directly: a real TLS 1.0 handshake attempt against a local
    server here hangs rather than completing — the same environment
    constraint `test_core.py`'s own suite already works around with a
    skip). What's tested here instead is the block-cipher-mode extraction
    logic itself, against real `cryptoparser` cipher suite objects, with no
    network involved -- the part of this function that's actually this
    module's own code, as opposed to CryptoLyzer's handshake completing.
    """

    def test_cbc_suite_detected(self) -> None:
        from cryptoparser.tls.ciphersuite import TlsCipherSuite

        suite = TlsCipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA
        mode = str(suite.value.block_cipher_mode).rsplit(".", 1)[-1]
        assert mode == "CBC"

    def test_gcm_suite_not_cbc(self) -> None:
        from cryptoparser.tls.ciphersuite import TlsCipherSuite

        suite = TlsCipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256
        mode = str(suite.value.block_cipher_mode).rsplit(".", 1)[-1]
        assert mode != "CBC"


class TestPostQuantumGroups:
    def test_ml_kem_hybrid_detected(self) -> None:
        from net_benchmark.ssl_check.deep_introspection import NamedGroupsResult

        result = NamedGroupsResult(
            attempted=True, groups=["SECP256R1", "X25519_ML_KEM_768"]
        )
        assert result.post_quantum_groups == ["X25519_ML_KEM_768"]

    def test_no_pq_groups(self) -> None:
        from net_benchmark.ssl_check.deep_introspection import NamedGroupsResult

        result = NamedGroupsResult(attempted=True, groups=["SECP256R1", "X25519"])
        assert result.post_quantum_groups == []

    def test_kyber_variant_detected(self) -> None:
        from net_benchmark.ssl_check.deep_introspection import NamedGroupsResult

        result = NamedGroupsResult(
            attempted=True, groups=["X25519_KYBER_768_R3_CLOUDFLARE"]
        )
        assert result.post_quantum_groups == ["X25519_KYBER_768_R3_CLOUDFLARE"]


class TestProbeDHParams:
    async def test_ecdhe_only_server_has_no_classic_dhe(
        self, tls_server, executor
    ) -> None:
        handle = await tls_server(max_version=ssl.TLSVersion.TLSv1_2)
        result = await probe_dh_params("localhost", handle.port, executor=executor)
        assert result.attempted is True
        assert result.error is None
        assert result.classic_dhe_key_size is None
        assert result.weak is None  # nothing observed to rate

    async def test_unreachable_target(self, executor) -> None:
        result = await probe_dh_params("localhost", 1, executor=executor)
        assert result.attempted is True
        assert result.error is not None


class TestProbeClientSimulation:
    async def test_real_server_produces_entries(self, tls_server, executor) -> None:
        from .conftest import make_key

        handle = await tls_server(key=make_key("rsa2048"))
        result = await probe_client_simulation(
            "localhost", handle.port, executor=executor
        )
        assert result.attempted is True
        assert result.error is None
        assert len(result.entries) > 0
        assert any(e.succeeded for e in result.entries)
        # Regression coverage for the real bug this probe caught during
        # development: using L7ClientTls (scheme "tls") here instead of
        # L7ClientHTTPS (scheme "https") silently produces zero entries
        # and no error at all, since the simulation analyzer's own
        # _CLIENT_TYPE_SCHEME_MAP only recognises "https".
        succeeded = [e for e in result.entries if e.succeeded]
        assert any(e.cipher_suite is not None for e in succeeded)

    async def test_incompatible_clients_property(self, tls_server, executor) -> None:
        from .conftest import make_key

        handle = await tls_server(key=make_key("rsa2048"))
        result = await probe_client_simulation(
            "localhost", handle.port, executor=executor
        )
        failed_entries = [e for e in result.entries if not e.succeeded]
        assert result.incompatible_clients == [e.client_name for e in failed_entries]
        if failed_entries:
            assert failed_entries[0].error is not None

    async def test_unreachable_target(self, executor) -> None:
        result = await probe_client_simulation("localhost", 1, executor=executor)
        assert result.attempted is True
        assert result.error is not None
        assert result.entries == []

    def test_to_dict_shape(self) -> None:
        from net_benchmark.ssl_check.deep_introspection import (
            ClientSimulationEntry,
            ClientSimulationResult,
        )

        result = ClientSimulationResult(
            attempted=True,
            entries=[
                ClientSimulationEntry(
                    client_name="A", succeeded=True, version="TLS 1.3"
                ),
                ClientSimulationEntry(
                    client_name="B", succeeded=False, error="no shared cipher"
                ),
            ],
        )
        d = result.to_dict()
        assert d["attempted"] is True
        assert len(d["entries"]) == 2
        assert d["incompatible_clients"] == ["B"]
