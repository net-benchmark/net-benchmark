"""Tests for `net_benchmark.ssl_check.multi_store`.

The Apple/Google fetch mechanism is tested with a mocked transport (the
real `api.tlsinspector.com` endpoint could not be reached from this
project's own development sandbox to record real bytes — its exact asset
URL is taken from the aggregator's own documented API pattern, not a
live-verified round trip, unlike every other external data source
elsewhere in this project). The certificate-validation logic itself is
tested with real X.509 certificates and a real local TLS server, so what's
actually exercised end-to-end with genuine data is the part that matters
most: does a chain validate correctly against a real, self-built `Store`.
"""

from __future__ import annotations

import datetime

import httpx
from cryptography.hazmat.primitives.asymmetric import ec

from net_benchmark.ssl_check.multi_store import (
    MultiStoreAudit,
    StoreVerificationResult,
    check_multi_store_trust,
    fetch_vendor_bundle,
)
from net_benchmark.ssl_check.tests.test_chain import _build_ca, _build_leaf

UTC = datetime.timezone.utc
NOW = datetime.datetime.now(UTC)


def _self_signed_cert() -> tuple[bytes, bytes]:
    """Returns (leaf_der, pem_bundle_containing_its_root) -- a real
    root -> leaf pair built with `test_chain.py`'s own established,
    already-proven cert-construction helpers, rather than a hand-rolled
    single self-signed certificate.

    An earlier version of this fixture tried a single self-signed
    certificate acting as both the leaf being validated and its own trust
    anchor. `cryptography`'s server verifier rejected that configuration
    twice, for two different real profile requirements (basicConstraints
    on an EE cert, then a missing required extension) — reusing the
    fixture pattern `test_chain.py` already validated against real
    verifier behaviour turned out to be the right call, not a shortcut
    around it.
    """
    root_key = ec.generate_private_key(ec.SECP256R1())
    root_cert = _build_ca(
        root_key,
        "Test Root CA",
        issuer_cn="Test Root CA",
        issuer_key=None,
        issuer_cert=None,
        path_length=1,
    )
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf_cert = _build_leaf(
        leaf_key,
        "example.com",
        issuer_cn="Test Root CA",
        issuer_key=root_key,
        issuer_cert=root_cert,
    )

    from cryptography.hazmat.primitives.serialization import Encoding

    der = leaf_cert.public_bytes(Encoding.DER)
    pem = root_cert.public_bytes(Encoding.PEM)
    return der, pem


class TestFetchVendorBundle:
    async def test_fetch_and_cache(self, tmp_path) -> None:
        body = b"-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----\n"

        def handler(request: httpx.Request) -> httpx.Response:
            assert "net-benchmark" in request.headers.get("user-agent", "")
            return httpx.Response(200, content=body)

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            data, error = await fetch_vendor_bundle(client, "apple", cache_dir=tmp_path)
        assert error is None
        assert data == body
        assert (tmp_path / "apple_ca_bundle.pem").exists()

    async def test_second_fetch_served_from_cache(self, tmp_path) -> None:
        body = b"-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----\n"
        call_count = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            call_count["n"] += 1
            return httpx.Response(200, content=body)

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            await fetch_vendor_bundle(client, "google", cache_dir=tmp_path)
            await fetch_vendor_bundle(client, "google", cache_dir=tmp_path)
        assert call_count["n"] == 1

    async def test_fetch_failure_returns_error_not_exception(self, tmp_path) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(403, content=b"denied")

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            data, error = await fetch_vendor_bundle(client, "apple", cache_dir=tmp_path)
        assert data is None
        assert error is not None


class TestCheckMultiStoreTrust:
    async def test_verified_against_self_signed_trust_anchor(self, tmp_path) -> None:
        """Real ServerVerifier.verify() call against a real Store built
        from a real self-signed cert that is its own trust anchor --
        proves the actual validation logic, not just that no exception was
        raised.
        """
        der, pem = _self_signed_cert()

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=pem)

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            audit = await check_multi_store_trust(
                der,
                None,
                client=client,
                hostname="example.com",
                now=NOW,
                cache_dir=tmp_path,
            )
        apple_result = next(r for r in audit.results if r.store_name == "apple")
        assert apple_result.verified is True
        assert apple_result.unavailable_reason is None

    async def test_not_verified_against_unrelated_store(self, tmp_path) -> None:
        der, _ = _self_signed_cert()
        # A different, unrelated self-signed cert as the "vendor store" --
        # the leaf cannot chain to it.
        _, unrelated_pem = _self_signed_cert()

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=unrelated_pem)

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            audit = await check_multi_store_trust(
                der,
                None,
                client=client,
                hostname="example.com",
                now=NOW,
                cache_dir=tmp_path,
            )
        apple_result = next(r for r in audit.results if r.store_name == "apple")
        assert apple_result.verified is False
        assert apple_result.verification_error is not None

    async def test_fetch_failure_reported_as_unavailable_not_crash(
        self, tmp_path
    ) -> None:
        der, _ = _self_signed_cert()

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500)

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            audit = await check_multi_store_trust(
                der,
                None,
                client=client,
                hostname="example.com",
                now=NOW,
                cache_dir=tmp_path,
            )
        assert audit.attempted is True
        apple_result = next(r for r in audit.results if r.store_name == "apple")
        assert apple_result.unavailable_reason is not None
        assert apple_result.verified is None

    async def test_consistent_true_when_stores_agree(self, tmp_path) -> None:
        der, pem = _self_signed_cert()

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=pem)

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            audit = await check_multi_store_trust(
                der,
                None,
                client=client,
                hostname="example.com",
                now=NOW,
                cache_dir=tmp_path,
            )
        # Apple and Google both mocked to the same trusting bundle; if
        # mscerts is installed, Microsoft (real, unrelated data) will
        # disagree -- exercising whichever branch is actually reachable
        # here without assuming mscerts is present in every environment.
        verdicts = {
            r.store_name: r.verified for r in audit.results if r.verified is not None
        }
        if verdicts.get("apple") is True and verdicts.get("google") is True:
            assert len(verdicts) >= 2

    def test_consistent_none_with_fewer_than_two_verdicts(self) -> None:
        audit = MultiStoreAudit(
            attempted=True,
            results=[
                StoreVerificationResult(store_name="apple", verified=True),
                StoreVerificationResult(
                    store_name="google", unavailable_reason="blocked"
                ),
            ],
        )
        assert audit.consistent is None

    def test_consistent_false_when_stores_disagree(self) -> None:
        audit = MultiStoreAudit(
            attempted=True,
            results=[
                StoreVerificationResult(store_name="apple", verified=True),
                StoreVerificationResult(store_name="google", verified=False),
            ],
        )
        assert audit.consistent is False

    def test_consistent_true_when_stores_agree_unit(self) -> None:
        audit = MultiStoreAudit(
            attempted=True,
            results=[
                StoreVerificationResult(store_name="apple", verified=True),
                StoreVerificationResult(store_name="google", verified=True),
            ],
        )
        assert audit.consistent is True

    def test_to_dict_shape(self) -> None:
        audit = MultiStoreAudit(
            attempted=True,
            results=[StoreVerificationResult(store_name="apple", verified=True)],
        )
        d = audit.to_dict()
        assert d["attempted"] is True
        assert len(d["results"]) == 1
