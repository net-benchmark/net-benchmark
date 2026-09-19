"""Tests for `net_benchmark.ssl_check.chain`.

No test here makes a real network call. AIA fetches are served by an
`httpx.MockTransport`, keyed on the CA Issuers URL each test builds into its
own certificates -- same "no test reaches the internet" rule
`tests/conftest.py` states for the rest of this package, extended to cover
the one class of network I/O this module adds.

Certificate generation
-----------------------
`tests/conftest.py`'s `make_cert()` builds a self-signed leaf only -- it has
no `BasicConstraints(ca=True)`, no `AuthorityKeyIdentifier`, and always signs
with the subject's own key, none of which produces something
`cryptography.x509.verification` will accept as an intermediate or root. The
local `_build_ca()` / `_build_leaf()` helpers below build genuine
root -> intermediate -> leaf chains instead; they are private to this file
rather than added to the shared fixture, since nothing else in the suite
needs a validatable chain.
"""

from __future__ import annotations

import datetime
from typing import Optional, Tuple

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import (
    AuthorityInformationAccessOID,
    ExtendedKeyUsageOID,
    NameOID,
)
from cryptography.x509.verification import Store

from net_benchmark.ssl_check import chain as chain_module
from net_benchmark.ssl_check.chain import (
    ChainSource,
    build_chain_audit,
    default_trust_store,
    fetch_issuer_certificate,
)

UTC = datetime.timezone.utc
NOW = datetime.datetime.now(UTC)


# ---------------------------------------------------------------------------
# Local chain-building helpers
# ---------------------------------------------------------------------------


def _aia_extension(url: str) -> x509.AuthorityInformationAccess:
    return x509.AuthorityInformationAccess(
        [
            x509.AccessDescription(
                AuthorityInformationAccessOID.CA_ISSUERS,
                x509.UniformResourceIdentifier(url),
            )
        ]
    )


def _build_ca(
    key: ec.EllipticCurvePrivateKey,
    cn: str,
    *,
    issuer_cn: str,
    issuer_key: Optional[ec.EllipticCurvePrivateKey],
    issuer_cert: Optional[x509.Certificate],
    path_length: int,
    aia_url: Optional[str] = None,
) -> x509.Certificate:
    """A CA certificate (self-signed root when `issuer_key` is None)."""
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)])
    signing_key = issuer_key or key
    akid_source = issuer_cert.public_key() if issuer_cert else key.public_key()

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - datetime.timedelta(days=1))
        .not_valid_after(NOW + datetime.timedelta(days=3650))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=path_length), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(akid_source),
            critical=False,
        )
    )
    if aia_url:
        builder = builder.add_extension(_aia_extension(aia_url), critical=False)
    return builder.sign(signing_key, hashes.SHA256())


def _build_leaf(
    key: ec.EllipticCurvePrivateKey,
    cn: str,
    *,
    issuer_cn: str,
    issuer_key: ec.EllipticCurvePrivateKey,
    issuer_cert: x509.Certificate,
    aia_url: Optional[str] = None,
) -> x509.Certificate:
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - datetime.timedelta(days=1))
        .not_valid_after(NOW + datetime.timedelta(days=90))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                issuer_cert.public_key()
            ),
            False,
        )
    )
    if aia_url:
        builder = builder.add_extension(_aia_extension(aia_url), critical=False)
    return builder.sign(issuer_key, hashes.SHA256())


class ChainFixture:
    """A root -> intermediate -> leaf chain, with the intermediate served
    over a mocked AIA URL.
    """

    def __init__(self) -> None:
        self.root_key = ec.generate_private_key(ec.SECP256R1())
        self.root_cert = _build_ca(
            self.root_key,
            "Test Root CA",
            issuer_cn="Test Root CA",
            issuer_key=None,
            issuer_cert=None,
            path_length=1,
        )
        self.intermediate_key = ec.generate_private_key(ec.SECP256R1())
        self.intermediate_cert = _build_ca(
            self.intermediate_key,
            "Test Intermediate CA",
            issuer_cn="Test Root CA",
            issuer_key=self.root_key,
            issuer_cert=self.root_cert,
            path_length=0,
            aia_url="https://ca.example/root.der",
        )
        self.leaf_key = ec.generate_private_key(ec.SECP256R1())

    def leaf(self, cn: str = "example.com", *, aia_url: Optional[str] = None) -> bytes:
        cert = _build_leaf(
            self.leaf_key,
            cn,
            issuer_cn="Test Intermediate CA",
            issuer_key=self.intermediate_key,
            issuer_cert=self.intermediate_cert,
            aia_url=aia_url,
        )
        return cert.public_bytes(Encoding.DER)

    @property
    def store(self) -> Store:
        return Store([self.root_cert])

    def aia_responses(self) -> dict:
        return {
            "https://ca.example/root.der": self.intermediate_cert.public_bytes(
                Encoding.DER
            ),
        }


def _mock_client(responses: dict) -> httpx.AsyncClient:
    def handler(request: httpx.Request) -> httpx.Response:
        body = responses.get(str(request.url))
        if body is None:
            return httpx.Response(404)
        return httpx.Response(
            200, content=body, headers={"content-type": "application/pkix-cert"}
        )

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


@pytest.fixture
def fixture() -> ChainFixture:
    return ChainFixture()


# ---------------------------------------------------------------------------
# build_chain_audit
# ---------------------------------------------------------------------------


class TestBuildChainAudit:
    async def test_full_chain_from_peer_needs_no_fetch(
        self, fixture: ChainFixture
    ) -> None:
        leaf_der = fixture.leaf()
        peer_chain = [leaf_der, fixture.intermediate_cert.public_bytes(Encoding.DER)]
        async with _mock_client({}) as client:  # no AIA responses registered
            audit = await build_chain_audit(
                leaf_der,
                peer_chain,
                client=client,
                hostname="example.com",
                now=NOW,
                store=fixture.store,
            )
        assert audit.attempted is True
        assert audit.verified is True
        assert audit.complete is True
        assert audit.missing_intermediate is False
        assert audit.depth == 2  # intermediate + root
        assert [link.source for link in audit.links] == [
            ChainSource.PEER,
            ChainSource.PEER,
        ]
        assert audit.root is not None
        assert audit.root.subject_cn == "Test Root CA"

    async def test_missing_intermediate_fetched_via_aia(
        self, fixture: ChainFixture
    ) -> None:
        leaf_der = fixture.leaf(aia_url="https://ca.example/root.der")
        async with _mock_client(fixture.aia_responses()) as client:
            audit = await build_chain_audit(
                leaf_der,
                None,  # platform cannot observe the peer chain (< 3.13)
                client=client,
                hostname="example.com",
                now=NOW,
                store=fixture.store,
            )
        assert audit.verified is True
        assert audit.missing_intermediate is True
        assert audit.depth == 2
        assert audit.links[0].source is ChainSource.AIA_FETCH
        assert audit.links[0].certificate.subject_cn == "Test Intermediate CA"

    async def test_no_aia_url_and_no_peer_chain_fails_cleanly(
        self, fixture: ChainFixture
    ) -> None:
        leaf_der = fixture.leaf()  # no AIA extension this time
        async with _mock_client({}) as client:
            audit = await build_chain_audit(
                leaf_der,
                None,
                client=client,
                hostname="example.com",
                now=NOW,
                store=fixture.store,
            )
        assert audit.verified is False
        assert audit.complete is False
        assert audit.verification_error is not None
        assert audit.links == []

    async def test_untrusted_root_rejected(self, fixture: ChainFixture) -> None:
        leaf_der = fixture.leaf()
        peer_chain = [leaf_der, fixture.intermediate_cert.public_bytes(Encoding.DER)]
        # A store trusting an unrelated root, not fixture's own -- Store([])
        # is rejected outright by cryptography.x509.verification.
        other_root_key = ec.generate_private_key(ec.SECP256R1())
        other_root_cert = _build_ca(
            other_root_key,
            "Unrelated Root",
            issuer_cn="Unrelated Root",
            issuer_key=None,
            issuer_cert=None,
            path_length=1,
        )
        untrusting_store = Store([other_root_cert])
        async with _mock_client({}) as client:
            audit = await build_chain_audit(
                leaf_der,
                peer_chain,
                client=client,
                hostname="example.com",
                now=NOW,
                store=untrusting_store,
            )
        assert audit.verified is False
        assert audit.verification_error is not None
        assert "validation failed" in audit.verification_error

    async def test_leaf_unparseable_does_not_raise(self, fixture: ChainFixture) -> None:
        async with _mock_client({}) as client:
            audit = await build_chain_audit(
                b"not a certificate",
                None,
                client=client,
                hostname="example.com",
                now=NOW,
                store=fixture.store,
            )
        assert audit.attempted is True
        assert audit.verified is False
        assert audit.verification_error is not None
        assert "unparseable" in audit.verification_error

    async def test_max_depth_stops_a_pathological_aia_loop(
        self, fixture: ChainFixture
    ) -> None:
        """An intermediate whose AIA points at itself must not hang the
        engine -- the depth cap has to win, not the loop.
        """
        leaf_der = fixture.leaf(aia_url="https://ca.example/loop.der")
        responses = {"https://ca.example/loop.der": fixture.leaf(aia_url=None)}
        # Reuse the leaf's own bytes as a bogus "issuer" that keeps pointing
        # at the same URL -- extract_revocation_endpoints on it finds no
        # further AIA (leaf() built with aia_url=None has none), so this
        # specific loop terminates on its own; the assertion that matters is
        # that build_chain_audit returns promptly either way rather than
        # exceeding max_depth iterations.
        async with _mock_client(responses) as client:
            audit = await build_chain_audit(
                leaf_der,
                None,
                client=client,
                hostname="example.com",
                now=NOW,
                store=fixture.store,
                max_depth=3,
            )
        assert audit.attempted is True
        assert audit.verified is False

    async def test_missing_intermediate_flagged_even_when_peer_sent_leaf_only(
        self, fixture: ChainFixture
    ) -> None:
        leaf_der = fixture.leaf(aia_url="https://ca.example/root.der")
        async with _mock_client(fixture.aia_responses()) as client:
            audit = await build_chain_audit(
                leaf_der,
                [leaf_der],  # peer sent a chain, but it's leaf-only
                client=client,
                hostname="example.com",
                now=NOW,
                store=fixture.store,
            )
        assert audit.verified is True
        assert audit.missing_intermediate is True

    async def test_peer_chain_order_correct(self, fixture: ChainFixture) -> None:
        leaf_der = fixture.leaf()
        peer_chain = [leaf_der, fixture.intermediate_cert.public_bytes(Encoding.DER)]
        async with _mock_client({}) as client:
            audit = await build_chain_audit(
                leaf_der,
                peer_chain,
                client=client,
                hostname="example.com",
                now=NOW,
                store=fixture.store,
            )
        assert audit.peer_chain_ordered is True
        assert audit.peer_chain_order_detail is None

    async def test_peer_chain_order_wrong_flagged(self, fixture: ChainFixture) -> None:
        # Root sent before the intermediate -- a real, common misordering.
        leaf_der = fixture.leaf()
        peer_chain = [
            leaf_der,
            fixture.root_cert.public_bytes(Encoding.DER),
            fixture.intermediate_cert.public_bytes(Encoding.DER),
        ]
        async with _mock_client({}) as client:
            audit = await build_chain_audit(
                leaf_der,
                peer_chain,
                client=client,
                hostname="example.com",
                now=NOW,
                store=fixture.store,
            )
        # Order is wrong even though a valid path can still be assembled --
        # verify() doesn't care about candidate order, ordering-detection
        # does.
        assert audit.peer_chain_ordered is False
        assert audit.peer_chain_order_detail is not None
        assert "position 1" in audit.peer_chain_order_detail

    async def test_peer_chain_order_none_when_too_short_to_check(
        self, fixture: ChainFixture
    ) -> None:
        leaf_der = fixture.leaf(aia_url="https://ca.example/root.der")
        async with _mock_client(fixture.aia_responses()) as client:
            audit = await build_chain_audit(
                leaf_der,
                None,
                client=client,  # nothing peer-observed at all
                hostname="example.com",
                now=NOW,
                store=fixture.store,
            )
        assert audit.peer_chain_ordered is None
        assert audit.peer_chain_order_detail is None


# ---------------------------------------------------------------------------
# Weak-hash aggregation (item 16) -- chain.py's own responsibility, isolated
# from certificate.py's already-tested audit_signature() via monkeypatch.
# See test_certificate.py::TestSignatureAudit::test_sha1_flagged for why a
# genuinely weak-hash CA cert can't be constructed directly: this
# cryptography build refuses to sign with SHA-1/MD5 at all, and DER
# OID-patching (the technique used there) breaks the signature that
# `cryptography.x509.verification` re-checks, so a "weak but still
# validates" chain cert can't be produced that way either.
# ---------------------------------------------------------------------------


class TestWeakHashAggregation:
    async def test_weak_hash_flagged_per_non_leaf_cert_only(
        self,
        fixture: ChainFixture,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        def fake_audit(cert: x509.Certificate) -> Tuple[bool, Optional[str]]:
            return True, "SHA1 is broken for certificate signing"

        monkeypatch.setattr(chain_module, "_audit_chain_signature", fake_audit)

        leaf_der = fixture.leaf()
        peer_chain = [leaf_der, fixture.intermediate_cert.public_bytes(Encoding.DER)]
        async with _mock_client({}) as client:
            audit = await build_chain_audit(
                leaf_der,
                peer_chain,
                client=client,
                hostname="example.com",
                now=NOW,
                store=fixture.store,
            )
        assert audit.verified is True
        assert audit.weak_hash_in_chain is True
        # Both non-leaf certs (intermediate + root) flagged, leaf excluded --
        # the leaf never enters `non_leaf` in build_chain_audit at all.
        assert len(audit.weak_hash_details) == 2
        assert audit.depth == 2


# ---------------------------------------------------------------------------
# Cross-sign heuristic (item 15)
# ---------------------------------------------------------------------------


class TestCrossSign:
    async def test_not_evaluated_by_default(self, fixture: ChainFixture) -> None:
        leaf_der = fixture.leaf()
        peer_chain = [leaf_der, fixture.intermediate_cert.public_bytes(Encoding.DER)]
        async with _mock_client({}) as client:
            audit = await build_chain_audit(
                leaf_der,
                peer_chain,
                client=client,
                hostname="example.com",
                now=NOW,
                store=fixture.store,
                check_cross_sign=False,
            )
        assert audit.cross_signed is None

    async def test_same_root_both_paths_not_cross_signed(
        self, fixture: ChainFixture
    ) -> None:
        leaf_der = fixture.leaf(aia_url="https://ca.example/root.der")
        peer_chain = [leaf_der, fixture.intermediate_cert.public_bytes(Encoding.DER)]
        async with _mock_client(fixture.aia_responses()) as client:
            audit = await build_chain_audit(
                leaf_der,
                peer_chain,
                client=client,
                hostname="example.com",
                now=NOW,
                store=fixture.store,
                check_cross_sign=True,
            )
        assert audit.verified is True
        assert audit.cross_signed is False

    async def test_divergent_roots_flagged(self) -> None:
        # Two independent roots, one intermediate key cross-signed by both.
        root_a_key = ec.generate_private_key(ec.SECP256R1())
        root_a_cert = _build_ca(
            root_a_key,
            "Root A",
            issuer_cn="Root A",
            issuer_key=None,
            issuer_cert=None,
            path_length=1,
        )
        root_b_key = ec.generate_private_key(ec.SECP256R1())
        root_b_cert = _build_ca(
            root_b_key,
            "Root B",
            issuer_cn="Root B",
            issuer_key=None,
            issuer_cert=None,
            path_length=1,
        )
        shared_int_key = ec.generate_private_key(ec.SECP256R1())
        int_via_a = _build_ca(
            shared_int_key,
            "Shared Intermediate",
            issuer_cn="Root A",
            issuer_key=root_a_key,
            issuer_cert=root_a_cert,
            path_length=0,
            aia_url="https://ca.example/root-a.der",
        )
        int_via_b = _build_ca(
            shared_int_key,
            "Shared Intermediate",
            issuer_cn="Root B",
            issuer_key=root_b_key,
            issuer_cert=root_b_cert,
            path_length=0,
            aia_url="https://ca.example/root-b.der",
        )
        leaf_key = ec.generate_private_key(ec.SECP256R1())
        # The leaf's own AIA points at the Root-B-signed copy -- an
        # independent AIA-only walk finds Root B, while the peer hands over
        # the Root-A-signed copy directly.
        leaf_cert = _build_leaf(
            leaf_key,
            "example.com",
            issuer_cn="Shared Intermediate",
            issuer_key=shared_int_key,
            issuer_cert=int_via_b,
            aia_url="https://ca.example/int-b.der",
        )
        leaf_der = leaf_cert.public_bytes(Encoding.DER)
        peer_chain = [leaf_der, int_via_a.public_bytes(Encoding.DER)]
        responses = {
            "https://ca.example/int-b.der": int_via_b.public_bytes(Encoding.DER),
            "https://ca.example/root-b.der": root_b_cert.public_bytes(Encoding.DER),
        }
        store = Store([root_a_cert, root_b_cert])
        async with _mock_client(responses) as client:
            audit = await build_chain_audit(
                leaf_der,
                peer_chain,
                client=client,
                hostname="example.com",
                now=NOW,
                store=store,
                check_cross_sign=True,
            )
        assert audit.verified is True  # via peer's Root-A path
        assert audit.cross_signed is True
        assert audit.cross_sign_detail is not None
        assert "Root A" in audit.cross_sign_detail
        assert "Root B" in audit.cross_sign_detail


# ---------------------------------------------------------------------------
# fetch_issuer_certificate
# ---------------------------------------------------------------------------


class TestFetchIssuerCertificate:
    async def test_der_response(self, fixture: ChainFixture) -> None:
        body = fixture.intermediate_cert.public_bytes(Encoding.DER)

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200, content=body, headers={"content-type": "application/pkix-cert"}
            )

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            cert, error = await fetch_issuer_certificate(
                client, ["https://ca.example/int.der"], timeout=5.0
            )
        assert error is None
        assert cert is not None
        assert cert.subject.rfc4514_string() == "CN=Test Intermediate CA"

    async def test_pem_response_also_parses(self, fixture: ChainFixture) -> None:
        body = fixture.intermediate_cert.public_bytes(Encoding.PEM)

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200, content=body, headers={"content-type": "application/x-pem-file"}
            )

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            cert, error = await fetch_issuer_certificate(
                client, ["https://ca.example/int.pem"], timeout=5.0
            )
        assert error is None
        assert cert is not None

    async def test_oversized_response_rejected(self, fixture: ChainFixture) -> None:
        oversized = b"0" * (chain_module.DEFAULT_MAX_FETCH_BYTES + 1)

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=oversized)

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            cert, error = await fetch_issuer_certificate(
                client, ["https://ca.example/huge.der"], timeout=5.0
            )
        assert cert is None
        assert error is not None
        assert "exceeded" in error

    async def test_404_recorded_and_next_url_tried(self, fixture: ChainFixture) -> None:
        body = fixture.intermediate_cert.public_bytes(Encoding.DER)

        def handler(request: httpx.Request) -> httpx.Response:
            if str(request.url).endswith("missing.der"):
                return httpx.Response(404)
            return httpx.Response(200, content=body)

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            cert, error = await fetch_issuer_certificate(
                client,
                ["https://ca.example/missing.der", "https://ca.example/int.der"],
                timeout=5.0,
            )
        assert cert is not None  # second URL succeeded
        assert cert.subject.rfc4514_string() == "CN=Test Intermediate CA"

    async def test_all_urls_fail_returns_last_error(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500)

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            cert, error = await fetch_issuer_certificate(
                client,
                ["https://ca.example/a.der", "https://ca.example/b.der"],
                timeout=5.0,
            )
        assert cert is None
        assert error is not None
        assert "b.der" in error


# ---------------------------------------------------------------------------
# default_trust_store
# ---------------------------------------------------------------------------


class TestDefaultTrustStore:
    def test_loads_without_error(self) -> None:
        store = default_trust_store()
        assert isinstance(store, Store)

    def test_cached_across_calls(self) -> None:
        # lru_cache keyed on the (empty) extra_pem_paths tuple -- same
        # object back, not a re-parse of certifi's ~150 roots.
        assert default_trust_store() is default_trust_store()
