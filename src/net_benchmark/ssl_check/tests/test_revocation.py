"""Tests for `net_benchmark.ssl_check.revocation`.

No test makes a real network call -- OCSP responders and CRL distribution
points are both served by an `httpx.MockTransport`, same convention
`test_chain.py` uses for AIA. `cryptography`'s own `ocsp.OCSPResponseBuilder`
and `x509.CertificateRevocationListBuilder` build the mocked responses, so
this exercises the real parse/verify path against real DER, not a stub.
"""

from __future__ import annotations

import datetime
from typing import Optional

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from net_benchmark.ssl_check.certificate import RevocationEndpoints
from net_benchmark.ssl_check.revocation import (
    CRLStatus,
    OCSPStatus,
    check_revocation,
)

UTC = datetime.timezone.utc
NOW = datetime.datetime.now(UTC)


@pytest.fixture(autouse=True)
def _isolated_crl_cache_dir(tmp_path, monkeypatch):
    """Every test gets its own on-disk CRL cache location, never the real
    default (`~/.cache/net-benchmark/crl`).

    Without this, a stale entry an earlier test's `check_revocation` call
    wrote under `sha256(CRL_URL)` gets served to a *later* test that reuses
    the same `CRL_URL` constant but built a fresh `RevocationFixture` with a
    different issuer key -- the cached CRL, signed by the earlier issuer,
    then fails signature verification against the current one. That's
    exactly the failure this fixture exists to prevent; found it by tracing
    a real, reproducible `INVALID_SIGNATURE` rather than assuming.

    `TestCRLCache` tests that specifically exercise caching pass their own
    `crl_cache=CRLCache(directory=tmp_path / ...)` or `use_crl_cache=False`
    and are unaffected by this default.
    """
    from net_benchmark.ssl_check import revocation as revocation_module

    monkeypatch.setattr(
        revocation_module,
        "default_crl_cache_dir",
        lambda: tmp_path / "crl-cache-default",
    )


OCSP_URL = "https://ca.example/ocsp"
OCSP_URL_2 = "https://ca.example/ocsp2"
CRL_URL = "https://ca.example/crl"


class RevocationFixture:
    def __init__(self) -> None:
        self.issuer_key = ec.generate_private_key(ec.SECP256R1())
        self.issuer_subject = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, "Test Issuer")]
        )
        self.issuer_cert = (
            x509.CertificateBuilder()
            .subject_name(self.issuer_subject)
            .issuer_name(self.issuer_subject)
            .public_key(self.issuer_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(NOW - datetime.timedelta(days=1))
            .not_valid_after(NOW + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(self.issuer_key.public_key()),
                critical=False,
            )
            .sign(self.issuer_key, hashes.SHA256())
        )
        self.leaf_key = ec.generate_private_key(ec.SECP256R1())
        self.leaf_cert = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")])
            )
            .issuer_name(self.issuer_subject)
            .public_key(self.leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(NOW - datetime.timedelta(days=1))
            .not_valid_after(NOW + datetime.timedelta(days=90))
            .sign(self.issuer_key, hashes.SHA256())
        )

    @property
    def leaf_der(self) -> bytes:
        return self.leaf_cert.public_bytes(Encoding.DER)

    def endpoints(
        self, *, ocsp_urls: list = None, crl_urls: list = None  # type: ignore[assignment]
    ) -> RevocationEndpoints:
        return RevocationEndpoints(
            ocsp_urls=ocsp_urls if ocsp_urls is not None else [OCSP_URL],
            crl_urls=crl_urls if crl_urls is not None else [CRL_URL],
        )

    def ocsp_response(
        self,
        *,
        status: ocsp.OCSPCertStatus = ocsp.OCSPCertStatus.GOOD,
        signer_key=None,
        responder_id_cert=None,
        embed_delegate_cert=None,
        next_update: Optional[datetime.datetime] = None,
        revocation_time: Optional[datetime.datetime] = None,
        revocation_reason=None,
    ) -> bytes:
        key = signer_key or self.issuer_key
        # The cert used for the responder_id field: `.sign()` requires its
        # public key to match `key`, so a "wrong key" test has to supply its
        # own matching cert here, separate from `embed_delegate_cert` (which
        # is what `check_ocsp`'s delegation path actually verifies).
        id_cert = responder_id_cert or self.issuer_cert
        if status is ocsp.OCSPCertStatus.REVOKED and revocation_time is None:
            revocation_time = NOW - datetime.timedelta(days=2)
        builder = ocsp.OCSPResponseBuilder().add_response(
            cert=self.leaf_cert,
            issuer=self.issuer_cert,
            algorithm=hashes.SHA1(),
            cert_status=status,
            this_update=NOW,
            next_update=(
                next_update
                if next_update is not None
                else NOW + datetime.timedelta(days=1)
            ),
            revocation_time=revocation_time,
            revocation_reason=revocation_reason,
        )
        if embed_delegate_cert is not None:
            builder = builder.certificates([embed_delegate_cert])
        builder = builder.responder_id(ocsp.OCSPResponderEncoding.HASH, id_cert)
        return builder.sign(key, hashes.SHA256()).public_bytes(Encoding.DER)

    def delegate(self) -> "tuple":
        """An OCSP-signing delegate certificate, properly issued by the
        issuer (EKU: id-kp-OCSPSigning).
        """
        delegate_key = ec.generate_private_key(ec.SECP256R1())
        delegate_subject = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, "OCSP Responder")]
        )
        delegate_cert = (
            x509.CertificateBuilder()
            .subject_name(delegate_subject)
            .issuer_name(self.issuer_subject)
            .public_key(delegate_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(NOW - datetime.timedelta(days=1))
            .not_valid_after(NOW + datetime.timedelta(days=30))
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.OCSP_SIGNING]), False
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    self.issuer_key.public_key()
                ),
                False,
            )
            .sign(self.issuer_key, hashes.SHA256())
        )
        return delegate_key, delegate_cert

    def crl(
        self,
        *,
        revoked_serials: list = None,  # type: ignore[assignment]
        signer_key=None,
        last_update: Optional[datetime.datetime] = None,
        next_update: Optional[datetime.datetime] = None,
    ) -> bytes:
        key = signer_key or self.issuer_key
        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(self.issuer_subject)
            .last_update(last_update if last_update is not None else NOW)
            .next_update(
                next_update
                if next_update is not None
                else NOW + datetime.timedelta(days=7)
            )
        )
        for serial in revoked_serials or []:
            entry = (
                x509.RevokedCertificateBuilder()
                .serial_number(serial)
                .revocation_date(NOW - datetime.timedelta(days=1))
                .build()
            )
            builder = builder.add_revoked_certificate(entry)
        return builder.sign(key, hashes.SHA256()).public_bytes(Encoding.DER)


def _mock_client(responses: dict) -> httpx.AsyncClient:
    def handler(request: httpx.Request) -> httpx.Response:
        entry = responses.get(str(request.url))
        if entry is None:
            return httpx.Response(404)
        status, body = entry if isinstance(entry, tuple) else (200, entry)
        return httpx.Response(status, content=body)

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


@pytest.fixture
def fixture() -> RevocationFixture:
    return RevocationFixture()


# ---------------------------------------------------------------------------
# OCSP
# ---------------------------------------------------------------------------


class TestOCSP:
    async def test_good(self, fixture: RevocationFixture) -> None:
        responses = {OCSP_URL: fixture.ocsp_response(status=ocsp.OCSPCertStatus.GOOD)}
        async with _mock_client(responses) as client:
            audit = await check_revocation(
                fixture.leaf_der,
                fixture.endpoints(crl_urls=[]),
                client=client,
                issuer=fixture.issuer_cert,
                now=NOW,
            )
        assert audit.ocsp_status is OCSPStatus.GOOD
        assert audit.ocsp_responder_url == OCSP_URL
        # CRL is the primary channel (see revocation.py's module docstring);
        # OCSP alone confirms nothing was revoked, but does not confirm
        # good on its own.
        assert audit.revoked is None

    async def test_revoked(self, fixture: RevocationFixture) -> None:
        responses = {
            OCSP_URL: fixture.ocsp_response(
                status=ocsp.OCSPCertStatus.REVOKED,
                revocation_time=NOW - datetime.timedelta(days=3),
                revocation_reason=x509.ReasonFlags.key_compromise,
            )
        }
        async with _mock_client(responses) as client:
            audit = await check_revocation(
                fixture.leaf_der,
                fixture.endpoints(crl_urls=[]),
                client=client,
                issuer=fixture.issuer_cert,
                now=NOW,
            )
        assert audit.ocsp_status is OCSPStatus.REVOKED
        assert audit.ocsp_revocation_reason == "keyCompromise"
        assert audit.revoked is True

    async def test_delegated_responder_verified(
        self, fixture: RevocationFixture
    ) -> None:
        delegate_key, delegate_cert = fixture.delegate()
        responses = {
            OCSP_URL: fixture.ocsp_response(
                status=ocsp.OCSPCertStatus.GOOD,
                signer_key=delegate_key,
                responder_id_cert=delegate_cert,
                embed_delegate_cert=delegate_cert,
            )
        }
        async with _mock_client(responses) as client:
            audit = await check_revocation(
                fixture.leaf_der,
                fixture.endpoints(crl_urls=[]),
                client=client,
                issuer=fixture.issuer_cert,
                now=NOW,
            )
        assert audit.ocsp_status is OCSPStatus.GOOD
        assert audit.ocsp_responder_delegated is True

    async def test_response_signed_by_wrong_key_rejected(
        self, fixture: RevocationFixture
    ) -> None:
        # Signed by an unrelated key with no delegate cert embedded --
        # check_ocsp verifies straight against the real issuer's public key
        # (the no-delegation path), which this signature will not match.
        # `responder_id_cert` just needs *a* cert whose public key matches
        # the signing key, to satisfy the builder's own key/cert check.
        rogue_key = ec.generate_private_key(ec.SECP256R1())
        rogue_cert = (
            x509.CertificateBuilder()
            .subject_name(fixture.issuer_subject)
            .issuer_name(fixture.issuer_subject)
            .public_key(rogue_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(NOW - datetime.timedelta(days=1))
            .not_valid_after(NOW + datetime.timedelta(days=1))
            .sign(rogue_key, hashes.SHA256())
        )
        responses = {
            OCSP_URL: fixture.ocsp_response(
                status=ocsp.OCSPCertStatus.GOOD,
                signer_key=rogue_key,
                responder_id_cert=rogue_cert,
            )
        }
        async with _mock_client(responses) as client:
            audit = await check_revocation(
                fixture.leaf_der,
                fixture.endpoints(crl_urls=[]),
                client=client,
                issuer=fixture.issuer_cert,
                now=NOW,
            )
        assert audit.ocsp_status is OCSPStatus.INVALID_SIGNATURE
        assert audit.revoked is None
        assert any("signature did not verify" in e for e in audit.check_errors)

    async def test_stale_response_not_trusted(self, fixture: RevocationFixture) -> None:
        responses = {
            OCSP_URL: fixture.ocsp_response(
                status=ocsp.OCSPCertStatus.GOOD,
                next_update=NOW - datetime.timedelta(days=1),
            )
        }
        async with _mock_client(responses) as client:
            audit = await check_revocation(
                fixture.leaf_der,
                fixture.endpoints(crl_urls=[]),
                client=client,
                issuer=fixture.issuer_cert,
                now=NOW,
            )
        assert audit.ocsp_status is OCSPStatus.STALE
        assert audit.revoked is None

    async def test_first_url_down_second_url_used(
        self, fixture: RevocationFixture
    ) -> None:
        responses = {
            OCSP_URL: (500, b""),
            OCSP_URL_2: fixture.ocsp_response(status=ocsp.OCSPCertStatus.GOOD),
        }
        async with _mock_client(responses) as client:
            audit = await check_revocation(
                fixture.leaf_der,
                fixture.endpoints(ocsp_urls=[OCSP_URL, OCSP_URL_2], crl_urls=[]),
                client=client,
                issuer=fixture.issuer_cert,
                now=NOW,
            )
        assert audit.ocsp_status is OCSPStatus.GOOD
        assert audit.ocsp_responder_url == OCSP_URL_2
        assert any(OCSP_URL in e for e in audit.check_errors)

    async def test_all_urls_unreachable(self, fixture: RevocationFixture) -> None:
        async with _mock_client({}) as client:  # every URL 404s
            audit = await check_revocation(
                fixture.leaf_der,
                fixture.endpoints(crl_urls=[]),
                client=client,
                issuer=fixture.issuer_cert,
                now=NOW,
            )
        assert audit.ocsp_status is OCSPStatus.UNREACHABLE
        assert audit.revoked is None

    async def test_no_ocsp_urls_not_checked(self, fixture: RevocationFixture) -> None:
        async with _mock_client({}) as client:
            audit = await check_revocation(
                fixture.leaf_der,
                fixture.endpoints(ocsp_urls=[], crl_urls=[]),
                client=client,
                issuer=fixture.issuer_cert,
                now=NOW,
            )
        assert audit.ocsp_status is OCSPStatus.NOT_CHECKED
        assert audit.attempted is True  # invoked; just nothing to check


# ---------------------------------------------------------------------------
# CRL
# ---------------------------------------------------------------------------


class TestCRL:
    async def test_good(self, fixture: RevocationFixture) -> None:
        responses = {CRL_URL: fixture.crl(revoked_serials=[])}
        async with _mock_client(responses) as client:
            audit = await check_revocation(
                fixture.leaf_der,
                fixture.endpoints(ocsp_urls=[]),
                client=client,
                issuer=fixture.issuer_cert,
                now=NOW,
            )
        assert audit.crl_status is CRLStatus.GOOD
        assert audit.revoked is False

    async def test_revoked(self, fixture: RevocationFixture) -> None:
        responses = {
            CRL_URL: fixture.crl(revoked_serials=[fixture.leaf_cert.serial_number])
        }
        async with _mock_client(responses) as client:
            audit = await check_revocation(
                fixture.leaf_der,
                fixture.endpoints(ocsp_urls=[]),
                client=client,
                issuer=fixture.issuer_cert,
                now=NOW,
            )
        assert audit.crl_status is CRLStatus.REVOKED
        assert audit.crl_revocation_time is not None
        assert audit.revoked is True

    async def test_wrong_signer_rejected(self, fixture: RevocationFixture) -> None:
        rogue_key = ec.generate_private_key(ec.SECP256R1())
        responses = {CRL_URL: fixture.crl(signer_key=rogue_key)}
        async with _mock_client(responses) as client:
            audit = await check_revocation(
                fixture.leaf_der,
                fixture.endpoints(ocsp_urls=[]),
                client=client,
                issuer=fixture.issuer_cert,
                now=NOW,
            )
        assert audit.crl_status is CRLStatus.INVALID_SIGNATURE
        assert audit.revoked is None

    async def test_stale_crl_not_trusted(self, fixture: RevocationFixture) -> None:
        responses = {
            CRL_URL: fixture.crl(
                last_update=NOW - datetime.timedelta(days=10),
                next_update=NOW - datetime.timedelta(days=3),
            )
        }
        async with _mock_client(responses) as client:
            audit = await check_revocation(
                fixture.leaf_der,
                fixture.endpoints(ocsp_urls=[]),
                client=client,
                issuer=fixture.issuer_cert,
                now=NOW,
            )
        assert audit.crl_status is CRLStatus.STALE
        assert audit.revoked is None


# ---------------------------------------------------------------------------
# Combined OCSP + CRL semantics, issuer sourcing, misc
# ---------------------------------------------------------------------------


class TestCombinedAndMisc:
    async def test_ocsp_revoked_wins_even_if_crl_good(
        self, fixture: RevocationFixture
    ) -> None:
        """The two channels can disagree -- OCSP saying REVOKED must not be
        masked by a CRL that has not caught up yet.
        """
        responses = {
            OCSP_URL: fixture.ocsp_response(status=ocsp.OCSPCertStatus.REVOKED),
            CRL_URL: fixture.crl(revoked_serials=[]),
        }
        async with _mock_client(responses) as client:
            audit = await check_revocation(
                fixture.leaf_der,
                fixture.endpoints(),
                client=client,
                issuer=fixture.issuer_cert,
                now=NOW,
            )
        assert audit.ocsp_status is OCSPStatus.REVOKED
        assert audit.crl_status is CRLStatus.GOOD
        assert audit.revoked is True

    async def test_issuer_fetched_via_aia_when_not_provided(
        self, fixture: RevocationFixture
    ) -> None:
        aia_url = "https://ca.example/issuer.der"
        endpoints = RevocationEndpoints(
            ocsp_urls=[OCSP_URL], crl_urls=[], ca_issuer_urls=[aia_url]
        )
        responses = {
            OCSP_URL: fixture.ocsp_response(status=ocsp.OCSPCertStatus.GOOD),
            aia_url: fixture.issuer_cert.public_bytes(Encoding.DER),
        }
        async with _mock_client(responses) as client:
            audit = await check_revocation(
                fixture.leaf_der,
                endpoints,
                client=client,
                issuer=None,
                now=NOW,
            )
        assert audit.issuer_source == "aia_fetch"
        assert audit.ocsp_status is OCSPStatus.GOOD

    async def test_no_issuer_no_aia_url_fails_cleanly(
        self, fixture: RevocationFixture
    ) -> None:
        endpoints = RevocationEndpoints(
            ocsp_urls=[OCSP_URL], crl_urls=[], ca_issuer_urls=[]
        )
        async with _mock_client({}) as client:
            audit = await check_revocation(
                fixture.leaf_der,
                endpoints,
                client=client,
                issuer=None,
                now=NOW,
            )
        assert audit.ocsp_status is OCSPStatus.NOT_CHECKED
        assert audit.check_errors
        assert audit.issuer_source is None

    async def test_no_endpoints_at_all(self, fixture: RevocationFixture) -> None:
        async with _mock_client({}) as client:
            audit = await check_revocation(
                fixture.leaf_der,
                RevocationEndpoints(ocsp_urls=[], crl_urls=[]),
                client=client,
                issuer=fixture.issuer_cert,
                now=NOW,
            )
        assert audit.attempted is True
        assert audit.ocsp_status is OCSPStatus.NOT_CHECKED
        assert audit.crl_status is CRLStatus.NOT_CHECKED
        assert audit.revoked is None

    async def test_leaf_unparseable_does_not_raise(
        self, fixture: RevocationFixture
    ) -> None:
        async with _mock_client({}) as client:
            audit = await check_revocation(
                b"not a certificate",
                fixture.endpoints(),
                client=client,
                issuer=fixture.issuer_cert,
                now=NOW,
            )
        assert audit.attempted is True
        assert audit.check_errors
        assert "unparseable" in audit.check_errors[0]


class TestCRLCache:
    async def test_second_fetch_served_from_cache(
        self, fixture: RevocationFixture, tmp_path
    ) -> None:
        from net_benchmark.ssl_check.revocation import CRLCache

        call_count = {"n": 0}
        crl_bytes = fixture.crl(revoked_serials=[])

        def handler(request: httpx.Request) -> httpx.Response:
            call_count["n"] += 1
            return httpx.Response(200, content=crl_bytes)

        cache = CRLCache(directory=tmp_path / "crl-cache")
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            audit1 = await check_revocation(
                fixture.leaf_der,
                fixture.endpoints(ocsp_urls=[]),
                client=client,
                issuer=fixture.issuer_cert,
                now=NOW,
                crl_cache=cache,
            )
            audit2 = await check_revocation(
                fixture.leaf_der,
                fixture.endpoints(ocsp_urls=[]),
                client=client,
                issuer=fixture.issuer_cert,
                now=NOW,
                crl_cache=cache,
            )
        assert call_count["n"] == 1, "second fetch should have hit the cache"
        assert audit1.crl_from_cache is False
        assert audit2.crl_from_cache is True
        assert audit1.crl_status is CRLStatus.GOOD
        assert audit2.crl_status is CRLStatus.GOOD

    async def test_use_crl_cache_false_disables_caching(
        self, fixture: RevocationFixture, tmp_path, monkeypatch
    ) -> None:
        from net_benchmark.ssl_check import revocation as revocation_module

        # Point the default cache dir somewhere harmless in case the
        # no-cache path is broken and it writes anyway -- the assertion
        # below is what actually proves the behaviour.
        monkeypatch.setattr(
            revocation_module, "default_crl_cache_dir", lambda: tmp_path / "unused"
        )
        call_count = {"n": 0}
        crl_bytes = fixture.crl(revoked_serials=[])

        def handler(request: httpx.Request) -> httpx.Response:
            call_count["n"] += 1
            return httpx.Response(200, content=crl_bytes)

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            for _ in range(2):
                await check_revocation(
                    fixture.leaf_der,
                    fixture.endpoints(ocsp_urls=[]),
                    client=client,
                    issuer=fixture.issuer_cert,
                    now=NOW,
                    use_crl_cache=False,
                )
        assert call_count["n"] == 2, "caching disabled should mean no cache hit"

    async def test_crl_checked_before_ocsp(self, fixture: RevocationFixture) -> None:
        order: list = []

        def handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if url == CRL_URL:
                order.append("crl")
                return httpx.Response(200, content=fixture.crl(revoked_serials=[]))
            order.append("ocsp")
            return httpx.Response(
                200, content=fixture.ocsp_response(status=ocsp.OCSPCertStatus.GOOD)
            )

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            await check_revocation(
                fixture.leaf_der,
                fixture.endpoints(),
                client=client,
                issuer=fixture.issuer_cert,
                now=NOW,
                use_crl_cache=False,
            )
        assert order == ["crl", "ocsp"]
