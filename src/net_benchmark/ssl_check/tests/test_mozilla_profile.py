"""Tests for `net_benchmark.ssl_check.mozilla_profile`.

`REAL_GUIDELINES` below is the actual `data.tlsref.org/guidelines/latest.json`
content (version 6.0), fetched directly to verify the schema and current
profile set before writing this module -- not fabricated. No test fetches
it live; the mocked transport below serves the same bytes.
"""

from __future__ import annotations

import datetime
import json

import httpx
import pytest

from net_benchmark.ssl_check.certificate import (
    CertificateInfo,
    Fingerprints,
    KeyType,
    LifetimeAudit,
    LifetimeVerdict,
    PublicKeyInfo,
)
from net_benchmark.ssl_check.core import SSLResult
from net_benchmark.ssl_check.deep_introspection import (
    DeepIntrospectionResult,
    DHParamsResult,
    NamedGroupsResult,
    TLS13CipherResult,
    VersionProbeResult,
)
from net_benchmark.ssl_check.enumeration import (
    CipherPreferenceResult,
    CipherStrength,
    CipherSupport,
    EnumerationResult,
    VersionSupport,
)
from net_benchmark.ssl_check.handshake import (
    HandshakeStatus,
    StartTLSProtocol,
    TLSVersion,
)
from net_benchmark.ssl_check.mozilla_profile import (
    check_mozilla_profiles,
    evaluate_profile,
    fetch_guidelines,
)

UTC = datetime.timezone.utc
NOW = datetime.datetime.now(UTC)

# The real, current (v6.0) document -- no "old" profile, confirmed by
# fetching it directly before writing this module.
REAL_GUIDELINES = {
    "version": 6.0,
    "href": "https://data.tlsref.org/guidelines/6.0.json",
    "configurations": {
        "modern": {
            "certificate_curves": ["prime256v1", "secp384r1"],
            "certificate_signatures": [
                "ecdsa-with-SHA256",
                "ecdsa-with-SHA384",
                "ecdsa-with-SHA512",
            ],
            "certificate_types": ["ecdsa"],
            "ciphers": {"iana": [], "openssl": []},
            "ciphersuites": [
                "TLS_AES_128_GCM_SHA256",
                "TLS_AES_256_GCM_SHA384",
                "TLS_CHACHA20_POLY1305_SHA256",
            ],
            "dh_param_size": None,
            "ecdh_param_size": 256,
            "hsts_min_age": 63072000,
            "maximum_certificate_lifespan": 90,
            "ocsp_staple": True,
            "rsa_key_size": None,
            "server_preferred_order": False,
            "tls_curves": ["X25519MLKEM768", "X25519", "prime256v1", "secp384r1"],
            "tls_versions": ["TLSv1.3"],
        },
        "intermediate": {
            "certificate_curves": ["prime256v1", "secp384r1"],
            "certificate_signatures": [
                "sha256WithRSAEncryption",
                "ecdsa-with-SHA256",
                "ecdsa-with-SHA384",
                "ecdsa-with-SHA512",
            ],
            "certificate_types": ["ecdsa", "rsa"],
            "ciphers": {
                "iana": [
                    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
                    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
                ],
                "openssl": [
                    "ECDHE-ECDSA-AES128-GCM-SHA256",
                    "ECDHE-RSA-AES128-GCM-SHA256",
                    "ECDHE-ECDSA-AES256-GCM-SHA384",
                    "ECDHE-RSA-AES256-GCM-SHA384",
                    "ECDHE-ECDSA-CHACHA20-POLY1305",
                    "ECDHE-RSA-CHACHA20-POLY1305",
                ],
            },
            "ciphersuites": [
                "TLS_AES_128_GCM_SHA256",
                "TLS_AES_256_GCM_SHA384",
                "TLS_CHACHA20_POLY1305_SHA256",
            ],
            "dh_param_size": 2048,
            "ecdh_param_size": 256,
            "hsts_min_age": 63072000,
            "maximum_certificate_lifespan": 366,
            "ocsp_staple": True,
            "rsa_key_size": 2048,
            "server_preferred_order": False,
            "tls_curves": ["X25519MLKEM768", "X25519", "prime256v1", "secp384r1"],
            "tls_versions": ["TLSv1.2", "TLSv1.3"],
        },
    },
}


def _fingerprints() -> Fingerprints:
    return Fingerprints(
        cert_sha256="a" * 64,
        cert_sha1="b" * 40,
        spki_sha256="c" * 64,
        spki_sha256_b64="d",
    )


def _lifetime(days: int = 90) -> LifetimeAudit:
    return LifetimeAudit(
        not_before=NOW - datetime.timedelta(days=1),
        not_after=NOW + datetime.timedelta(days=days - 1),
        lifetime_days=days,
        days_remaining=days - 1,
        verdict=LifetimeVerdict.COMPLIANT,
    )


def _base_result(**overrides) -> SSLResult:
    result = SSLResult(
        host="example.com",
        port=443,
        starttls=StartTLSProtocol.NONE,
        status=HandshakeStatus.OK,
        start_time=0.0,
        end_time=0.0,
        measured=True,
    )
    for key, value in overrides.items():
        setattr(result, key, value)
    return result


class TestEvaluateProfileIntermediate:
    def test_fully_compliant(self) -> None:
        cert = CertificateInfo(
            subject_dn="CN=example.com",
            issuer_dn="CN=Test CA",
            serial_number="1",
            version=3,
            fingerprints=_fingerprints(),
            lifetime=_lifetime(90),
            public_key=PublicKeyInfo(
                key_type=KeyType.ECDSA, key_size=256, curve_name="secp256r1"
            ),
            signature_algorithm="ecdsa-with-SHA256",
        )
        result = _base_result(
            certificate=cert,
            enumeration=EnumerationResult(
                attempted=True,
                versions=[
                    VersionSupport(TLSVersion.TLSV1_2, True),
                    VersionSupport(TLSVersion.TLSV1_3, True),
                ],
                ciphers=[
                    CipherSupport(
                        "ECDHE-RSA-AES128-GCM-SHA256",
                        None,
                        True,
                        CipherStrength.A,
                        "ok",
                    )
                ],
            ),
            deep_introspection=DeepIntrospectionResult(
                attempted=True,
                versions=VersionProbeResult(
                    attempted=True, versions=["TLS 1.2", "TLS 1.3"]
                ),
                tls13_ciphers=TLS13CipherResult(
                    attempted=True, suites=["TLS_AES_128_GCM_SHA256"]
                ),
                named_groups=NamedGroupsResult(attempted=True, groups=["X25519"]),
                dh_params=DHParamsResult(attempted=True),
            ),
            cipher_preference=CipherPreferenceResult(
                attempted=True, server_enforces_order=False
            ),
        )
        spec = REAL_GUIDELINES["configurations"]["intermediate"]
        outcome = evaluate_profile("intermediate", spec, result)
        assert outcome.compliant is True
        assert outcome.violations == []

    def test_extra_tls_version_is_a_violation(self) -> None:
        cert = CertificateInfo(
            subject_dn="CN=example.com",
            issuer_dn="CN=Test CA",
            serial_number="1",
            version=3,
            fingerprints=_fingerprints(),
            lifetime=_lifetime(90),
            public_key=PublicKeyInfo(
                key_type=KeyType.ECDSA, key_size=256, curve_name="secp256r1"
            ),
            signature_algorithm="ecdsa-with-SHA256",
        )
        result = _base_result(
            certificate=cert,
            enumeration=EnumerationResult(
                attempted=True,
                versions=[
                    VersionSupport(
                        TLSVersion.TLSV1_0, True
                    ),  # not allowed by Intermediate
                    VersionSupport(TLSVersion.TLSV1_2, True),
                ],
                ciphers=[],
            ),
        )
        spec = REAL_GUIDELINES["configurations"]["intermediate"]
        outcome = evaluate_profile("intermediate", spec, result)
        assert outcome.compliant is False
        assert any(
            v.field == "tls_versions" and "TLS1.0" in v.observed
            for v in outcome.violations
        )

    def test_disallowed_cipher_is_a_violation(self) -> None:
        cert = CertificateInfo(
            subject_dn="CN=example.com",
            issuer_dn="CN=Test CA",
            serial_number="1",
            version=3,
            fingerprints=_fingerprints(),
            lifetime=_lifetime(90),
            public_key=PublicKeyInfo(key_type=KeyType.RSA, key_size=2048),
            signature_algorithm="sha256WithRSAEncryption",
        )
        result = _base_result(
            certificate=cert,
            enumeration=EnumerationResult(
                attempted=True,
                versions=[VersionSupport(TLSVersion.TLSV1_2, True)],
                ciphers=[
                    CipherSupport("RC4-SHA", None, True, CipherStrength.C, "weak"),
                ],
            ),
        )
        spec = REAL_GUIDELINES["configurations"]["intermediate"]
        outcome = evaluate_profile("intermediate", spec, result)
        assert outcome.compliant is False
        assert any(v.field == "ciphers" for v in outcome.violations)

    def test_certificate_curve_alias_recognised(self) -> None:
        """cryptography reports 'secp256r1'; the guidelines list
        'prime256v1' -- the same curve, different naming convention. Must
        not be flagged as a violation.
        """
        cert = CertificateInfo(
            subject_dn="CN=example.com",
            issuer_dn="CN=Test CA",
            serial_number="1",
            version=3,
            fingerprints=_fingerprints(),
            lifetime=_lifetime(90),
            public_key=PublicKeyInfo(
                key_type=KeyType.ECDSA, key_size=256, curve_name="secp256r1"
            ),
            signature_algorithm="ecdsa-with-SHA256",
        )
        result = _base_result(certificate=cert)
        spec = REAL_GUIDELINES["configurations"]["intermediate"]
        outcome = evaluate_profile("intermediate", spec, result)
        assert not any(v.field == "certificate_curves" for v in outcome.violations)

    def test_weak_rsa_key_is_a_violation(self) -> None:
        cert = CertificateInfo(
            subject_dn="CN=example.com",
            issuer_dn="CN=Test CA",
            serial_number="1",
            version=3,
            fingerprints=_fingerprints(),
            lifetime=_lifetime(90),
            public_key=PublicKeyInfo(key_type=KeyType.RSA, key_size=1024),
            signature_algorithm="sha256WithRSAEncryption",
        )
        result = _base_result(certificate=cert)
        spec = REAL_GUIDELINES["configurations"]["intermediate"]
        outcome = evaluate_profile("intermediate", spec, result)
        assert any(v.field == "rsa_key_size" for v in outcome.violations)

    def test_certificate_lifetime_too_long_is_a_violation(self) -> None:
        cert = CertificateInfo(
            subject_dn="CN=example.com",
            issuer_dn="CN=Test CA",
            serial_number="1",
            version=3,
            fingerprints=_fingerprints(),
            lifetime=_lifetime(400),  # > 366 day cap
            public_key=PublicKeyInfo(key_type=KeyType.RSA, key_size=2048),
            signature_algorithm="sha256WithRSAEncryption",
        )
        result = _base_result(certificate=cert)
        spec = REAL_GUIDELINES["configurations"]["intermediate"]
        outcome = evaluate_profile("intermediate", spec, result)
        assert any(
            v.field == "maximum_certificate_lifespan" for v in outcome.violations
        )

    def test_not_evaluated_always_lists_ocsp_and_hsts(self) -> None:
        result = _base_result(certificate=None)
        spec = REAL_GUIDELINES["configurations"]["intermediate"]
        outcome = evaluate_profile("intermediate", spec, result)
        assert any("ocsp_staple" in n for n in outcome.not_evaluated)
        assert any("hsts_min_age" in n for n in outcome.not_evaluated)

    def test_no_data_gives_none_not_false(self) -> None:
        result = _base_result(certificate=None)
        spec = REAL_GUIDELINES["configurations"]["intermediate"]
        outcome = evaluate_profile("intermediate", spec, result)
        assert outcome.compliant is None


class TestEvaluateProfileModern:
    def test_rsa_certificate_violates_modern_ecdsa_requirement(self) -> None:
        cert = CertificateInfo(
            subject_dn="CN=example.com",
            issuer_dn="CN=Test CA",
            serial_number="1",
            version=3,
            fingerprints=_fingerprints(),
            lifetime=_lifetime(90),
            public_key=PublicKeyInfo(key_type=KeyType.RSA, key_size=2048),
            signature_algorithm="sha256WithRSAEncryption",
        )
        result = _base_result(certificate=cert)
        spec = REAL_GUIDELINES["configurations"]["modern"]
        outcome = evaluate_profile("modern", spec, result)
        assert any(v.field == "certificate_types" for v in outcome.violations)


class TestCheckMozillaProfiles:
    async def test_old_profile_does_not_exist(self) -> None:
        result = _base_result()
        async with httpx.AsyncClient() as client:
            audit = await check_mozilla_profiles(
                result, client=client, profiles=["old"], guidelines=REAL_GUIDELINES
            )
        assert audit.attempted is True
        assert audit.available_profiles == ["intermediate", "modern"]
        assert "old" in audit.results
        assert audit.results["old"].compliant is None
        assert any("does not exist" in n for n in audit.results["old"].not_evaluated)

    async def test_defaults_to_every_available_profile(self) -> None:
        result = _base_result()
        async with httpx.AsyncClient() as client:
            audit = await check_mozilla_profiles(
                result, client=client, guidelines=REAL_GUIDELINES
            )
        assert set(audit.results) == {"modern", "intermediate"}

    async def test_guideline_version_recorded(self) -> None:
        result = _base_result()
        async with httpx.AsyncClient() as client:
            audit = await check_mozilla_profiles(
                result, client=client, guidelines=REAL_GUIDELINES
            )
        assert audit.guideline_version == "6.0"
        assert audit.guideline_url == "https://data.tlsref.org/guidelines/6.0.json"


class TestFetchGuidelines:
    @pytest.fixture(autouse=True)
    def _isolated_cache(self, tmp_path):
        self.cache_path = tmp_path / "guidelines.json"

    async def test_fetch_and_cache(self) -> None:
        body = json.dumps(REAL_GUIDELINES).encode()

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=body)

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            data, error = await fetch_guidelines(client, cache_path=self.cache_path)
        assert error is None
        assert data is not None
        assert data["version"] == 6.0
        assert self.cache_path.exists()

    async def test_second_fetch_served_from_cache(self) -> None:
        body = json.dumps(REAL_GUIDELINES).encode()
        call_count = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            call_count["n"] += 1
            return httpx.Response(200, content=body)

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            await fetch_guidelines(client, cache_path=self.cache_path)
            await fetch_guidelines(client, cache_path=self.cache_path)
        assert call_count["n"] == 1

    async def test_fetch_failure_returns_error_not_exception(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500)

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            data, error = await fetch_guidelines(client, cache_path=self.cache_path)
        assert data is None
        assert error is not None
