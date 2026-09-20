"""Tests for `net_benchmark.ssl_check.grading`.

Every scenario's expected grade is hand-computed against the actual SSL
Labs Server Rating Guide tables (fetched and read in full before writing
`grading.py` -- see that module's docstring), not just asserted against
whatever the code happens to produce. Comments show the arithmetic.
"""

from __future__ import annotations

from net_benchmark.ssl_check.certificate import (
    CertificateInfo,
    Fingerprints,
    HostnameMatch,
    KeyType,
    LifetimeAudit,
    LifetimeVerdict,
    PublicKeyInfo,
)
from net_benchmark.ssl_check.chain import ChainAudit
from net_benchmark.ssl_check.core import SSLResult
from net_benchmark.ssl_check.deep_introspection import (
    DeepIntrospectionResult,
    DHParamsResult,
    ExtensionsResult,
    NamedGroupsResult,
    TLS13CipherResult,
    VersionProbeResult,
    VulnerabilitiesResult,
)
from net_benchmark.ssl_check.enumeration import (
    CipherStrength,
    CipherSupport,
    EnumerationResult,
    VersionSupport,
)
from net_benchmark.ssl_check.grading import Grade, grade_certificate, normalize_version
from net_benchmark.ssl_check.handshake import (
    HandshakeStatus,
    StartTLSProtocol,
    TLSVersion,
)


def _fingerprints() -> Fingerprints:
    return Fingerprints(
        cert_sha256="a" * 64,
        cert_sha1="b" * 40,
        spki_sha256="c" * 64,
        spki_sha256_b64="d",
    )


def _valid_lifetime() -> LifetimeAudit:
    from datetime import datetime, timedelta, timezone

    now = datetime.now(timezone.utc)
    return LifetimeAudit(
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=89),
        lifetime_days=90,
        days_remaining=89,
        verdict=LifetimeVerdict.COMPLIANT,
    )


def _certificate(
    key_type: KeyType = KeyType.ECDSA,
    key_size: int = 256,
    self_issued: bool = False,
    signature_weak: bool = False,
    signature_hash: str = "sha256",
    weak_key: bool = False,
) -> CertificateInfo:
    return CertificateInfo(
        subject_dn="CN=example.com",
        issuer_dn="CN=Test CA",
        serial_number="1",
        version=3,
        subject_cn="example.com",
        fingerprints=_fingerprints(),
        lifetime=_valid_lifetime(),
        public_key=PublicKeyInfo(key_type=key_type, key_size=key_size, weak=weak_key),
        signature_weak=signature_weak,
        signature_hash=signature_hash,
        self_issued=self_issued,
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
        certificate=_certificate(),
        hostname_match=HostnameMatch.MATCH,
        chain_audit=ChainAudit(attempted=True, verified=True),
    )
    for key, value in overrides.items():
        setattr(result, key, value)
    return result


class TestNormalizeVersion:
    def test_enumeration_style(self) -> None:
        assert normalize_version("TLSv1.2") == "TLS1.2"
        assert normalize_version("TLSv1.3") == "TLS1.3"
        assert normalize_version("TLSv1") == "TLS1.0"
        assert normalize_version("SSLv3") == "SSL3"

    def test_cryptolyzer_style(self) -> None:
        assert normalize_version("TLS 1.2") == "TLS1.2"
        assert normalize_version("TLS 1.3") == "TLS1.3"
        assert normalize_version("SSL 2.0") == "SSL2"
        assert normalize_version("SSL 3.0") == "SSL3"

    def test_tls13_draft_normalises_to_tls13(self) -> None:
        assert normalize_version("TLS 1.3 Draft 18") == "TLS1.3"
        assert normalize_version("TLS1_3_DRAFT_18") == "TLS1.3"

    def test_unrecognised_returns_none(self) -> None:
        assert normalize_version("carrier pigeon") is None


class TestCertificateBaseFailures:
    def test_name_mismatch_is_m(self) -> None:
        result = _base_result(hostname_match=HostnameMatch.MISMATCH)
        grade = grade_certificate(result)
        assert grade.grade is Grade.M

    def test_self_signed_is_t(self) -> None:
        result = _base_result(certificate=_certificate(self_issued=True))
        grade = grade_certificate(result)
        assert grade.grade is Grade.T

    def test_untrusted_chain_is_t(self) -> None:
        result = _base_result(
            chain_audit=ChainAudit(
                attempted=True, verified=False, verification_error="untrusted root"
            )
        )
        grade = grade_certificate(result)
        assert grade.grade is Grade.T

    def test_expired_is_f(self) -> None:
        from datetime import datetime, timedelta, timezone

        now = datetime.now(timezone.utc)
        expired = LifetimeAudit(
            not_before=now - timedelta(days=100),
            not_after=now - timedelta(days=1),
            lifetime_days=99,
            days_remaining=-1,
            verdict=LifetimeVerdict.COMPLIANT,
            expired=True,
        )
        cert = _certificate()
        cert.lifetime = expired
        result = _base_result(certificate=cert)
        grade = grade_certificate(result)
        assert grade.grade is Grade.F

    def test_weak_signature_is_f(self) -> None:
        result = _base_result(
            certificate=_certificate(signature_weak=True, signature_hash="sha1")
        )
        grade = grade_certificate(result)
        assert grade.grade is Grade.F

    def test_weak_key_is_f(self) -> None:
        cert = _certificate(key_type=KeyType.RSA, key_size=512)
        cert.public_key.weak = True
        cert.public_key.weak_reason = "RSA key under 2048 bits"
        result = _base_result(certificate=cert)
        grade = grade_certificate(result)
        assert grade.grade is Grade.F

    def test_no_certificate_no_grade(self) -> None:
        result = _base_result(certificate=None)
        grade = grade_certificate(result)
        assert grade.grade is None
        assert grade.data_gaps


class TestBaseScoring:
    def test_modern_perfect_config_grades_a(self) -> None:
        """TLS 1.3 only, 256-bit AEAD cipher, X25519 ECDHE, EC-256 cert key.

        Hand-computed:
          protocol: best=worst=TLS1.3=100 -> (100+100)/2 = 100
          cipher: best=worst=256-bit AEAD=100 -> (100+100)/2 = 100
          key exchange: cert EC-256 -> 3072-bit equivalent; ephemeral
            X25519 -> 3072-bit equivalent; min=3072 -> Table 4 bucket
            2048<=x<4096 -> 90
          overall = 0.30*100 + 0.30*90 + 0.40*100 = 30 + 27 + 40 = 97 -> A
          No caps apply (TLS 1.3 supported, no vulnerabilities set).
        """
        result = _base_result(
            enumeration=EnumerationResult(
                attempted=True,
                versions=[VersionSupport(TLSVersion.TLSV1_3, True)],
                ciphers=[],
            ),
            deep_introspection=DeepIntrospectionResult(
                attempted=True,
                versions=VersionProbeResult(attempted=True, versions=["TLS 1.3"]),
                tls13_ciphers=TLS13CipherResult(
                    attempted=True, suites=["TLS_AES_256_GCM_SHA384"]
                ),
                named_groups=NamedGroupsResult(attempted=True, groups=["X25519"]),
                dh_params=DHParamsResult(attempted=True),
                extensions=ExtensionsResult(
                    attempted=True, compression_methods=["NULL"]
                ),
                vulnerabilities=VulnerabilitiesResult(
                    attempted=True,
                    sweet32=False,
                    rc4=False,
                    export_grade=False,
                    anonymous_dh=False,
                    weak_dh=False,
                    drown=False,
                    non_forward_secret=False,
                    poodle=False,
                    beast=False,
                ),
            ),
        )
        grade = grade_certificate(result)
        assert grade.protocol_score == 100
        assert grade.cipher_strength_score == 100
        assert grade.key_exchange_score == 90
        assert grade.numerical_score == 97
        assert grade.grade is Grade.A

    def test_no_tls13_caps_a_minus(self) -> None:
        """Same as above but TLS 1.2 only -- 2009r: no TLS 1.3 -> cap A-."""
        result = _base_result(
            enumeration=EnumerationResult(
                attempted=True,
                versions=[VersionSupport(TLSVersion.TLSV1_2, True)],
                ciphers=[],
            ),
            deep_introspection=DeepIntrospectionResult(
                attempted=True,
                versions=VersionProbeResult(attempted=True, versions=["TLS 1.2"]),
                tls13_ciphers=TLS13CipherResult(attempted=True, suites=[]),
                named_groups=NamedGroupsResult(attempted=True, groups=["X25519"]),
                dh_params=DHParamsResult(attempted=True),
                extensions=ExtensionsResult(
                    attempted=True, compression_methods=["NULL"]
                ),
                vulnerabilities=VulnerabilitiesResult(
                    attempted=True,
                    sweet32=False,
                    rc4=False,
                    export_grade=False,
                    anonymous_dh=False,
                    weak_dh=False,
                    drown=False,
                    non_forward_secret=False,
                    poodle=False,
                    beast=False,
                ),
            ),
        )
        # add a strong TLS 1.2 cipher via enumeration
        result.enumeration.ciphers = [
            CipherSupport(
                "ECDHE-RSA-AES256-GCM-SHA384", None, True, CipherStrength.A, "strong"
            )
        ]
        grade = grade_certificate(result)
        assert grade.grade is Grade.A_MINUS
        assert any("TLS 1.3 not supported" in r for r in grade.applied_rules)

    def test_sslv3_and_rc4_grades_low(self) -> None:
        """SSLv3 + TLS1.0, RC4 *and* a strong AEAD cipher both offered
        (RC4 present but not the server's only option — that's a separate,
        already-covered scenario in test_only_rc4_fails), weak-but-not-
        insecure 1536-bit DH.

        Hand-computed:
          protocol: best=TLS1.0(90) worst=SSL3(80) -> (90+80)/2 = 85
          cipher: best=256-bit AEAD=100, worst=RC4(40-bit fallback)=20 ->
            (100+20)/2 = 60
          key exchange: DHE 1536-bit -> bucket <2048 -> 80
          overall = 0.30*85 + 0.30*80 + 0.40*60 = 25.5+24+24 = 73.5 -> B (base)
          Caps in play: SSL3 supported -> B; RC4 supported (but not with
            TLS1.1+, since only SSLv3/TLS1.0 are offered here, so the
            stricter "RC4 with TLS1.1+" cap does not fire) -> B; no TLS1.2
            -> C; TLS1.0/1.1 supported -> B; weak DH <2048 -> B; no forward
            secrecy -> B.
          C is a stricter (worse) ceiling than B, so it's the tightest cap
          actually reached, and wins over both the B-tier caps and the
          base B(73.5) score.
        """
        result = _base_result(
            enumeration=EnumerationResult(
                attempted=True,
                versions=[
                    VersionSupport(TLSVersion.SSLV3, True),
                    VersionSupport(TLSVersion.TLSV1_0, True),
                ],
                ciphers=[
                    CipherSupport("RC4-SHA", None, True, CipherStrength.C, "weak"),
                    CipherSupport(
                        "ECDHE-RSA-AES256-GCM-SHA384",
                        None,
                        True,
                        CipherStrength.A,
                        "strong",
                    ),
                ],
            ),
            deep_introspection=DeepIntrospectionResult(
                attempted=True,
                versions=VersionProbeResult(
                    attempted=True, versions=["SSL 3.0", "TLS 1.0"]
                ),
                tls13_ciphers=TLS13CipherResult(attempted=True, suites=[]),
                named_groups=NamedGroupsResult(attempted=True, groups=[]),
                dh_params=DHParamsResult(attempted=True, classic_dhe_key_size=1536),
                extensions=ExtensionsResult(
                    attempted=True, compression_methods=["NULL"]
                ),
                vulnerabilities=VulnerabilitiesResult(
                    attempted=True,
                    sweet32=False,
                    rc4=True,
                    export_grade=False,
                    anonymous_dh=False,
                    weak_dh=False,
                    drown=False,
                    non_forward_secret=True,
                    insecure_ssl_version=True,
                    early_tls_version=True,
                    poodle=False,
                    beast=False,
                ),
            ),
        )
        grade = grade_certificate(result)
        assert grade.protocol_score == 85
        assert grade.cipher_strength_score == 60
        assert grade.key_exchange_score == 80
        assert grade.numerical_score == 73.5
        assert grade.grade is Grade.C

    def test_only_rc4_fails(self) -> None:
        result = _base_result(
            enumeration=EnumerationResult(
                attempted=True,
                versions=[VersionSupport(TLSVersion.TLSV1_2, True)],
                ciphers=[
                    CipherSupport("RC4-SHA", None, True, CipherStrength.C, "weak"),
                    CipherSupport("RC4-MD5", None, True, CipherStrength.C, "weak"),
                ],
            ),
            deep_introspection=DeepIntrospectionResult(
                attempted=True,
                versions=VersionProbeResult(attempted=True, versions=["TLS 1.2"]),
                tls13_ciphers=TLS13CipherResult(attempted=True, suites=[]),
                named_groups=NamedGroupsResult(attempted=True, groups=[]),
                dh_params=DHParamsResult(attempted=True),
                extensions=ExtensionsResult(
                    attempted=True, compression_methods=["NULL"]
                ),
                vulnerabilities=VulnerabilitiesResult(
                    attempted=True,
                    sweet32=False,
                    rc4=True,
                    export_grade=False,
                    anonymous_dh=False,
                    weak_dh=False,
                    drown=False,
                    non_forward_secret=True,
                    poodle=False,
                    beast=False,
                ),
            ),
        )
        grade = grade_certificate(result)
        assert grade.grade is Grade.F
        assert any("only RC4" in r for r in grade.applied_rules)

    def test_export_grade_fails(self) -> None:
        result = _base_result(
            enumeration=EnumerationResult(
                attempted=True,
                versions=[VersionSupport(TLSVersion.TLSV1_2, True)],
                ciphers=[
                    CipherSupport(
                        "ECDHE-RSA-AES256-GCM-SHA384",
                        None,
                        True,
                        CipherStrength.A,
                        "strong",
                    )
                ],
            ),
            deep_introspection=DeepIntrospectionResult(
                attempted=True,
                versions=VersionProbeResult(attempted=True, versions=["TLS 1.2"]),
                tls13_ciphers=TLS13CipherResult(attempted=True, suites=[]),
                named_groups=NamedGroupsResult(attempted=True, groups=["X25519"]),
                dh_params=DHParamsResult(attempted=True),
                extensions=ExtensionsResult(
                    attempted=True, compression_methods=["NULL"]
                ),
                vulnerabilities=VulnerabilitiesResult(
                    attempted=True,
                    sweet32=False,
                    rc4=False,
                    export_grade=True,
                    anonymous_dh=False,
                    weak_dh=False,
                    drown=False,
                    non_forward_secret=False,
                    poodle=False,
                    beast=False,
                ),
            ),
        )
        grade = grade_certificate(result)
        assert grade.grade is Grade.F

    def test_drown_fails(self) -> None:
        result = _base_result(
            enumeration=EnumerationResult(
                attempted=True,
                versions=[VersionSupport(TLSVersion.TLSV1_2, True)],
                ciphers=[
                    CipherSupport(
                        "ECDHE-RSA-AES256-GCM-SHA384",
                        None,
                        True,
                        CipherStrength.A,
                        "strong",
                    )
                ],
            ),
            deep_introspection=DeepIntrospectionResult(
                attempted=True,
                versions=VersionProbeResult(attempted=True, versions=["TLS 1.2"]),
                tls13_ciphers=TLS13CipherResult(attempted=True, suites=[]),
                named_groups=NamedGroupsResult(attempted=True, groups=["X25519"]),
                dh_params=DHParamsResult(attempted=True),
                extensions=ExtensionsResult(
                    attempted=True, compression_methods=["NULL"]
                ),
                vulnerabilities=VulnerabilitiesResult(
                    attempted=True,
                    sweet32=False,
                    rc4=False,
                    export_grade=False,
                    anonymous_dh=False,
                    weak_dh=False,
                    drown=True,
                    non_forward_secret=False,
                    poodle=False,
                    beast=False,
                ),
            ),
        )
        grade = grade_certificate(result)
        assert grade.grade is Grade.F

    def test_data_gaps_recorded_when_checks_never_ran(self) -> None:
        result = _base_result()  # no enumeration, no deep_introspection
        grade = grade_certificate(result)
        assert grade.grade is None
        assert any("enumeration" in g for g in grade.data_gaps)
        assert any("deep introspection" in g for g in grade.data_gaps)

    def test_unevaluated_rules_always_listed(self) -> None:
        result = _base_result()
        grade = grade_certificate(result)
        assert any("ROBOT" in r for r in grade.unevaluated_rules)
        assert any("Ticketbleed" in r for r in grade.unevaluated_rules)
        assert any("HSTS" in r for r in grade.unevaluated_rules)

    def test_rubric_version_recorded(self) -> None:
        result = _base_result()
        grade = grade_certificate(result)
        assert "2009r" in grade.rubric_version
        assert grade.rubric_url.startswith("https://")


class TestToDict:
    def test_shape(self) -> None:
        result = _base_result()
        grade = grade_certificate(result)
        d = grade.to_dict()
        assert d["attempted"] is True
        assert "rubric_version" in d
        assert "inputs" in d
