"""Tests for `net_benchmark.ssl_check.certificate`.

Every certificate here is a fixture built by `cert_factory` / `make_cert`; no
test parses a certificate fetched from a real host. Deterministic input is the
point: the lifetime and expiry-tier assertions depend on exact day counts, and
a live certificate's validity window changes on its own schedule.
"""

from __future__ import annotations

import datetime
import ipaddress
from pathlib import Path
from typing import Callable, Tuple

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from net_benchmark.ssl_check.certificate import (
    DEFAULT_EXPIRY_TIERS,
    ExpiryAlert,
    HostnameMatch,
    KeyType,
    LifetimeVerdict,
    _match_dns_label,
    audit_wildcards,
    cab_lifetime_cap,
    cab_short_lived_threshold,
    expiry_alert,
    match_hostname,
    parse_cert_der_compat,
    parse_certificate,
)

from .conftest import make_cert, make_key

CertFactory = Callable[..., Tuple[Path, Path, x509.Certificate]]
UTC = datetime.timezone.utc


def _der(cert_factory: CertFactory, **kwargs: object) -> bytes:
    _, _, certificate = cert_factory(**kwargs)
    return certificate.public_bytes(Encoding.DER)


def _der_at(
    tmp_path: Path,
    *,
    validity_days: int,
    not_before: datetime.datetime,
    filename_hint: str,
    **kwargs: object,
) -> bytes:
    """Build a certificate with an explicit historical `not_before`.

    `cert_factory`'s `age_days` is relative to wall-clock "now" at call time,
    which cannot place a certificate's issuance at a specific date in the
    past. The lifetime-schedule tests need that, so they go through
    `make_cert` directly with `age_days` computed against the fixed reference
    date the test is reasoning about.
    """
    reference_now = datetime.datetime.now(UTC)
    age_days = (reference_now - not_before).days
    _, _, certificate = make_cert(
        tmp_path,
        validity_days=validity_days,
        age_days=age_days,
        filename_hint=filename_hint,
        **kwargs,  # type: ignore[arg-type]
    )
    return certificate.public_bytes(Encoding.DER)


class TestHostnameMatching:
    """Item 11 - RFC 6125 wildcard rules, not fnmatch and not CN fallback."""

    @pytest.mark.parametrize(
        "pattern,hostname,expected",
        [
            ("*.example.com", "a.example.com", True),
            ("*.example.com", "example.com", False),  # wildcard != bare domain
            ("*.example.com", "a.b.example.com", False),  # one label only
            ("f*.example.com", "foo.example.com", False),  # not leftmost-complete
            ("*.*.example.com", "a.b.example.com", False),  # single '*' only
            ("example.com", "EXAMPLE.COM", True),  # case-insensitive
            ("*.example.com", ".example.com", False),  # empty label
            ("*.example.com", "a.example.com.", True),  # trailing dot on host
        ],
    )
    def test_dns_label_matching(
        self, pattern: str, hostname: str, expected: bool
    ) -> None:
        assert _match_dns_label(pattern, hostname) is expected

    def test_match_via_wildcard_san(self, cert_factory: CertFactory) -> None:
        der = _der(
            cert_factory,
            sans=[x509.DNSName("*.example.com"), x509.DNSName("example.com")],
        )
        info = parse_certificate(der)
        assert match_hostname(info, "a.example.com") is HostnameMatch.MATCH
        assert match_hostname(info, "example.com") is HostnameMatch.MATCH
        assert match_hostname(info, "evil.com") is HostnameMatch.MISMATCH

    def test_cn_only_certificate_is_no_san_not_match(
        self, cert_factory: CertFactory
    ) -> None:
        """CN-as-hostname was deprecated by RFC 2818 and removed from Chrome
        in 2017. A CN-only certificate must NOT be reported as matching -
        that would be a false pass for a certificate every current browser
        rejects."""
        der = _der(cert_factory, common_name="cnonly.test", sans=[])
        info = parse_certificate(der)
        assert match_hostname(info, "cnonly.test") is HostnameMatch.NO_SAN

    def test_ip_san_matches_ip_not_dns(self, cert_factory: CertFactory) -> None:
        der = _der(
            cert_factory, sans=[x509.IPAddress(ipaddress.ip_address("10.0.0.1"))]
        )
        info = parse_certificate(der)
        assert match_hostname(info, "10.0.0.1") is HostnameMatch.MATCH
        assert match_hostname(info, "10.0.0.2") is HostnameMatch.MISMATCH

    def test_empty_hostname_not_checked(self, cert_factory: CertFactory) -> None:
        der = _der(cert_factory)
        info = parse_certificate(der)
        assert match_hostname(info, "") is HostnameMatch.NOT_CHECKED


class TestWildcardAudit:
    """Item 6 - presence, malformed patterns, and scope heuristic."""

    def test_no_wildcard(self) -> None:
        assert audit_wildcards(["example.com"]).present is False

    def test_simple_wildcard_not_flagged_broad(self) -> None:
        audit = audit_wildcards(["*.example.com"])
        assert audit.present is True
        assert audit.overly_broad is False

    def test_two_label_wildcard_flagged_broad(self) -> None:
        """*.com has only two labels. Deciding this authoritatively needs the
        Public Suffix List, out of scope here - this is a heuristic flag, not
        a verdict, and the note says so."""
        audit = audit_wildcards(["*.com"])
        assert audit.overly_broad is True
        assert audit.note is not None

    def test_malformed_wildcard_noted(self) -> None:
        audit = audit_wildcards(["f*.example.com"])
        assert audit.note is not None
        assert "f*.example.com" in (audit.note or "")


class TestKeyAudit:
    """Item 8 - RSA <2048 and the EC/Ed25519 paths."""

    def test_rsa_2048_not_weak(self, cert_factory: CertFactory) -> None:
        info = parse_certificate(_der(cert_factory, key=make_key("rsa2048")))
        assert info.public_key.key_type is KeyType.RSA
        assert info.public_key.key_size == 2048
        assert info.public_key.weak is False

    def test_ec_p256_not_weak(self, cert_factory: CertFactory) -> None:
        info = parse_certificate(_der(cert_factory, key=make_key("ec")))
        assert info.public_key.key_type is KeyType.ECDSA
        assert info.public_key.curve_name == "secp256r1"
        assert info.public_key.weak is False

    def test_ed25519_key_and_no_signature_hash(self, cert_factory: CertFactory) -> None:
        """Ed25519 has no separable signature hash - cryptography raises on
        signature_hash_algorithm for it. That must not surface as an unknown
        or weak hash; it is the strongest algorithm the tool sees."""
        info = parse_certificate(_der(cert_factory, key=make_key("ed25519")))
        assert info.public_key.key_type is KeyType.ED25519
        assert info.signature_weak is False
        assert info.signature_hash is None


class TestSignatureAudit:
    """Item 7 - SHA-1/MD5 flagged, current hashes not."""

    def test_sha256_not_weak(self, cert_factory: CertFactory) -> None:
        info = parse_certificate(_der(cert_factory))
        assert info.signature_weak is False
        assert info.signature_hash == "sha256"

    def test_sha1_flagged(self, cert_factory: CertFactory) -> None:
        # cryptography 44 refuses to SIGN with SHA-1, so a realistic legacy
        # fixture is built by patching the AlgorithmIdentifier OID bytes in
        # the DER from sha256WithRSAEncryption to sha1WithRSAEncryption - same
        # length, differing only in the final byte (0x0b vs 0x05).
        der = _der(cert_factory, key=make_key("rsa2048"))
        sha256_rsa = bytes.fromhex("06092a864886f70d01010b")
        sha1_rsa = bytes.fromhex("06092a864886f70d010105")
        assert der.count(sha256_rsa) == 2
        info = parse_certificate(der.replace(sha256_rsa, sha1_rsa))
        assert info.signature_weak is True
        assert info.signature_hash == "sha1"
        assert info.signature_weak_reason is not None


class TestSelfSignedDetection:
    """Item 10 - self_issued (DN match) is necessary but not sufficient for
    self_signed (signature verification): cross-signed roots and misconfigured
    private CAs both produce self-issued certificates signed by a DIFFERENT
    key."""

    def test_self_issued_and_self_signed(self, cert_factory: CertFactory) -> None:
        info = parse_certificate(
            _der(cert_factory, common_name="root", issuer_cn="root")
        )
        assert info.self_issued is True
        assert info.self_signed is True

    def test_normal_leaf_not_self_issued(self, cert_factory: CertFactory) -> None:
        info = parse_certificate(
            _der(cert_factory, common_name="leaf", issuer_cn="SomeCA")
        )
        assert info.self_issued is False
        # Never verified, so left None - not False. A check that did not run
        # has not established that someone else signed it.
        assert info.self_signed is None


class TestCABLifetimeSchedule:
    """Item 16 - the schedule must cover certificates issued before
    2026-03-15, or the audit reports UNKNOWN for most of the live web."""

    def test_2018_step(self) -> None:
        assert cab_lifetime_cap(datetime.datetime(2019, 1, 1, tzinfo=UTC))[0] == 825

    def test_2020_step(self) -> None:
        assert cab_lifetime_cap(datetime.datetime(2025, 6, 1, tzinfo=UTC))[0] == 398

    def test_2026_step(self) -> None:
        assert cab_lifetime_cap(datetime.datetime(2026, 6, 1, tzinfo=UTC))[0] == 200

    def test_2027_step(self) -> None:
        assert cab_lifetime_cap(datetime.datetime(2027, 6, 1, tzinfo=UTC))[0] == 100

    def test_2029_step(self) -> None:
        assert cab_lifetime_cap(datetime.datetime(2029, 6, 1, tzinfo=UTC))[0] == 47

    def test_before_schedule_is_unknown(self) -> None:
        cap, effective = cab_lifetime_cap(datetime.datetime(2017, 1, 1, tzinfo=UTC))
        assert cap is None
        assert effective is None

    def test_short_lived_thresholds(self) -> None:
        assert (
            cab_short_lived_threshold(datetime.datetime(2025, 1, 1, tzinfo=UTC)) == 10
        )
        assert cab_short_lived_threshold(datetime.datetime(2026, 4, 1, tzinfo=UTC)) == 7


class TestLifetimeAudit:
    """Items 16-18. `now` is always injected - see --as-of, item 55."""

    def test_compliant_under_cap(self, tmp_path: Path) -> None:
        nb = datetime.datetime(2026, 4, 1, tzinfo=UTC)
        now = datetime.datetime(2026, 5, 1, tzinfo=UTC)
        der = _der_at(tmp_path, validity_days=150, not_before=nb, filename_hint="a")
        info = parse_certificate(der, now=now)
        assert info.lifetime is not None
        assert info.lifetime.verdict is LifetimeVerdict.COMPLIANT

    def test_exactly_at_cap_is_compliant(self, tmp_path: Path) -> None:
        """The CA/B validity period is inclusive of the cap; only EXCEEDING it
        is a violation, matching how zlint implements the same check."""
        nb = datetime.datetime(2026, 4, 1, tzinfo=UTC)
        now = datetime.datetime(2026, 5, 1, tzinfo=UTC)
        der = _der_at(tmp_path, validity_days=200, not_before=nb, filename_hint="b")
        info = parse_certificate(der, now=now)
        assert info.lifetime is not None
        assert info.lifetime.verdict is LifetimeVerdict.COMPLIANT

    def test_over_cap_is_non_compliant(self, tmp_path: Path) -> None:
        nb = datetime.datetime(2026, 4, 1, tzinfo=UTC)
        now = datetime.datetime(2026, 5, 1, tzinfo=UTC)
        der = _der_at(tmp_path, validity_days=250, not_before=nb, filename_hint="c")
        info = parse_certificate(der, now=now)
        assert info.lifetime is not None
        assert info.lifetime.verdict is LifetimeVerdict.NON_COMPLIANT

    def test_short_lived_flag(self, tmp_path: Path) -> None:
        nb = datetime.datetime(2026, 4, 1, tzinfo=UTC)
        now = datetime.datetime(2026, 5, 1, tzinfo=UTC)
        der = _der_at(tmp_path, validity_days=6, not_before=nb, filename_hint="d")
        info = parse_certificate(der, now=now)
        assert info.lifetime is not None
        assert info.lifetime.short_lived is True

    def test_fails_at_next_renewal(self, tmp_path: Path) -> None:
        """Item 17 - compliant under the current cap, but a renewal of the
        same length crosses into a lower cap taking effect before this
        certificate expires."""
        nb = datetime.datetime(2026, 12, 1, tzinfo=UTC)  # 200-day cap in force
        der = _der_at(
            tmp_path,
            validity_days=180,  # expires 2027-05-30, after the 2027-03-15 step
            not_before=nb,
            filename_hint="e",
        )
        info = parse_certificate(der, now=nb)
        assert info.lifetime is not None
        assert info.lifetime.verdict is LifetimeVerdict.FAILS_AT_NEXT_RENEWAL
        assert info.lifetime.next_cap_days == 100

    def test_no_cap_before_schedule(self, tmp_path: Path) -> None:
        der = _der_at(
            tmp_path,
            validity_days=90,
            not_before=datetime.datetime(2017, 1, 1, tzinfo=UTC),
            filename_hint="f",
        )
        info = parse_certificate(der, now=datetime.datetime(2017, 6, 1, tzinfo=UTC))
        assert info.lifetime is not None
        assert info.lifetime.cap_days is None
        assert info.lifetime.verdict is LifetimeVerdict.UNKNOWN

    def test_expired_and_not_yet_valid_flags(self, tmp_path: Path) -> None:
        nb = datetime.datetime(2026, 1, 1, tzinfo=UTC)
        der = _der_at(tmp_path, validity_days=30, not_before=nb, filename_hint="g")
        past = parse_certificate(der, now=datetime.datetime(2026, 6, 1, tzinfo=UTC))
        future = parse_certificate(der, now=datetime.datetime(2025, 1, 1, tzinfo=UTC))
        assert past.lifetime is not None and past.lifetime.expired is True
        assert future.lifetime is not None and future.lifetime.not_yet_valid is True


class TestExpiryAlertTiers:
    """Item 42 - fraction-of-validity thresholds with an absolute floor and a
    fixed ceiling. A fixed 30/14/7/1 schedule breaks against a 6-day
    certificate; the tiers must not."""

    class _FakeLifetime:
        def __init__(self, lifetime_days: int, days_remaining: int) -> None:
            self.lifetime_days = lifetime_days
            self.days_remaining = days_remaining
            self.expired = days_remaining < 0

    def test_no_certificate_is_unknown_not_expired(self) -> None:
        """The single most important assertion in this class: treating a
        missing certificate as 0 days remaining would report every
        unreachable host as an expiry emergency."""
        assert expiry_alert(None) is ExpiryAlert.UNKNOWN

    def test_expired(self) -> None:
        assert expiry_alert(self._FakeLifetime(90, -1)) is ExpiryAlert.EXPIRED  # type: ignore[arg-type]

    def test_six_day_cert_scales_down(self) -> None:
        """A fixed 30-day NOTICE would fire before a 6-day certificate is even
        issued. The tiers must scale to the certificate's own validity."""
        assert expiry_alert(self._FakeLifetime(6, 4)) is ExpiryAlert.OK  # type: ignore[arg-type]
        assert expiry_alert(self._FakeLifetime(6, 2)) is ExpiryAlert.NOTICE  # type: ignore[arg-type]
        assert expiry_alert(self._FakeLifetime(6, 1)) is ExpiryAlert.CRITICAL  # type: ignore[arg-type]

    def test_long_cert_uses_fixed_ceiling(self) -> None:
        """398 * 1/3 is 131 days - the fixed 30-day cap must win, or a
        year-long certificate spends four months in permanent NOTICE."""
        assert expiry_alert(self._FakeLifetime(398, 100)) is ExpiryAlert.OK  # type: ignore[arg-type]
        assert expiry_alert(self._FakeLifetime(398, 25)) is ExpiryAlert.NOTICE  # type: ignore[arg-type]
        assert expiry_alert(self._FakeLifetime(398, 5)) is ExpiryAlert.CRITICAL  # type: ignore[arg-type]

    def test_tiers_ordered_most_urgent_first(self) -> None:
        levels = [tier.level for tier in DEFAULT_EXPIRY_TIERS]
        assert levels == [
            ExpiryAlert.CRITICAL,
            ExpiryAlert.WARNING,
            ExpiryAlert.NOTICE,
        ]


class TestExtensions:
    """Items 13, 31, 36."""

    def test_must_staple_and_eku(self, tmp_path: Path) -> None:
        key = make_key("ec")
        now = datetime.datetime.now(UTC)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "staple.test")])
        certificate = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=90))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName("staple.test")]), False
            )
            .add_extension(x509.TLSFeature([x509.TLSFeatureType.status_request]), False)
            .add_extension(
                x509.ExtendedKeyUsage(
                    [
                        ExtendedKeyUsageOID.SERVER_AUTH,
                        ExtendedKeyUsageOID.CODE_SIGNING,
                    ]
                ),
                False,
            )
            .sign(key, hashes.SHA256())
        )
        info = parse_certificate(certificate.public_bytes(Encoding.DER))
        assert info.revocation.must_staple is True
        assert info.usage.has_server_auth is True
        assert info.usage.conflicting_ekus == ["codeSigning"]
        assert info.revocation.has_any_source is False

    def test_no_revocation_endpoints_on_plain_cert(
        self, cert_factory: CertFactory
    ) -> None:
        info = parse_certificate(_der(cert_factory))
        assert info.revocation.ocsp_urls == []
        assert info.revocation.crl_urls == []
        assert info.revocation.has_any_source is False


class TestFingerprints:
    """Item 9 - SPKI pin fingerprint is over the KEY, not the certificate, so
    it survives a routine renewal that reuses the key."""

    def test_fingerprint_lengths(self, cert_factory: CertFactory) -> None:
        info = parse_certificate(_der(cert_factory))
        assert info.fingerprints is not None
        assert len(info.fingerprints.cert_sha256) == 64  # hex SHA-256
        assert len(info.fingerprints.cert_sha1) == 40  # hex SHA-1
        assert len(info.fingerprints.spki_sha256_b64) == 44  # base64 SHA-256

    def test_spki_fingerprint_stable_across_renewal_with_same_key(
        self, cert_factory: CertFactory
    ) -> None:
        key = make_key("ec")
        info1 = parse_certificate(_der(cert_factory, key=key, filename_hint="r1"))
        info2 = parse_certificate(_der(cert_factory, key=key, filename_hint="r2"))
        assert info1.fingerprints is not None and info2.fingerprints is not None
        # Same key, different certificates (different serials) - SPKI
        # fingerprint matches, certificate fingerprint does not.
        assert info1.fingerprints.spki_sha256 == info2.fingerprints.spki_sha256
        assert info1.fingerprints.cert_sha256 != info2.fingerprints.cert_sha256


class TestHTTPCompatShim:
    """Item 15 - the migration target for http_bench.core._parse_cert_der."""

    def test_matches_legacy_tuple_shape(self, cert_factory: CertFactory) -> None:
        der = _der(
            cert_factory,
            common_name="compat.test",
            issuer_cn="TestCA",
            sans=[x509.DNSName("*.compat.test")],
        )
        days, subject_cn, issuer_cn, sans, wildcard = parse_cert_der_compat(der)
        assert subject_cn == "compat.test"
        assert issuer_cn == "TestCA"
        assert sans == ["*.compat.test"]
        assert wildcard is True
        assert isinstance(days, int)

    def test_garbage_bytes_return_legacy_all_none(self) -> None:
        """Matches _parse_cert_der's existing contract for non-certificate
        bytes: the migration must not change HTTPResult population on this
        path."""
        assert parse_cert_der_compat(b"not a certificate") == (
            None,
            None,
            None,
            [],
            False,
        )


class TestParseCertificateRaisesOnGarbage:
    def test_non_certificate_bytes_raise(self) -> None:
        """Non-certificate bytes raise; a malformed but genuine certificate
        does not - see the module docstring on why those are different
        failure classes."""
        with pytest.raises(ValueError):
            parse_certificate(b"definitely not DER")
