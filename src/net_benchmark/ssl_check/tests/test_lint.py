"""Tests for `net_benchmark.ssl_check.lint`.

Requires the `[lint]` extra (pkilint) to be installed to exercise the real
linting path; the availability/not-installed path is tested by monkeypatching
the import rather than actually uninstalling pkilint mid-suite.
"""

from __future__ import annotations

import builtins
import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from net_benchmark.ssl_check.lint import (
    FindingSeverity,
    LintAvailability,
    lint_availability,
    lint_certificate,
)

pkilint = pytest.importorskip(
    "pkilint", reason="lint.py tests require the [lint] extra"
)

UTC = datetime.timezone.utc
NOW = datetime.datetime.now(UTC)


def _realistic_dv_leaf_der() -> bytes:
    """A leaf with enough of the real Baseline-Requirements-relevant
    extensions (AKI/SKI, EKU, key usage, policy OID, AIA) that pkilint
    detects it as DV-FINAL-CERTIFICATE and produces real findings --
    verified interactively against a real pkilint install before writing
    this test, not assumed.
    """
    root_key = ec.generate_private_key(ec.SECP256R1())
    root_subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "Test Root CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
        ]
    )
    
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")])
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(leaf_subject)
        .issuer_name(root_subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - datetime.timedelta(days=1))
        .not_valid_after(NOW + datetime.timedelta(days=90))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("example.com")]), False
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                key_cert_sign=False,
                crl_sign=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.CertificatePolicies(
                [x509.PolicyInformation(x509.ObjectIdentifier("2.23.140.1.2.1"), None)]
            ),
            False,
        )
        .add_extension(
            x509.AuthorityInformationAccess(
                [
                    x509.AccessDescription(
                        x509.oid.AuthorityInformationAccessOID.OCSP,
                        x509.UniformResourceIdentifier("http://ocsp.example.com"),
                    )
                ]
            ),
            False,
        )
        .sign(root_key, hashes.SHA256())
    )
    return leaf_cert.public_bytes(Encoding.DER)


class TestLintAvailability:
    def test_available_when_pkilint_installed(self) -> None:
        assert lint_availability() is LintAvailability.AVAILABLE

    def test_not_installed_detected_via_import_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name == "pkilint":
                raise ImportError("simulated: pkilint not installed")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", fake_import)
        assert lint_availability() is LintAvailability.NOT_INSTALLED


class TestLintCertificate:
    def test_realistic_leaf_detected_as_dv(self) -> None:
        audit = lint_certificate(_realistic_dv_leaf_der())
        assert audit.attempted is True
        assert audit.availability is LintAvailability.AVAILABLE
        assert audit.pkilint_version is not None
        assert audit.detected_certificate_type == "DV-FINAL-CERTIFICATE"
        assert audit.error is None

    def test_missing_ca_issuers_aia_is_flagged(self) -> None:
        # The fixture only sets an OCSP AIA, not CA Issuers -- a real BR
        # finding, confirmed against a live pkilint run before writing this
        # assertion.
        audit = lint_certificate(_realistic_dv_leaf_der())
        codes = {f.code for f in audit.findings}
        assert "cabf.serverauth.subscriber.ca_issuers_aia_access_method_absent" in codes

    def test_findings_have_required_fields(self) -> None:
        audit = lint_certificate(_realistic_dv_leaf_der())
        assert audit.findings
        for finding in audit.findings:
            assert isinstance(finding.severity, FindingSeverity)
            assert finding.code
            assert finding.node_path

    def test_severity_threshold_filters_findings(self) -> None:
        all_findings = lint_certificate(
            _realistic_dv_leaf_der(), severity_threshold=FindingSeverity.DEBUG
        )
        errors_only = lint_certificate(
            _realistic_dv_leaf_der(), severity_threshold=FindingSeverity.ERROR
        )
        assert len(errors_only.findings) <= len(all_findings.findings)
        assert all(
            f.severity in (FindingSeverity.FATAL, FindingSeverity.ERROR)
            for f in errors_only.findings
        )

    def test_has_errors_or_worse_false_for_warning_only_findings(self) -> None:
        audit = lint_certificate(_realistic_dv_leaf_der())
        # The fixture's findings are all WARNING/INFO in practice; this
        # assertion documents the property's contract rather than assuming
        # the exact severities pkilint assigns won't shift between versions.
        if audit.findings and not any(
            f.severity in (FindingSeverity.FATAL, FindingSeverity.ERROR)
            for f in audit.findings
        ):
            assert audit.has_errors_or_worse is False

    def test_garbage_bytes_do_not_raise(self) -> None:
        audit = lint_certificate(b"not a certificate")
        assert audit.attempted is True
        assert audit.error is not None
        assert audit.findings == []

    def test_report_all_can_only_add_findings(self) -> None:
        der = _realistic_dv_leaf_der()
        filtered = lint_certificate(der, report_all=False)
        unfiltered = lint_certificate(der, report_all=True)
        assert len(unfiltered.findings) >= len(filtered.findings)

    def test_to_dict_shape(self) -> None:
        audit = lint_certificate(_realistic_dv_leaf_der())
        d = audit.to_dict()
        assert d["attempted"] is True
        assert d["availability"] == "available"
        assert isinstance(d["findings"], list)
        assert "has_errors_or_worse" in d
