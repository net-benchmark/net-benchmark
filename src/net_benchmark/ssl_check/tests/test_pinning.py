"""Tests for `net_benchmark.ssl_check.pinning`."""

from __future__ import annotations

import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from net_benchmark.ssl_check.certificate import CertificateInfo, Fingerprints
from net_benchmark.ssl_check.chain import ChainAudit, ChainLink, ChainSource
from net_benchmark.ssl_check.core import SSLResult
from net_benchmark.ssl_check.handshake import HandshakeStatus, StartTLSProtocol
from net_benchmark.ssl_check.pinning import generate_pin_set

UTC = datetime.timezone.utc
NOW = datetime.datetime.now(UTC)


def _real_cert(cn: str) -> x509.Certificate:
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - datetime.timedelta(days=1))
        .not_valid_after(NOW + datetime.timedelta(days=89))
        .sign(key, hashes.SHA256())
    )


def _cert_info(cn: str, spki_b64: str) -> CertificateInfo:
    return CertificateInfo(
        subject_dn=f"CN={cn}",
        issuer_dn="CN=Test CA",
        serial_number="1",
        version=3,
        subject_cn=cn,
        fingerprints=Fingerprints(
            cert_sha256="a" * 64,
            cert_sha1="b" * 40,
            spki_sha256="c" * 64,
            spki_sha256_b64=spki_b64,
        ),
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


class TestGeneratePinSet:
    def test_leaf_only_no_chain(self) -> None:
        result = _base_result(certificate=_cert_info("example.com", "LEAFPIN"))
        pin_set = generate_pin_set(result)
        assert pin_set.attempted is True
        assert len(pin_set.pins) == 1
        assert pin_set.pins[0].label == "leaf"
        assert pin_set.pins[0].spki_sha256_b64 == "LEAFPIN"
        assert pin_set.backup_pins_unavailable is True

    def test_leaf_plus_chain_with_root(self) -> None:
        chain_audit = ChainAudit(
            attempted=True,
            verified=True,
            links=[
                ChainLink(
                    certificate=_cert_info("Intermediate CA", "INTPIN"),
                    source=ChainSource.PEER,
                    raw=_real_cert("Intermediate CA"),
                ),
                ChainLink(
                    certificate=_cert_info("Root CA", "ROOTPIN"),
                    source=ChainSource.PEER,
                    raw=_real_cert("Root CA"),
                ),
            ],
        )
        result = _base_result(
            certificate=_cert_info("example.com", "LEAFPIN"), chain_audit=chain_audit
        )
        pin_set = generate_pin_set(result)
        assert [p.label for p in pin_set.pins] == ["leaf", "intermediate-1", "root"]
        assert [p.spki_sha256_b64 for p in pin_set.pins] == [
            "LEAFPIN",
            "INTPIN",
            "ROOTPIN",
        ]
        assert pin_set.backup_pins_unavailable is False

    def test_exclude_root(self) -> None:
        chain_audit = ChainAudit(
            attempted=True,
            verified=True,
            links=[
                ChainLink(
                    certificate=_cert_info("Intermediate CA", "INTPIN"),
                    source=ChainSource.PEER,
                    raw=_real_cert("Intermediate CA"),
                ),
                ChainLink(
                    certificate=_cert_info("Root CA", "ROOTPIN"),
                    source=ChainSource.PEER,
                    raw=_real_cert("Root CA"),
                ),
            ],
        )
        result = _base_result(
            certificate=_cert_info("example.com", "LEAFPIN"), chain_audit=chain_audit
        )
        pin_set = generate_pin_set(result, include_root=False)
        assert [p.label for p in pin_set.pins] == ["leaf", "intermediate-1"]
        assert "ROOTPIN" not in [p.spki_sha256_b64 for p in pin_set.pins]

    def test_hpkp_header_value_format(self) -> None:
        result = _base_result(certificate=_cert_info("example.com", "LEAFPIN"))
        pin_set = generate_pin_set(result)
        assert pin_set.hpkp_header_value == 'pin-sha256="LEAFPIN"'

    def test_no_certificate_reports_error(self) -> None:
        result = _base_result(certificate=None)
        pin_set = generate_pin_set(result)
        assert pin_set.attempted is True
        assert pin_set.error is not None
        assert pin_set.pins == []

    def test_to_dict_shape(self) -> None:
        result = _base_result(certificate=_cert_info("example.com", "LEAFPIN"))
        pin_set = generate_pin_set(result)
        d = pin_set.to_dict()
        assert d["attempted"] is True
        assert len(d["pins"]) == 1
        assert "hpkp_header_value" in d
