"""Tests for `net_benchmark.ssl_check.san_audit`.

Every scenario runs against real local TLS servers and real DNS resolution
(genuine `nonexistent-subdomain...` lookups, genuine `localhost`
resolution) — there's no meaningful way to mock "does this hostname
resolve and serve this certificate" without losing the point of the test.
"""

from __future__ import annotations

from cryptography import x509

from net_benchmark.ssl_check.certificate import parse_certificate
from net_benchmark.ssl_check.san_audit import audit_san_entries


class TestAuditSanEntries:
    async def test_matching_san_is_clean(self, tls_server, cert_factory) -> None:
        from cryptography.hazmat.primitives.serialization import Encoding

        cert_path, key_path, cert_obj = cert_factory(
            common_name="a.example.com",
            sans=[x509.DNSName("a.example.com"), x509.DNSName("localhost")],
        )
        handle = await tls_server(cert=(cert_path, key_path, cert_obj))
        cert_info = parse_certificate(cert_obj.public_bytes(Encoding.DER))

        result = await audit_san_entries(cert_info, port=handle.port, timeout=3)
        entry = next(e for e in result.entries if e.hostname == "localhost")
        assert entry.dns_resolves is True
        assert entry.tls_reachable is True
        assert entry.serves_same_certificate is True
        assert "localhost" not in result.inactive_sans
        assert "localhost" not in result.inconsistent_sans

    async def test_nonresolving_san_is_inactive(self, tls_server, cert_factory) -> None:
        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import Encoding

        cert_path, key_path, cert_obj = cert_factory(
            common_name="a.example.com",
            sans=[
                x509.DNSName("a.example.com"),
                x509.DNSName("nonexistent-subdomain-xyz123.invalid"),
            ],
        )
        await tls_server(cert=(cert_path, key_path, cert_obj))
        cert_info = parse_certificate(cert_obj.public_bytes(Encoding.DER))

        result = await audit_san_entries(cert_info, port=443, timeout=3)
        assert "nonexistent-subdomain-xyz123.invalid" in result.inactive_sans
        entry = next(
            e
            for e in result.entries
            if e.hostname == "nonexistent-subdomain-xyz123.invalid"
        )
        assert entry.dns_resolves is False
        assert entry.error is not None

    async def test_wildcard_is_skipped_not_probed(
        self, tls_server, cert_factory
    ) -> None:
        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import Encoding

        cert_path, key_path, cert_obj = cert_factory(
            common_name="a.example.com",
            sans=[x509.DNSName("a.example.com"), x509.DNSName("*.example.com")],
        )
        await tls_server(cert=(cert_path, key_path, cert_obj))
        cert_info = parse_certificate(cert_obj.public_bytes(Encoding.DER))

        result = await audit_san_entries(cert_info, port=443, timeout=3)
        assert "*.example.com" in result.skipped_entries
        assert not any(e.hostname == "*.example.com" for e in result.entries)

    async def test_reachable_but_different_certificate_is_inconsistent(
        self, tls_server, cert_factory
    ) -> None:
        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import Encoding

        # The cert being AUDITED claims to cover "localhost".
        audited_path, audited_key, audited_cert = cert_factory(
            common_name="a.example.com",
            sans=[x509.DNSName("a.example.com"), x509.DNSName("localhost")],
        )
        # But the server actually running on localhost serves a DIFFERENT
        # cert entirely.
        real_path, real_key, real_cert = cert_factory(common_name="localhost")
        handle = await tls_server(cert=(real_path, real_key, real_cert))

        cert_info = parse_certificate(audited_cert.public_bytes(Encoding.DER))
        result = await audit_san_entries(cert_info, port=handle.port, timeout=3)

        entry = next(e for e in result.entries if e.hostname == "localhost")
        assert entry.tls_reachable is True
        assert entry.serves_same_certificate is False
        assert "localhost" in result.inconsistent_sans
        assert "localhost" not in result.inactive_sans

    async def test_max_entries_caps_probing(self, tls_server, cert_factory) -> None:
        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import Encoding

        many_sans = [x509.DNSName(f"host{i}.example.com") for i in range(10)]
        cert_path, key_path, cert_obj = cert_factory(
            common_name="a.example.com", sans=many_sans
        )
        await tls_server(cert=(cert_path, key_path, cert_obj))
        cert_info = parse_certificate(cert_obj.public_bytes(Encoding.DER))

        result = await audit_san_entries(cert_info, port=443, max_entries=3, timeout=2)
        assert len(result.entries) == 3
        assert len(result.skipped_entries) == 7

    async def test_no_fingerprints_reports_error(self) -> None:
        from net_benchmark.ssl_check.certificate import CertificateInfo

        cert_info = CertificateInfo(
            subject_dn="CN=example.com",
            issuer_dn="CN=Test CA",
            serial_number="1",
            version=3,
            san_dns=["example.com"],
        )
        result = await audit_san_entries(cert_info)
        assert result.error is not None

    def test_to_dict_shape(self) -> None:
        from net_benchmark.ssl_check.san_audit import SanAuditResult, SanEntryStatus

        result = SanAuditResult(
            attempted=True,
            entries=[
                SanEntryStatus(
                    hostname="a.example.com",
                    dns_resolves=True,
                    tls_reachable=True,
                    serves_same_certificate=True,
                ),
                SanEntryStatus(hostname="b.example.com", dns_resolves=False),
            ],
        )
        d = result.to_dict()
        assert d["attempted"] is True
        assert len(d["entries"]) == 2
        assert d["inactive_sans"] == ["b.example.com"]
