"""Tests for `net_benchmark.ssl_check.handshake`.

Every handshake here runs against the local `tls_server` / `smtp_server`
fixtures. No test reaches out to a real host — see `tests/conftest.py` for
why.
"""

from __future__ import annotations

import asyncio
import ssl
from typing import Callable, Coroutine

import pytest
from cryptography import x509

from net_benchmark.ssl_check.handshake import (
    HandshakeResult,
    HandshakeStatus,
    ProbeConfig,
    StartTLSProtocol,
    TLSVersion,
    build_client_context,
    build_ldap_starttls_request,
    iana_cipher_code,
    parse_ldap_result_code,
    probe_tls,
    starttls_for_port,
)

from .conftest import TLSServerHandle


class TestPortDefaults:
    """Item 41 — default STARTTLS mode per port."""

    def test_implicit_ports(self) -> None:
        for port in (443, 8443, 465, 993, 995, 636):
            assert starttls_for_port(port) is StartTLSProtocol.NONE

    def test_starttls_ports(self) -> None:
        assert starttls_for_port(587) is StartTLSProtocol.SMTP
        assert starttls_for_port(25) is StartTLSProtocol.SMTP
        assert starttls_for_port(143) is StartTLSProtocol.IMAP
        assert starttls_for_port(110) is StartTLSProtocol.POP3
        assert starttls_for_port(389) is StartTLSProtocol.LDAP
        assert starttls_for_port(21) is StartTLSProtocol.FTP

    def test_unknown_port_defaults_to_implicit(self) -> None:
        """Safe direction: implicit TLS against a plaintext service fails
        cleanly; STARTTLS bytes against a service expecting TLS records do
        not."""
        assert starttls_for_port(9999) is StartTLSProtocol.NONE


class TestTLSVersion:
    def test_deprecated_versions(self) -> None:
        assert TLSVersion.SSLV3.is_deprecated is True
        assert TLSVersion.TLSV1_0.is_deprecated is True
        assert TLSVersion.TLSV1_1.is_deprecated is True

    def test_current_versions_not_deprecated(self) -> None:
        assert TLSVersion.TLSV1_2.is_deprecated is False
        assert TLSVersion.TLSV1_3.is_deprecated is False

    def test_unknown_not_deprecated(self) -> None:
        """An unrecognised version is an unknown, not a deprecation finding —
        reporting it as deprecated would be a fabricated verdict."""
        assert TLSVersion.UNKNOWN.is_deprecated is False

    def test_from_openssl_unrecognised(self) -> None:
        assert TLSVersion.from_openssl("SomeFutureVersion") is TLSVersion.UNKNOWN
        assert TLSVersion.from_openssl(None) is TLSVersion.UNKNOWN

    def test_from_openssl_known(self) -> None:
        assert TLSVersion.from_openssl("TLSv1.3") is TLSVersion.TLSV1_3


class TestIANACipherCode:
    """Item 34 — cipher() has no IANA code; get_ciphers()['id'] & 0xFFFF does."""

    def test_known_tls13_suite(self) -> None:
        code = iana_cipher_code("TLS_AES_256_GCM_SHA384")
        assert code == 0x1302

    def test_known_tls12_suite(self) -> None:
        code = iana_cipher_code("ECDHE-RSA-AES128-GCM-SHA256")
        assert code == 0xC02F

    def test_unknown_suite_returns_none(self) -> None:
        """An unrecognised name must not produce an invented code point."""
        assert iana_cipher_code("NOT-A-REAL-CIPHER-SUITE") is None

    def test_none_name_returns_none(self) -> None:
        assert iana_cipher_code(None) is None


class TestLDAPStartTLS:
    """Item 39 — hand-rolled BER encode/parse, not a general LDAP client."""

    def test_request_structure(self) -> None:
        request = build_ldap_starttls_request(message_id=1)
        # SEQUENCE tag, then messageID INTEGER = 1.
        assert request[0] == 0x30
        assert request[2] == 0x02  # INTEGER tag for messageID
        assert request[3] == 0x01  # length 1
        assert request[4] == 0x01  # value 1
        # ExtendedRequest [APPLICATION 23] tag, requestName [0] context tag.
        assert 0x77 in request  # ExtendedRequest
        assert 0x80 in request  # requestName (LDAPOID)
        # The StartTLS OID travels as its dotted-string ASCII bytes.
        assert b"1.3.6.1.4.1.1466.20.037" in request

    def test_different_message_ids_differ_only_in_that_byte(self) -> None:
        r1 = build_ldap_starttls_request(message_id=1)
        r2 = build_ldap_starttls_request(message_id=7)
        assert r1[4] == 1
        assert r2[4] == 7
        assert r1[:4] == r2[:4]
        assert r1[5:] == r2[5:]

    def test_parse_success(self) -> None:
        # ExtendedResponse [APPLICATION 24] (0x78) wrapping resultCode as an
        # ENUMERATED (0x0a, RFC 4511 §4.1.9) — NOT an INTEGER (0x02); an
        # earlier version of this fixture used the wrong tag and, correctly,
        # failed to parse.
        payload = bytes.fromhex("300c02010178070a0100040004" + "00")
        assert parse_ldap_result_code(payload) == 0

    def test_parse_protocol_error(self) -> None:
        payload = bytes.fromhex("300c02010178070a0102040004" + "00")
        assert parse_ldap_result_code(payload) == 2

    def test_parse_garbage_returns_none(self) -> None:
        assert parse_ldap_result_code(b"not an LDAP message at all") is None

    def test_parse_empty_returns_none(self) -> None:
        assert parse_ldap_result_code(b"") is None


class TestBuildClientContext:
    def test_verify_disabled_unconditionally(self) -> None:
        """Trust is validated afterwards over parsed certificates, not by
        OpenSSL during the handshake — see the handshake.py module docstring
        for why."""
        context = build_client_context(ProbeConfig())
        assert context.verify_mode is ssl.CERT_NONE
        assert context.check_hostname is False

    def test_bad_cipher_string_raises(self) -> None:
        with pytest.raises(ssl.SSLError):
            build_client_context(ProbeConfig(cipher_string="NOT-A-CIPHER"))


class TestProbeTLS:
    """End-to-end handshakes against the local `tls_server` fixture."""

    async def test_successful_handshake(
        self, tls_server: Callable[..., Coroutine[None, None, TLSServerHandle]]
    ) -> None:
        handle = await tls_server()
        result = await probe_tls(
            "localhost",
            handle.port,
            config=ProbeConfig(handshake_timeout=6, pinned_ip="127.0.0.1"),
        )
        assert result.status is HandshakeStatus.OK
        assert result.succeeded is True
        assert result.tls_version is TLSVersion.TLSV1_3
        assert result.leaf_der is not None
        assert result.handshake_ms is not None
        assert result.handshake_bytes_total > 0
        assert result.cipher_id is not None

    async def test_tls12_forced(
        self, tls_server: Callable[..., Coroutine[None, None, TLSServerHandle]]
    ) -> None:
        handle = await tls_server(max_version=ssl.TLSVersion.TLSv1_2)
        result = await probe_tls(
            "localhost",
            handle.port,
            config=ProbeConfig(handshake_timeout=6, pinned_ip="127.0.0.1"),
        )
        assert result.status is HandshakeStatus.OK
        assert result.tls_version is TLSVersion.TLSV1_2
        assert result.tls_version.is_deprecated is False

    async def test_connection_refused(self, unused_tcp_port: int) -> None:
        result = await probe_tls(
            "127.0.0.1",
            unused_tcp_port,
            config=ProbeConfig(connect_timeout=3),
        )
        assert result.status is HandshakeStatus.TCP_REFUSED
        assert result.succeeded is False
        assert result.handshake_ms is None, "no timing fabricated for an unreached port"

    async def test_tcp_timeout(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A real non-routable address is not a reliable way to trigger this:
        it depends on the network path being configured to drop rather than
        reject, which varies by environment (a transparent egress proxy, for
        one, answers everything). Patching the connect call to hang tests the
        SAME code path — the `asyncio.wait_for` around
        `asyncio.open_connection` in handshake.py — without depending on
        network topology to produce the hang."""

        async def _hang(*args: object, **kwargs: object) -> None:
            await asyncio.sleep(60)

        monkeypatch.setattr(asyncio, "open_connection", _hang)

        result = await probe_tls(
            "127.0.0.1",
            443,
            config=ProbeConfig(connect_timeout=0.2),
        )
        assert result.status is HandshakeStatus.TCP_TIMEOUT
        assert result.handshake_ms is None

    async def test_hostname_carries_through_to_leaf(
        self, tls_server: Callable[..., Coroutine[None, None, TLSServerHandle]]
    ) -> None:
        handle = await tls_server(common_name="probe-target.test")
        result = await probe_tls(
            "localhost",
            handle.port,
            config=ProbeConfig(handshake_timeout=6, pinned_ip="127.0.0.1"),
        )
        assert result.leaf_der is not None
        leaf = x509.load_der_x509_certificate(result.leaf_der)
        assert leaf.subject.rfc4514_string() == "CN=probe-target.test"


class TestChainObservability:
    """The 3.10 floor with a 3.13 capability: chain visibility depends on the
    interpreter running the tool, not on the target."""

    async def test_chain_field_matches_interpreter_capability(
        self, tls_server: Callable[..., Coroutine[None, None, TLSServerHandle]]
    ) -> None:
        handle = await tls_server()
        result = await probe_tls(
            "localhost",
            handle.port,
            config=ProbeConfig(handshake_timeout=6, pinned_ip="127.0.0.1"),
        )
        has_capability = hasattr(ssl.SSLObject, "get_unverified_chain")
        if has_capability:
            assert result.peer_chain_der is not None
            assert result.chain_unavailable_reason is None
        else:
            assert result.peer_chain_der is None
            assert result.chain_unavailable_reason is not None
            assert "3.13" in result.chain_unavailable_reason


class TestSTARTTLS:
    """Item 39 — SMTP negotiator against a real plaintext-then-TLS socket."""

    async def test_starttls_advertised_and_upgrades(
        self, smtp_server: Callable[[bool], Coroutine[None, None, int]]
    ) -> None:
        port = await smtp_server(True)
        result = await probe_tls(
            "localhost",
            port,
            starttls=StartTLSProtocol.SMTP,
            config=ProbeConfig(
                handshake_timeout=6, starttls_timeout=6, pinned_ip="127.0.0.1"
            ),
        )
        assert result.status is HandshakeStatus.OK
        assert result.starttls_bytes_sent > 0
        assert result.starttls_bytes_received > 0
        # Plaintext negotiation bytes and TLS handshake bytes are counted
        # separately (item 54) — an EHLO exchange plus STARTTLS command is a
        # handful of lines and must not be conflated with the handshake.
        assert result.handshake_bytes_total > 0
        assert result.starttls_bytes_sent < result.handshake_bytes_total

    async def test_starttls_not_advertised(
        self, smtp_server: Callable[[bool], Coroutine[None, None, int]]
    ) -> None:
        port = await smtp_server(False)
        result = await probe_tls(
            "localhost",
            port,
            starttls=StartTLSProtocol.SMTP,
            config=ProbeConfig(
                handshake_timeout=6, starttls_timeout=6, pinned_ip="127.0.0.1"
            ),
        )
        assert result.status is HandshakeStatus.STARTTLS_UNSUPPORTED
        assert "STARTTLS" in (result.error_message or "")


class TestIMAPStartTLS:
    """`_negotiate_imap` against a real plaintext-then-TLS socket, mirroring
    TestSTARTTLS's SMTP coverage exactly."""

    async def test_advertised_and_upgrades(
        self, imap_server: Callable[[bool], Coroutine[None, None, int]]
    ) -> None:
        port = await imap_server(True)
        result = await probe_tls(
            "localhost",
            port,
            starttls=StartTLSProtocol.IMAP,
            config=ProbeConfig(
                handshake_timeout=6, starttls_timeout=6, pinned_ip="127.0.0.1"
            ),
        )
        assert result.status is HandshakeStatus.OK
        assert result.starttls_bytes_sent > 0
        assert result.starttls_bytes_received > 0
        assert result.handshake_bytes_total > 0

    async def test_not_advertised(
        self, imap_server: Callable[[bool], Coroutine[None, None, int]]
    ) -> None:
        port = await imap_server(False)
        result = await probe_tls(
            "localhost",
            port,
            starttls=StartTLSProtocol.IMAP,
            config=ProbeConfig(
                handshake_timeout=6, starttls_timeout=6, pinned_ip="127.0.0.1"
            ),
        )
        assert result.status is HandshakeStatus.STARTTLS_UNSUPPORTED
        assert "STARTTLS" in (result.error_message or "")


class TestPOP3StartTLS:
    """`_negotiate_pop3` against a real plaintext-then-TLS socket."""

    async def test_advertised_and_upgrades(
        self, pop3_server: Callable[[bool], Coroutine[None, None, int]]
    ) -> None:
        port = await pop3_server(True)
        result = await probe_tls(
            "localhost",
            port,
            starttls=StartTLSProtocol.POP3,
            config=ProbeConfig(
                handshake_timeout=6, starttls_timeout=6, pinned_ip="127.0.0.1"
            ),
        )
        assert result.status is HandshakeStatus.OK
        assert result.starttls_bytes_sent > 0
        assert result.handshake_bytes_total > 0

    async def test_not_advertised(
        self, pop3_server: Callable[[bool], Coroutine[None, None, int]]
    ) -> None:
        """POP3 answers -ERR for STLS the same as for any unrecognized
        command, so an unsupported STLS and a refused one are
        indistinguishable at the protocol level -- reported as
        STARTTLS_UNSUPPORTED either way, per _negotiate_pop3's own
        comment on this."""
        port = await pop3_server(False)
        result = await probe_tls(
            "localhost",
            port,
            starttls=StartTLSProtocol.POP3,
            config=ProbeConfig(
                handshake_timeout=6, starttls_timeout=6, pinned_ip="127.0.0.1"
            ),
        )
        assert result.status is HandshakeStatus.STARTTLS_UNSUPPORTED


class TestFTPStartTLS:
    """`_negotiate_ftp` against a real plaintext-then-TLS socket."""

    async def test_advertised_and_upgrades(
        self, ftp_server: Callable[[bool], Coroutine[None, None, int]]
    ) -> None:
        port = await ftp_server(True)
        result = await probe_tls(
            "localhost",
            port,
            starttls=StartTLSProtocol.FTP,
            config=ProbeConfig(
                handshake_timeout=6, starttls_timeout=6, pinned_ip="127.0.0.1"
            ),
        )
        assert result.status is HandshakeStatus.OK
        assert result.starttls_bytes_sent > 0
        assert result.handshake_bytes_total > 0

    async def test_not_advertised(
        self, ftp_server: Callable[[bool], Coroutine[None, None, int]]
    ) -> None:
        port = await ftp_server(False)
        result = await probe_tls(
            "localhost",
            port,
            starttls=StartTLSProtocol.FTP,
            config=ProbeConfig(
                handshake_timeout=6, starttls_timeout=6, pinned_ip="127.0.0.1"
            ),
        )
        assert result.status is HandshakeStatus.STARTTLS_UNSUPPORTED
        assert "AUTH TLS" in (result.error_message or "")


class TestLDAPStartTLSLive:
    """`_negotiate_ldap` against a real socket answering a BER-encoded
    ExtendedResponse -- the live-negotiation counterpart to
    TestLDAPStartTLS's byte-level unit tests above, which check
    build_ldap_starttls_request()/parse_ldap_result_code() directly
    without a socket."""

    async def test_advertised_and_upgrades(
        self, ldap_server: Callable[[bool], Coroutine[None, None, int]]
    ) -> None:
        port = await ldap_server(True)
        result = await probe_tls(
            "localhost",
            port,
            starttls=StartTLSProtocol.LDAP,
            config=ProbeConfig(
                handshake_timeout=6, starttls_timeout=6, pinned_ip="127.0.0.1"
            ),
        )
        assert result.status is HandshakeStatus.OK
        assert result.starttls_bytes_sent > 0
        assert result.starttls_bytes_received > 0
        assert result.handshake_bytes_total > 0

    async def test_protocol_error_is_unsupported(
        self, ldap_server: Callable[[bool], Coroutine[None, None, int]]
    ) -> None:
        port = await ldap_server(False)
        result = await probe_tls(
            "localhost",
            port,
            starttls=StartTLSProtocol.LDAP,
            config=ProbeConfig(
                handshake_timeout=6, starttls_timeout=6, pinned_ip="127.0.0.1"
            ),
        )
        assert result.status is HandshakeStatus.STARTTLS_UNSUPPORTED
        assert "resultCode 2" in (result.error_message or "")


class TestHandshakeResultToDict:
    """`HandshakeResult.to_dict()` -- the export-safe projection. Never
    directly exercised by the live-handshake tests above, which assert on
    the object's attributes, not its dict form."""

    async def test_successful_result_round_trips_through_json(
        self, tls_server: Callable[..., Coroutine[None, None, TLSServerHandle]]
    ) -> None:
        import json

        handle = await tls_server()
        result = await probe_tls(
            "localhost",
            handle.port,
            config=ProbeConfig(handshake_timeout=6, pinned_ip="127.0.0.1"),
        )
        payload = result.to_dict()
        # Must be JSON-serializable -- this is the export-safety contract
        # to_dict() exists for; a raw ssl.SSLSession or DER bytes leaking
        # into the dict would fail this immediately.
        json.dumps(payload)
        assert payload["status"] == "ok"
        assert payload["tls_version"] == "TLSv1.3"
        assert payload["cipher_iana_hex"] == f"0x{result.cipher_id:04x}"
        assert payload["chain_length"] == (
            len(result.peer_chain_der) if result.peer_chain_der is not None else None
        )

    async def test_failed_result_has_no_fabricated_timing(
        self, unused_tcp_port: int
    ) -> None:
        import json

        result = await probe_tls(
            "127.0.0.1", unused_tcp_port, config=ProbeConfig(connect_timeout=2)
        )
        payload = result.to_dict()
        json.dumps(payload)
        assert payload["status"] == "tcp_refused"
        assert payload["handshake_ms"] is None
        assert payload["cipher_iana_hex"] is None

    def test_session_and_der_fields_excluded(self) -> None:
        """The one thing to_dict() exists to guarantee: no raw session
        object or certificate bytes ever reach an export."""
        result = HandshakeResult(
            host="x",
            port=443,
            starttls=StartTLSProtocol.NONE,
            status=HandshakeStatus.OK,
            start_time=0.0,
            leaf_der=b"\x30\x82fake-der-bytes",
        )
        payload = result.to_dict()
        assert "session" not in payload
        assert "leaf_der" not in payload
        assert "peer_chain_der" not in payload
