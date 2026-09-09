"""Shared fixtures for the SSL/TLS module test suite.

Every fixture here runs against a **local** server bound to 127.0.0.1 on an
OS-assigned port. No test in this package makes a network call to a real
host — the whole point of the transport split in `handshake.py` is that the
engine is testable this way, and a suite that reached out to the internet
would be flaky by construction and untestable in CI sandboxes that block
egress.

Certificate generation
-----------------------
`make_cert()` builds a minimal self-signed leaf. Parameters exist for the
specific things individual tests need to control (validity window, key type,
signature hash) rather than being added speculatively — a fixture nobody uses
just teaches the reader that some path is exercised when it isn't.
"""

from __future__ import annotations

import asyncio
import datetime
import ssl
from pathlib import Path
from typing import AsyncIterator, Callable, Coroutine, List, Optional, Tuple, Union

import pytest
import pytest_asyncio
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import NameOID

# Narrower than cryptography's PrivateKeyTypes (which also admits DH/X25519/
# X448, none of which CertificateBuilder.sign() accepts) — exactly the three
# key kinds make_key() below can produce.
LeafPrivateKey = Union[
    ec.EllipticCurvePrivateKey, rsa.RSAPrivateKey, ed25519.Ed25519PrivateKey
]

# ---------------------------------------------------------------------------
# Certificate generation
# ---------------------------------------------------------------------------


def make_key(kind: str = "ec") -> LeafPrivateKey:
    if kind == "ec":
        return ec.generate_private_key(ec.SECP256R1())
    if kind == "rsa2048":
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)
    if kind == "ed25519":
        return ed25519.Ed25519PrivateKey.generate()
    raise ValueError(f"unknown key kind {kind!r}")


def make_cert(
    tmp_path: Path,
    *,
    common_name: str = "localhost",
    sans: Optional[List[x509.GeneralName]] = None,
    issuer_cn: Optional[str] = None,
    key: Optional[LeafPrivateKey] = None,
    validity_days: int = 90,
    age_days: int = 1,
    filename_hint: str = "cert",
) -> Tuple[Path, Path, x509.Certificate]:
    """Build and write a minimal self-signed leaf.

    `sans` defaults to a single DNSName for `common_name` — most tests want a
    certificate that validates against "localhost" without thinking about
    subjectAltName separately. Pass an explicit list (including `[]`) to test
    the no-SAN or custom-SAN paths.

    Returns (cert_path, key_path, the parsed `x509.Certificate`) so a test can
    assert against the object directly instead of re-parsing the file it just
    wrote.
    """
    key = key or make_key("ec")
    if sans is None:
        sans = [x509.DNSName(common_name)]

    now = datetime.datetime.now(datetime.timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn or common_name)]
    )

    # not_after is anchored to not_before, not to wall-clock "now" — a
    # certificate's validity window is a span starting at issuance, not a
    # window ending validity_days from whenever the test happens to run.
    # Anchoring to "now" instead only looks correct for small age_days (the
    # error is masked by the default age_days=1), and produces a wrong,
    # test-dependent lifetime for anything backdated further, which is
    # exactly what the CA/B lifetime-schedule tests need to do.
    not_before = now - datetime.timedelta(days=age_days)
    not_after = not_before + datetime.timedelta(days=validity_days)

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )
    if sans:
        builder = builder.add_extension(x509.SubjectAlternativeName(sans), False)

    sign_hash = None if isinstance(key, ed25519.Ed25519PrivateKey) else hashes.SHA256()
    certificate = builder.sign(key, sign_hash)

    cert_path = tmp_path / f"{filename_hint}.pem"
    key_path = tmp_path / f"{filename_hint}.key"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path, certificate


@pytest.fixture
def cert_factory(tmp_path: Path) -> Callable[..., Tuple[Path, Path, x509.Certificate]]:
    """Callable fixture so a test can build several certs with distinct names."""
    counter = {"n": 0}

    def _make(**kwargs: object) -> Tuple[Path, Path, x509.Certificate]:
        counter["n"] += 1
        kwargs.setdefault("filename_hint", f"cert{counter['n']}")
        return make_cert(tmp_path, **kwargs)  # type: ignore[arg-type]

    return _make


# ---------------------------------------------------------------------------
# Local TLS server
# ---------------------------------------------------------------------------


class TLSServerHandle:
    """A running local TLS server plus the port it's bound to."""

    def __init__(self, server: asyncio.base_events.Server, port: int) -> None:
        self.server = server
        self.port = port

    def close(self) -> None:
        self.server.close()


async def _start_tls_server(
    cert_path: Path,
    key_path: Path,
    *,
    max_version: Optional[ssl.TLSVersion] = None,
    min_version: Optional[ssl.TLSVersion] = None,
    hold_open_s: float = 0.2,
) -> TLSServerHandle:
    """Start a bare TLS server: accept, hold briefly, close.

    `hold_open_s` gives the client side enough time to complete a resumption
    probe's second handshake before the server tears the listener down when
    the test's `async with` block exits, without holding every test open
    unnecessarily long.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(cert_path), str(key_path))
    if max_version is not None:
        context.maximum_version = max_version
    if min_version is not None:
        context.minimum_version = min_version

    async def handle(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            await asyncio.sleep(hold_open_s)
            writer.close()
        except (ConnectionError, OSError):
            pass

    server = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=context)
    sockets = server.sockets
    assert sockets is not None
    port = sockets[0].getsockname()[1]
    return TLSServerHandle(server, port)


@pytest_asyncio.fixture
async def tls_server(
    cert_factory: Callable[..., Tuple[Path, Path, x509.Certificate]],
) -> AsyncIterator[Callable[..., Coroutine[None, None, TLSServerHandle]]]:
    """Factory fixture: start a TLS server, get back its port.

    Yields an async callable rather than a single server, so a test that needs
    several independent servers (a healthy one, an expiring one, a TLS-1.2-only
    one) can start each with its own certificate. All started servers are
    closed on teardown regardless of how the test exits.

    IMPORTANT — every caller must connect with `pinned_ip="127.0.0.1"`
    (via `ProbeConfig` or `SSLTarget`), never bare hostname resolution.
    This server binds to 127.0.0.1 only, but `getaddrinfo("localhost", ...)`
    order is OS-dependent: it returns IPv4 first on this project's Linux CI
    and sandbox, but returns the IPv6 loopback (::1) first on macOS — where
    nothing is listening, producing a confusing TCP_REFUSED that has nothing
    to do with the certificate or handshake logic actually under test. Pinning
    bypasses getaddrinfo entirely rather than depending on its return order,
    while leaving the "localhost" string in place for SNI and hostname
    matching, which is what the certificates in these fixtures are issued for.
    """
    handles: List[TLSServerHandle] = []

    async def _start(
        *,
        cert: Optional[Tuple[Path, Path, x509.Certificate]] = None,
        max_version: Optional[ssl.TLSVersion] = None,
        min_version: Optional[ssl.TLSVersion] = None,
        **cert_kwargs: object,
    ) -> TLSServerHandle:
        if cert is None:
            cert = cert_factory(**cert_kwargs)
        cert_path, key_path, _ = cert
        handle = await _start_tls_server(
            cert_path, key_path, max_version=max_version, min_version=min_version
        )
        handles.append(handle)
        return handle

    yield _start

    for handle in handles:
        handle.close()


# ---------------------------------------------------------------------------
# Local STARTTLS servers (SMTP only — sufficient to exercise the negotiator
# dispatch and the byte-accounting path; the other four protocols are covered
# at the unit level directly against their negotiator functions, which does
# not need a live socket).
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def smtp_server(
    cert_factory: Callable[..., Tuple[Path, Path, x509.Certificate]],
) -> AsyncIterator[Callable[[bool], Coroutine[None, None, int]]]:
    """Factory: start a plaintext SMTP server, optionally advertising STARTTLS.

    Returns the bound port. `advertise=False` produces a server that completes
    the EHLO exchange but never mentions STARTTLS — the case the
    `STARTTLS_UNSUPPORTED` status exists for.

    Same pinning requirement as `tls_server` above: this binds to 127.0.0.1
    only, so every caller must connect with `pinned_ip="127.0.0.1"` rather
    than relying on "localhost" resolving to it — see that fixture's
    docstring for why.
    """
    servers: List[asyncio.base_events.Server] = []
    cert_path, key_path, _ = cert_factory(filename_hint="smtp")
    tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls_context.load_cert_chain(str(cert_path), str(key_path))

    async def _start(advertise: bool = True) -> int:
        async def handle(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            try:
                writer.write(b"220 localhost ESMTP net-benchmark-test\r\n")
                await writer.drain()
                await reader.readline()  # EHLO
                writer.write(b"250-localhost\r\n")
                if advertise:
                    writer.write(b"250-STARTTLS\r\n")
                writer.write(b"250 8BITMIME\r\n")
                await writer.drain()

                line = await reader.readline()
                if advertise and line.strip().upper() == b"STARTTLS":
                    writer.write(b"220 ready to start TLS\r\n")
                    await writer.drain()
                    # Complete a real TLS handshake over the same socket so the
                    # client side sees a genuine upgrade rather than a
                    # protocol error immediately after.
                    if hasattr(writer, "start_tls"):
                        await writer.start_tls(tls_context)
                        await asyncio.sleep(0.15)
                writer.close()
            except (ConnectionError, OSError, asyncio.IncompleteReadError):
                pass

        server = await asyncio.start_server(handle, "127.0.0.1", 0)
        servers.append(server)
        sockets = server.sockets
        assert sockets is not None
        return int(sockets[0].getsockname()[1])

    yield _start

    for server in servers:
        server.close()


@pytest_asyncio.fixture
async def imap_server(
    cert_factory: Callable[..., Tuple[Path, Path, x509.Certificate]],
) -> AsyncIterator[Callable[[bool], Coroutine[None, None, int]]]:
    """Factory: start a plaintext IMAP server, optionally advertising
    STARTTLS in its CAPABILITY response. Same shape and same 127.0.0.1-only
    pinning requirement as `smtp_server` above."""
    servers: List[asyncio.base_events.Server] = []
    cert_path, key_path, _ = cert_factory(filename_hint="imap")
    tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls_context.load_cert_chain(str(cert_path), str(key_path))

    async def _start(advertise: bool = True) -> int:
        async def handle(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            try:
                writer.write(b"* OK IMAP4rev1 Service Ready\r\n")
                await writer.drain()
                await reader.readline()  # A001 CAPABILITY
                if advertise:
                    writer.write(b"* CAPABILITY IMAP4rev1 STARTTLS\r\n")
                else:
                    writer.write(b"* CAPABILITY IMAP4rev1\r\n")
                writer.write(b"A001 OK CAPABILITY completed\r\n")
                await writer.drain()

                if advertise:
                    line = await reader.readline()  # A002 STARTTLS
                    if line.strip().upper() == b"A002 STARTTLS":
                        writer.write(b"A002 OK Begin TLS negotiation now\r\n")
                        await writer.drain()
                        if hasattr(writer, "start_tls"):
                            await writer.start_tls(tls_context)
                            await asyncio.sleep(0.15)
                writer.close()
            except (ConnectionError, OSError, asyncio.IncompleteReadError):
                pass

        server = await asyncio.start_server(handle, "127.0.0.1", 0)
        servers.append(server)
        sockets = server.sockets
        assert sockets is not None
        return int(sockets[0].getsockname()[1])

    yield _start

    for server in servers:
        server.close()


@pytest_asyncio.fixture
async def pop3_server(
    cert_factory: Callable[..., Tuple[Path, Path, x509.Certificate]],
) -> AsyncIterator[Callable[[bool], Coroutine[None, None, int]]]:
    """Factory: start a plaintext POP3 server, optionally accepting STLS.
    Same shape and pinning requirement as `smtp_server` above."""
    servers: List[asyncio.base_events.Server] = []
    cert_path, key_path, _ = cert_factory(filename_hint="pop3")
    tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls_context.load_cert_chain(str(cert_path), str(key_path))

    async def _start(advertise: bool = True) -> int:
        async def handle(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            try:
                writer.write(b"+OK POP3 server ready\r\n")
                await writer.drain()
                await reader.readline()  # STLS
                if advertise:
                    writer.write(b"+OK Begin TLS negotiation\r\n")
                    await writer.drain()
                    if hasattr(writer, "start_tls"):
                        await writer.start_tls(tls_context)
                        await asyncio.sleep(0.15)
                else:
                    # POP3 answers -ERR for an unimplemented command --
                    # matches _negotiate_pop3's own comment on why an
                    # unsupported STLS and a refused one look identical.
                    writer.write(b"-ERR Unknown command\r\n")
                    await writer.drain()
                writer.close()
            except (ConnectionError, OSError, asyncio.IncompleteReadError):
                pass

        server = await asyncio.start_server(handle, "127.0.0.1", 0)
        servers.append(server)
        sockets = server.sockets
        assert sockets is not None
        return int(sockets[0].getsockname()[1])

    yield _start

    for server in servers:
        server.close()


@pytest_asyncio.fixture
async def ftp_server(
    cert_factory: Callable[..., Tuple[Path, Path, x509.Certificate]],
) -> AsyncIterator[Callable[[bool], Coroutine[None, None, int]]]:
    """Factory: start a plaintext FTP server, optionally accepting AUTH TLS.
    Same shape and pinning requirement as `smtp_server` above."""
    servers: List[asyncio.base_events.Server] = []
    cert_path, key_path, _ = cert_factory(filename_hint="ftp")
    tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls_context.load_cert_chain(str(cert_path), str(key_path))

    async def _start(advertise: bool = True) -> int:
        async def handle(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            try:
                writer.write(b"220 FTP server ready\r\n")
                await writer.drain()
                await reader.readline()  # AUTH TLS
                if advertise:
                    writer.write(b"234 AUTH TLS successful\r\n")
                    await writer.drain()
                    if hasattr(writer, "start_tls"):
                        await writer.start_tls(tls_context)
                        await asyncio.sleep(0.15)
                else:
                    writer.write(b"502 Command not implemented\r\n")
                    await writer.drain()
                writer.close()
            except (ConnectionError, OSError, asyncio.IncompleteReadError):
                pass

        server = await asyncio.start_server(handle, "127.0.0.1", 0)
        servers.append(server)
        sockets = server.sockets
        assert sockets is not None
        return int(sockets[0].getsockname()[1])

    yield _start

    for server in servers:
        server.close()


@pytest_asyncio.fixture
async def ldap_server(
    cert_factory: Callable[..., Tuple[Path, Path, x509.Certificate]],
) -> AsyncIterator[Callable[[bool], Coroutine[None, None, int]]]:
    """Factory: start a plaintext LDAP server answering one StartTLS
    ExtendedRequest with a BER-encoded ExtendedResponse. Same shape and
    pinning requirement as `smtp_server` above.

    Unlike the other three, LDAP StartTLS is not line-oriented -- the
    client sends one BER-encoded request and reads one raw response, so
    this fixture does not attempt to parse the incoming bytes, only to
    answer with a well-formed response. The response bytes are the exact
    ones proven correct in TestLDAPStartTLS.test_parse_success /
    test_parse_protocol_error against parse_ldap_result_code() directly --
    reused here so the live-socket test and the unit test agree on what
    "a real LDAP StartTLS response" looks like.
    """
    servers: List[asyncio.base_events.Server] = []
    cert_path, key_path, _ = cert_factory(filename_hint="ldap")
    tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls_context.load_cert_chain(str(cert_path), str(key_path))

    # SEQUENCE { messageID=1, ExtendedResponse { resultCode=<0 or 2>,
    #            matchedDN="", errorMessage="" } }
    _SUCCESS = bytes.fromhex("300c02010178070a0100040004" + "00")
    _PROTOCOL_ERROR = bytes.fromhex("300c02010178070a0102040004" + "00")

    async def _start(advertise: bool = True) -> int:
        async def handle(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            try:
                await reader.read(4096)  # the StartTLS ExtendedRequest
                if advertise:
                    writer.write(_SUCCESS)
                    await writer.drain()
                    if hasattr(writer, "start_tls"):
                        await writer.start_tls(tls_context)
                        await asyncio.sleep(0.15)
                else:
                    writer.write(_PROTOCOL_ERROR)
                    await writer.drain()
                writer.close()
            except (ConnectionError, OSError, asyncio.IncompleteReadError):
                pass

        server = await asyncio.start_server(handle, "127.0.0.1", 0)
        servers.append(server)
        sockets = server.sockets
        assert sockets is not None
        return int(sockets[0].getsockname()[1])

    yield _start

    for server in servers:
        server.close()


@pytest.fixture
def unused_tcp_port() -> int:
    """A port nothing is listening on, for the connection-refused paths."""
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    # The socket is closed on exit from the `with` block, so the port is free
    # again but was never accepting connections — refused, not filtered.
    return int(port)
