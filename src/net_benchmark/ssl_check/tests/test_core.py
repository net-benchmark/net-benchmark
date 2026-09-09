"""Tests for `net_benchmark.ssl_check.core`.

Target parsing is tested against strings alone (no network); the engine tests
run against the local `tls_server` fixture. `TestEvaluatePolicyPureUnit`
tests `evaluate_policy()` as the pure function it is, against directly
constructed `SSLResult`/`CertificateInfo` objects — no handshake, no
network, no dependency on what the local OpenSSL build will or won't
negotiate (see `test_deprecated_tls_rejected_by_default` above, which can
only run at all if the local OpenSSL still allows TLS 1.0). Policy logic and
transport capability are independent concerns and are tested independently.
"""

from __future__ import annotations

import datetime
import ssl
from pathlib import Path
from typing import Callable, Coroutine, List, Optional, Tuple

import pytest

from net_benchmark.ssl_check.certificate import (
    CertificateInfo,
    Fingerprints,
    HostnameMatch,
    KeyType,
    LifetimeAudit,
    LifetimeVerdict,
    PublicKeyInfo,
    RevocationEndpoints,
)
from net_benchmark.ssl_check.core import (
    PolicyConfig,
    SSLCheckEngine,
    SSLResult,
    SSLTarget,
    TargetManager,
    detect_forward_secrecy,
    evaluate_policy,
    parse_resolve_flags,
)
from net_benchmark.ssl_check.handshake import (
    HandshakeStatus,
    StartTLSProtocol,
    TLSVersion,
)

from .conftest import TLSServerHandle

TLSServerFactory = Callable[..., Coroutine[None, None, TLSServerHandle]]

UTC = datetime.timezone.utc


def make_lifetime(
    *,
    lifetime_days: int = 90,
    days_remaining: int = 60,
    expired: bool = False,
    not_yet_valid: bool = False,
    short_lived: bool = False,
) -> LifetimeAudit:
    now = datetime.datetime.now(UTC)
    return LifetimeAudit(
        not_before=now - datetime.timedelta(days=lifetime_days - days_remaining),
        not_after=now + datetime.timedelta(days=days_remaining),
        lifetime_days=lifetime_days,
        days_remaining=days_remaining,
        verdict=LifetimeVerdict.COMPLIANT,
        expired=expired,
        not_yet_valid=not_yet_valid,
        short_lived=short_lived,
    )


def make_certificate(
    *,
    lifetime: Optional[LifetimeAudit] = None,
    key_weak: bool = False,
    signature_weak: bool = False,
    issuer_dn: str = "CN=Test CA",
    issuer_cn: str = "Test CA",
    has_revocation_source: bool = True,
    fingerprint_sha256: str = "a" * 64,
    fingerprint_spki_sha256: str = "b" * 64,
    fingerprint_spki_b64: str = "c" * 44,
) -> CertificateInfo:
    """A minimal but complete CertificateInfo, every branch evaluate_policy
    can check set to an explicit, deliberate value rather than a default
    that happens not to trip a failure."""
    return CertificateInfo(
        subject_dn="CN=target.test",
        issuer_dn=issuer_dn,
        serial_number="01",
        version="v3",
        issuer_cn=issuer_cn,
        public_key=PublicKeyInfo(
            key_type=KeyType.ECDSA,
            key_size=256,
            weak=key_weak,
            weak_reason="key too small" if key_weak else None,
        ),
        signature_weak=signature_weak,
        signature_weak_reason="SHA-1 is broken" if signature_weak else None,
        fingerprints=Fingerprints(
            cert_sha256=fingerprint_sha256,
            cert_sha1="d" * 40,
            spki_sha256=fingerprint_spki_sha256,
            spki_sha256_b64=fingerprint_spki_b64,
        ),
        lifetime=lifetime if lifetime is not None else make_lifetime(),
        revocation=RevocationEndpoints(
            ocsp_urls=["http://ocsp.test/"] if has_revocation_source else [],
        ),
    )


_UNSET = object()  # sentinel: distinguishes "certificate not passed" (use the
# default fake cert) from "certificate=None passed explicitly" (test the
# no-certificate branch). A plain `certificate: Optional[...] = None` default
# cannot make this distinction -- an earlier version of this helper used
# exactly that and silently replaced an explicit `certificate=None` with a
# real certificate, which defeated the two tests that specifically exist to
# check the no-certificate branch. Caught because those tests failed for the
# wrong reason (asserting True instead of False) rather than the right one.


def make_result(
    *,
    measured: bool = True,
    tls_version: TLSVersion = TLSVersion.TLSV1_3,
    tls_version_deprecated: bool = False,
    forward_secrecy: Optional[bool] = True,
    hostname_match: HostnameMatch = HostnameMatch.MATCH,
    certificate: object = _UNSET,
    peer_offered_no_certificate: bool = False,
) -> SSLResult:
    resolved_certificate: Optional[CertificateInfo]
    if certificate is _UNSET:
        resolved_certificate = make_certificate()
    else:
        resolved_certificate = certificate  # type: ignore[assignment]
    return SSLResult(
        host="target.test",
        port=443,
        starttls=StartTLSProtocol.NONE,
        status=HandshakeStatus.OK if measured else HandshakeStatus.TCP_REFUSED,
        start_time=0.0,
        end_time=0.0,
        measured=measured,
        tls_version=tls_version,
        tls_version_deprecated=tls_version_deprecated,
        forward_secrecy=forward_secrecy,
        hostname_match=hostname_match,
        certificate=resolved_certificate,
        peer_offered_no_certificate=peer_offered_no_certificate,
    )


class TestTargetManagerParsing:
    """Item 3 (--resolve) and the host x port matrix construction."""

    def test_host_port_matrix_from_ports_flag(self) -> None:
        manager = TargetManager.parse_targets_input("example.com", ports=[443, 8443])
        pairs = [(t.host, t.port) for t in manager.targets]
        assert pairs == [("example.com", 443), ("example.com", 8443)]

    def test_explicit_port_not_expanded_by_ports_flag(self) -> None:
        """A target written as host:port means exactly that port; --ports
        must not multiply it across the rest of the scan."""
        manager = TargetManager.parse_targets_input(
            "mail.example.com:587", ports=[443, 8443]
        )
        assert [t.port for t in manager.targets] == [587]

    def test_mixed_list_with_explicit_and_default_ports(self) -> None:
        manager = TargetManager.parse_targets_input(
            "example.com,mail.example.com:587", ports=[443]
        )
        pairs = {(t.host, t.port) for t in manager.targets}
        assert pairs == {("example.com", 443), ("mail.example.com", 587)}

    def test_starttls_mode_assigned_from_port(self) -> None:
        manager = TargetManager.parse_targets_input("mail.example.com:587", ports=[443])
        assert manager.targets[0].starttls is StartTLSProtocol.SMTP

    def test_comma_separated_list_with_a_url_in_it(self) -> None:
        """http_bench.core.TargetManager has a defect here: its file-vs-inline
        heuristic tests only for '/' anywhere in the string, so
        'example.com,https://a.io/x' is misread as a filename because of the
        slash inside the SECOND entry. This TargetManager checks for a comma
        first specifically to avoid inheriting that bug."""
        manager = TargetManager.parse_targets_input(
            "example.com,https://a.io/path", ports=[443]
        )
        hosts = {t.host for t in manager.targets}
        assert hosts == {"example.com", "a.io"}

    def test_url_scheme_strips_to_authority(self) -> None:
        manager = TargetManager.parse_targets_input(
            "https://example.com/some/path", ports=[443]
        )
        assert manager.targets[0].host == "example.com"

    def test_ipv6_bracket_literal_with_port(self) -> None:
        host, port = TargetManager._split_host_port("[2001:db8::1]:8443")
        assert host == "2001:db8::1"
        assert port == 8443

    def test_bare_ipv6_literal_no_port(self) -> None:
        host, port = TargetManager._split_host_port("2001:db8::1")
        assert host == "2001:db8::1"
        assert port is None

    def test_dedup_across_entries(self) -> None:
        manager = TargetManager.parse_targets_input("a.com,a.com,a.com", ports=[443])
        assert len(manager.targets) == 1

    def test_empty_input_raises(self) -> None:
        with pytest.raises(ValueError):
            TargetManager.parse_targets_input("", ports=[443])

    def test_missing_file_raises(self) -> None:
        with pytest.raises(FileNotFoundError):
            TargetManager.parse_targets_input("/no/such/targets.txt", ports=[443])

    def test_load_from_file(self, tmp_path: Path) -> None:
        targets_file = tmp_path / "targets.txt"
        targets_file.write_text("a.com\n# comment\nb.com\n\n")
        manager = TargetManager.parse_targets_input(str(targets_file), ports=[443])
        hosts = {t.host for t in manager.targets}
        assert hosts == {"a.com", "b.com"}


class TestResolveFlagParsing:
    """Item 3 — --resolve host:port:ip."""

    def test_host_port_and_bare_host_keys(self) -> None:
        resolve_map = parse_resolve_flags(["example.com:443:192.0.2.9"])
        assert resolve_map["example.com:443"] == "192.0.2.9"
        assert resolve_map["example.com"] == "192.0.2.9"

    def test_ipv6_target_address(self) -> None:
        resolve_map = parse_resolve_flags(["a.com:443:2001:db8::5"])
        assert resolve_map["a.com:443"] == "2001:db8::5"

    def test_pin_applied_to_target(self) -> None:
        resolve_map = parse_resolve_flags(["example.com:443:192.0.2.9"])
        manager = TargetManager.parse_targets_input(
            "example.com", ports=[443], resolve_map=resolve_map
        )
        assert manager.targets[0].pinned_ip == "192.0.2.9"

    def test_malformed_value_raises(self) -> None:
        with pytest.raises(ValueError):
            parse_resolve_flags(["not-enough-parts"])


class TestForwardSecrecyDetection:
    """Item 35 — TLS 1.3 suite names carry no key-exchange component."""

    def test_tls13_always_forward_secret(self) -> None:
        """The suite name has no ECDHE/DHE substring to find under TLS 1.3;
        the version alone must decide it, or every TLS 1.3 server would be
        misreported as lacking forward secrecy."""
        assert (
            detect_forward_secrecy(TLSVersion.TLSV1_3, "TLS_AES_256_GCM_SHA384") is True
        )

    def test_tls12_ecdhe_suite(self) -> None:
        assert (
            detect_forward_secrecy(TLSVersion.TLSV1_2, "ECDHE-RSA-AES128-GCM-SHA256")
            is True
        )

    def test_tls12_static_rsa_suite(self) -> None:
        assert detect_forward_secrecy(TLSVersion.TLSV1_2, "AES128-SHA") is False

    def test_unknown_version_returns_none(self) -> None:
        """An inference from missing data is a guess, not a measurement."""
        assert detect_forward_secrecy(TLSVersion.UNKNOWN, None) is None


class TestEngineSingleTarget:
    async def test_successful_check(self, tls_server: TLSServerFactory) -> None:
        handle = await tls_server(validity_days=150)
        engine = SSLCheckEngine(
            handshake_samples=1,
            warmup_handshakes=0,
            connect_timeout=3,
            handshake_timeout=6,
        )
        result = await engine.check_target(
            SSLTarget("localhost", handle.port, pinned_ip="127.0.0.1")
        )
        assert result.status is HandshakeStatus.OK
        assert result.measured is True
        assert result.certificate is not None
        assert result.hostname_match.value == "match"

    async def test_unreachable_target_not_measured(self, unused_tcp_port: int) -> None:
        engine = SSLCheckEngine(connect_timeout=2)
        result = await engine.check_target(SSLTarget("127.0.0.1", unused_tcp_port))
        assert result.status is HandshakeStatus.TCP_REFUSED
        assert result.measured is False
        assert result.handshake_ms is None, "no timing fabricated"

    async def test_timing_samples_collected(self, tls_server: TLSServerFactory) -> None:
        handle = await tls_server()
        engine = SSLCheckEngine(
            handshake_samples=3,
            min_samples=5,
            warmup_handshakes=1,
            connect_timeout=3,
            handshake_timeout=6,
        )
        result = await engine.check_target(
            SSLTarget("localhost", handle.port, pinned_ip="127.0.0.1")
        )
        assert len(result.handshake_samples_ms) == 3
        assert result.handshake_mean_ms is not None

    async def test_min_samples_refuses_percentiles(
        self, tls_server: TLSServerFactory
    ) -> None:
        """Item 57 — too few samples must withhold p95/p99, not report them
        from a handful of handshakes."""
        handle = await tls_server()
        engine = SSLCheckEngine(
            handshake_samples=2,
            min_samples=5,
            warmup_handshakes=0,
            connect_timeout=3,
            handshake_timeout=6,
        )
        result = await engine.check_target(
            SSLTarget("localhost", handle.port, pinned_ip="127.0.0.1")
        )
        assert result.handshake_samples_refused is True
        assert result.handshake_p95_ms is None

    async def test_enough_samples_reports_percentiles(
        self, tls_server: TLSServerFactory
    ) -> None:
        handle = await tls_server()
        engine = SSLCheckEngine(
            handshake_samples=6,
            min_samples=5,
            warmup_handshakes=0,
            connect_timeout=3,
            handshake_timeout=6,
        )
        result = await engine.check_target(
            SSLTarget("localhost", handle.port, pinned_ip="127.0.0.1")
        )
        assert result.handshake_samples_refused is False
        assert result.handshake_p95_ms is not None


class TestResumptionProbe:
    """Items 4, 47 — the probe owns both handshakes and drains for the
    NewSessionTicket, or TLS 1.3 servers are misreported as never resuming."""

    async def test_tls13_resumption_detected(
        self, tls_server: TLSServerFactory
    ) -> None:
        handle = await tls_server()
        engine = SSLCheckEngine(
            handshake_samples=1,
            warmup_handshakes=0,
            connect_timeout=3,
            handshake_timeout=6,
            check_resumption=True,
            resumption_drain_s=0.4,
        )
        result = await engine.check_target(
            SSLTarget("localhost", handle.port, pinned_ip="127.0.0.1")
        )
        assert result.tls_version is TLSVersion.TLSV1_3
        assert result.resumption_supported is True

    async def test_timing_samples_are_never_resumed(
        self, tls_server: TLSServerFactory
    ) -> None:
        """The timing samples run with no post-handshake drain and must
        report full, unresumed handshakes — that is the entire point of
        item 38's measurement."""
        handle = await tls_server()
        engine = SSLCheckEngine(
            handshake_samples=3,
            min_samples=5,
            warmup_handshakes=0,
            connect_timeout=3,
            handshake_timeout=6,
        )
        result = await engine.check_target(
            SSLTarget("localhost", handle.port, pinned_ip="127.0.0.1")
        )
        assert result.session_reused is False

    async def test_resumption_not_probed_when_disabled(
        self, tls_server: TLSServerFactory
    ) -> None:
        handle = await tls_server()
        engine = SSLCheckEngine(
            handshake_samples=1, warmup_handshakes=0, connect_timeout=3
        )
        result = await engine.check_target(
            SSLTarget("localhost", handle.port, pinned_ip="127.0.0.1")
        )
        assert result.resumption_supported is None


class TestBackoff:
    """Item 2 — backoff must fire only on timeout-class failures, never on a
    plain refusal, or a multi-port scan (most ports closed) crawls."""

    async def test_refused_connection_does_not_trigger_backoff(
        self, unused_tcp_port: int
    ) -> None:
        engine = SSLCheckEngine(connect_timeout=2, backoff_on_timeout=True)
        await engine.check_target(SSLTarget("127.0.0.1", unused_tcp_port))
        assert engine.get_failed_hosts().get("127.0.0.1") is None

    async def test_timeout_triggers_backoff(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import asyncio

        async def _hang(*args: object, **kwargs: object) -> None:
            await asyncio.sleep(60)

        monkeypatch.setattr(asyncio, "open_connection", _hang)
        engine = SSLCheckEngine(connect_timeout=0.1, backoff_on_timeout=True)
        await engine.check_target(SSLTarget("127.0.0.1", 443))
        assert engine.get_failed_hosts().get("127.0.0.1") == 1


class TestBatchFanOut:
    async def test_all_targets_return_a_result(
        self, tls_server: TLSServerFactory, unused_tcp_port: int
    ) -> None:
        handle = await tls_server()
        engine = SSLCheckEngine(
            max_concurrent=4,
            handshake_samples=1,
            warmup_handshakes=0,
            connect_timeout=2,
            handshake_timeout=4,
        )
        targets = [
            SSLTarget("localhost", handle.port, pinned_ip="127.0.0.1") for _ in range(4)
        ] + [SSLTarget("127.0.0.1", unused_tcp_port)]
        results = await engine.check_targets(targets)
        assert len(results) == 5

    async def test_progress_callback_invoked_for_every_target(
        self, tls_server: TLSServerFactory
    ) -> None:
        handle = await tls_server()
        engine = SSLCheckEngine(
            handshake_samples=1, warmup_handshakes=0, connect_timeout=3
        )
        ticks: List[Tuple[int, int]] = []
        engine.set_progress_callback(lambda done, total: ticks.append((done, total)))
        targets = [
            SSLTarget("localhost", handle.port, pinned_ip="127.0.0.1") for _ in range(3)
        ]
        await engine.check_targets(targets)
        assert len(ticks) == 3
        assert ticks[-1] == (3, 3)

    async def test_raising_progress_callback_does_not_fail_the_check(
        self, tls_server: TLSServerFactory
    ) -> None:
        """A broken consumer callback must not take the check down with it —
        counted in progress_errors instead."""
        handle = await tls_server()
        engine = SSLCheckEngine(
            handshake_samples=1, warmup_handshakes=0, connect_timeout=3
        )

        def boom(done: int, total: int) -> None:
            raise RuntimeError("consumer broke")

        engine.set_progress_callback(boom)
        result = await engine.check_target(
            SSLTarget("localhost", handle.port, pinned_ip="127.0.0.1")
        )
        assert result.status is HandshakeStatus.OK
        assert engine.progress_errors == 1


class TestPolicyEvaluation:
    """The `measured`/`compliant` gate. Everything here is about what
    `compliant` becomes, not about the handshake."""

    async def test_healthy_target_is_compliant(
        self, tls_server: TLSServerFactory
    ) -> None:
        handle = await tls_server(validity_days=150)
        engine = SSLCheckEngine(
            handshake_samples=1, warmup_handshakes=0, connect_timeout=3
        )
        result = await engine.check_target(
            SSLTarget("localhost", handle.port, pinned_ip="127.0.0.1")
        )
        policy = PolicyConfig(min_days_remaining=30, min_tls_version=TLSVersion.TLSV1_2)
        evaluate_policy(result, policy)
        assert result.compliant is True
        assert result.policy_failures == []

    async def test_expiring_soon_fails_min_days_remaining(
        self, tls_server: TLSServerFactory
    ) -> None:
        handle = await tls_server(validity_days=90, age_days=87)
        engine = SSLCheckEngine(
            handshake_samples=1, warmup_handshakes=0, connect_timeout=3
        )
        result = await engine.check_target(
            SSLTarget("localhost", handle.port, pinned_ip="127.0.0.1")
        )
        evaluate_policy(result, PolicyConfig(min_days_remaining=30))
        assert result.compliant is False
        assert any("remaining" in f for f in result.policy_failures)

    async def test_unreachable_target_stays_unevaluated(
        self, unused_tcp_port: int
    ) -> None:
        """An unreachable target has not FAILED policy — it was never
        assessed. Reporting it as non-compliant would bucket a down host with
        an expired certificate."""
        engine = SSLCheckEngine(connect_timeout=2)
        result = await engine.check_target(SSLTarget("127.0.0.1", unused_tcp_port))
        evaluate_policy(result, PolicyConfig(min_days_remaining=30))
        assert result.compliant is None
        assert result.policy_failures == []

    async def test_short_lived_certificate_exempt_from_revocation_requirement(
        self, tls_server: TLSServerFactory
    ) -> None:
        """Item 30 — a modern 6-day certificate has no OCSP/CRL by design
        under the CA/B short-lived exemption; requiring one would flag a
        correctly issued certificate as a finding."""
        handle = await tls_server(validity_days=6)
        engine = SSLCheckEngine(
            handshake_samples=1, warmup_handshakes=0, connect_timeout=3
        )
        result = await engine.check_target(
            SSLTarget("localhost", handle.port, pinned_ip="127.0.0.1")
        )
        evaluate_policy(result, PolicyConfig(require_revocation_source=True))
        assert not any("revocation" in f for f in result.policy_failures)

    async def test_deprecated_tls_rejected_by_default(
        self, tls_server: TLSServerFactory
    ) -> None:
        handle = await tls_server(
            min_version=(
                ssl.TLSVersion.SSLv3
                if hasattr(ssl.TLSVersion, "SSLv3")
                else ssl.TLSVersion.TLSv1
            ),
            max_version=ssl.TLSVersion.TLSv1,
        )
        engine = SSLCheckEngine(
            handshake_samples=1,
            warmup_handshakes=0,
            connect_timeout=3,
            min_version=ssl.TLSVersion.TLSv1,
            max_version=ssl.TLSVersion.TLSv1,
        )
        result = await engine.check_target(
            SSLTarget("localhost", handle.port, pinned_ip="127.0.0.1")
        )
        if result.status is not HandshakeStatus.OK:
            pytest.skip("local OpenSSL build refuses TLS 1.0 entirely")
        evaluate_policy(result, PolicyConfig(reject_deprecated_tls=True))
        assert result.compliant is False
        assert any("deprecated" in f for f in result.policy_failures)


class TestEvaluatePolicyPureUnit:
    """Every `PolicyConfig` branch, exercised directly — no handshake, no
    OpenSSL version dependency, no network. See the module docstring."""

    def test_unmeasured_target_untouched(self) -> None:
        """An unreachable target must not even be evaluated — compliant
        stays None and no failures are invented for a target that was never
        assessed."""
        result = make_result(measured=False)
        evaluate_policy(result, PolicyConfig(min_days_remaining=9999))
        assert result.compliant is None
        assert result.policy_failures == []

    def test_deprecated_tls_flagged(self) -> None:
        result = make_result(
            tls_version=TLSVersion.TLSV1_0, tls_version_deprecated=True
        )
        evaluate_policy(result, PolicyConfig(reject_deprecated_tls=True))
        assert result.compliant is False
        assert any("deprecated" in f for f in result.policy_failures)

    def test_deprecated_tls_not_flagged_when_disabled(self) -> None:
        result = make_result(
            tls_version=TLSVersion.TLSV1_0, tls_version_deprecated=True
        )
        evaluate_policy(result, PolicyConfig(reject_deprecated_tls=False))
        assert not any("deprecated" in f for f in result.policy_failures)

    def test_min_tls_version_floor_breached(self) -> None:
        result = make_result(tls_version=TLSVersion.TLSV1_2)
        evaluate_policy(result, PolicyConfig(min_tls_version=TLSVersion.TLSV1_3))
        assert result.compliant is False
        assert any("below floor" in f for f in result.policy_failures)

    def test_min_tls_version_floor_met(self) -> None:
        result = make_result(tls_version=TLSVersion.TLSV1_3)
        evaluate_policy(result, PolicyConfig(min_tls_version=TLSVersion.TLSV1_2))
        assert not any("below floor" in f for f in result.policy_failures)

    def test_forward_secrecy_required_and_absent(self) -> None:
        result = make_result(forward_secrecy=False)
        evaluate_policy(result, PolicyConfig(require_forward_secrecy=True))
        assert result.compliant is False
        assert any("forward secrecy" in f for f in result.policy_failures)

    def test_forward_secrecy_not_required(self) -> None:
        """Default policy — forward secrecy absence is not flagged unless
        explicitly required."""
        result = make_result(forward_secrecy=False)
        evaluate_policy(result, PolicyConfig())
        assert not any("forward secrecy" in f for f in result.policy_failures)

    def test_hostname_mismatch_flagged_by_default(self) -> None:
        result = make_result(hostname_match=HostnameMatch.MISMATCH)
        evaluate_policy(result, PolicyConfig())
        assert result.compliant is False
        assert any("mismatch" in f for f in result.policy_failures)

    def test_hostname_mismatch_allowed_when_configured(self) -> None:
        result = make_result(hostname_match=HostnameMatch.MISMATCH)
        evaluate_policy(result, PolicyConfig(require_hostname_match=False))
        assert not any("mismatch" in f for f in result.policy_failures)

    def test_no_certificate_offered_flagged(self) -> None:
        """certificate is None entirely — the anonymous/PSK-suite path,
        distinct from a certificate that failed some other check."""
        result = make_result(certificate=None, peer_offered_no_certificate=True)
        evaluate_policy(result, PolicyConfig())
        assert result.compliant is False
        assert any("no certificate" in f for f in result.policy_failures)

    def test_no_certificate_short_circuits_certificate_only_checks(self) -> None:
        """With no certificate at all, key/signature/lifetime/issuer/
        fingerprint checks must not run — there is nothing for them to
        check, and the function must not raise on the None."""
        result = make_result(certificate=None, peer_offered_no_certificate=False)
        evaluate_policy(
            result,
            PolicyConfig(
                min_days_remaining=30,
                expected_issuer="whatever",
                reject_weak_key=True,
            ),
        )
        assert result.compliant is True
        assert result.policy_failures == []

    def test_weak_key_flagged(self) -> None:
        result = make_result(certificate=make_certificate(key_weak=True))
        evaluate_policy(result, PolicyConfig(reject_weak_key=True))
        assert result.compliant is False
        assert any("key too small" in f for f in result.policy_failures)

    def test_weak_key_allowed_when_configured(self) -> None:
        result = make_result(certificate=make_certificate(key_weak=True))
        evaluate_policy(result, PolicyConfig(reject_weak_key=False))
        assert not any("key too small" in f for f in result.policy_failures)

    def test_weak_signature_flagged(self) -> None:
        result = make_result(certificate=make_certificate(signature_weak=True))
        evaluate_policy(result, PolicyConfig(reject_weak_signature=True))
        assert result.compliant is False
        assert any("SHA-1 is broken" in f for f in result.policy_failures)

    def test_not_yet_valid_flagged(self) -> None:
        result = make_result(
            certificate=make_certificate(lifetime=make_lifetime(not_yet_valid=True))
        )
        evaluate_policy(result, PolicyConfig())
        assert result.compliant is False
        assert any("not yet valid" in f for f in result.policy_failures)

    def test_expired_flagged(self) -> None:
        result = make_result(
            certificate=make_certificate(lifetime=make_lifetime(expired=True))
        )
        evaluate_policy(result, PolicyConfig())
        assert result.compliant is False
        assert any("expired" in f for f in result.policy_failures)

    def test_max_lifetime_days_breached(self) -> None:
        result = make_result(
            certificate=make_certificate(
                lifetime=make_lifetime(lifetime_days=400, days_remaining=200)
            )
        )
        evaluate_policy(result, PolicyConfig(max_cert_lifetime_days=398))
        assert result.compliant is False
        assert any("exceeds" in f for f in result.policy_failures)

    def test_max_lifetime_days_within_bound(self) -> None:
        result = make_result(
            certificate=make_certificate(
                lifetime=make_lifetime(lifetime_days=90, days_remaining=60)
            )
        )
        evaluate_policy(result, PolicyConfig(max_cert_lifetime_days=398))
        assert not any("exceeds" in f for f in result.policy_failures)

    def test_expected_issuer_mismatch(self) -> None:
        result = make_result(
            certificate=make_certificate(
                issuer_dn="CN=Untrusted CA", issuer_cn="Untrusted CA"
            )
        )
        evaluate_policy(result, PolicyConfig(expected_issuer="DigiCert"))
        assert result.compliant is False
        assert any("does not match expected" in f for f in result.policy_failures)

    def test_expected_issuer_match_is_substring_and_case_insensitive(self) -> None:
        result = make_result(
            certificate=make_certificate(
                issuer_dn="CN=DigiCert Global Root", issuer_cn="DigiCert Global Root"
            )
        )
        evaluate_policy(result, PolicyConfig(expected_issuer="digicert"))
        assert not any("does not match expected" in f for f in result.policy_failures)

    def test_expected_fingerprint_match_cert_sha256(self) -> None:
        cert = make_certificate(fingerprint_sha256="a" * 64)
        result = make_result(certificate=cert)
        evaluate_policy(result, PolicyConfig(expected_fingerprint="a" * 64))
        assert not any("fingerprint" in f for f in result.policy_failures)

    def test_expected_fingerprint_match_spki_b64(self) -> None:
        """The pin can be given in any of the three fingerprint forms the
        certificate carries — hex cert, hex SPKI, or base64 SPKI."""
        cert = make_certificate(fingerprint_spki_b64="XYZ123")
        result = make_result(certificate=cert)
        evaluate_policy(result, PolicyConfig(expected_fingerprint="XYZ123"))
        assert not any("fingerprint" in f for f in result.policy_failures)

    def test_expected_fingerprint_mismatch(self) -> None:
        cert = make_certificate(fingerprint_sha256="a" * 64)
        result = make_result(certificate=cert)
        evaluate_policy(result, PolicyConfig(expected_fingerprint="0" * 64))
        assert result.compliant is False
        assert any("does not match expected value" in f for f in result.policy_failures)

    def test_revocation_source_required_and_missing(self) -> None:
        """The actual failing case — distinct from the short-lived
        exemption below, which must NOT fail this same check."""
        cert = make_certificate(
            has_revocation_source=False,
            lifetime=make_lifetime(lifetime_days=90, short_lived=False),
        )
        result = make_result(certificate=cert)
        evaluate_policy(result, PolicyConfig(require_revocation_source=True))
        assert result.compliant is False
        assert any("revocation source" in f for f in result.policy_failures)

    def test_revocation_source_short_lived_exempt(self) -> None:
        cert = make_certificate(
            has_revocation_source=False,
            lifetime=make_lifetime(lifetime_days=6, short_lived=True),
        )
        result = make_result(certificate=cert)
        evaluate_policy(result, PolicyConfig(require_revocation_source=True))
        assert not any("revocation source" in f for f in result.policy_failures)

    def test_fully_compliant_result_has_no_failures(self) -> None:
        """A clean result against every check enabled must produce zero
        failures — the inverse of every test above, and the case that
        proves the checks aren't accidentally always-on."""
        result = make_result()
        evaluate_policy(
            result,
            PolicyConfig(
                min_days_remaining=1,
                min_tls_version=TLSVersion.TLSV1_2,
                require_forward_secrecy=True,
                reject_weak_key=True,
                reject_weak_signature=True,
                reject_deprecated_tls=True,
            ),
        )
        assert result.compliant is True
        assert result.policy_failures == []
