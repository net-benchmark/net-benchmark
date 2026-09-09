"""CLI tests for `net-benchmark ssl check`.

Mirrors `http_bench.tests.test_cli`'s convention exactly: `CliRunner` plus a
monkeypatched `SSLCheckEngine.check_targets` returning canned `SSLResult`
objects instantly, rather than a live handshake per test. The handshake and
transport logic already has thorough, real-network coverage in
`test_handshake.py` and `test_core.py`; what's untested here is CLI-level
concern -- flag parsing, validation error paths, export dispatch, exit
codes -- which does not need a socket to verify.
"""

from __future__ import annotations

import csv
import datetime
import json
from pathlib import Path
from typing import Any, List

import pytest
from click.testing import CliRunner

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
from net_benchmark.ssl_check.cli import ssl as ssl_group
from net_benchmark.ssl_check.core import SSLResult, SSLTarget
from net_benchmark.ssl_check.handshake import (
    HandshakeStatus,
    StartTLSProtocol,
    TLSVersion,
)

UTC = datetime.timezone.utc


def make_cli_result(
    host: str = "example.test",
    port: int = 443,
    *,
    measured: bool = True,
    tls_version: TLSVersion = TLSVersion.TLSV1_3,
    days_remaining: int = 90,
    starttls: StartTLSProtocol = StartTLSProtocol.NONE,
) -> SSLResult:
    """A complete, realistic SSLResult for CLI-level tests -- real enough
    that SSLAnalyzer, every exporter, and evaluate_policy all run against it
    exactly as they would against a live result, since none of that layer
    is mocked here."""
    now = datetime.datetime.now(UTC)
    lifetime = LifetimeAudit(
        not_before=now - datetime.timedelta(days=90 - days_remaining),
        not_after=now + datetime.timedelta(days=days_remaining),
        lifetime_days=90,
        days_remaining=days_remaining,
        verdict=LifetimeVerdict.COMPLIANT,
    )
    certificate = CertificateInfo(
        subject_dn=f"CN={host}",
        issuer_dn="CN=Test CA",
        serial_number="01",
        version="v3",
        issuer_cn="Test CA",
        san_dns=[host],
        public_key=PublicKeyInfo(key_type=KeyType.ECDSA, key_size=256),
        fingerprints=Fingerprints(
            cert_sha256="a" * 64,
            cert_sha1="b" * 40,
            spki_sha256="c" * 64,
            spki_sha256_b64="d" * 44,
        ),
        lifetime=lifetime,
        revocation=RevocationEndpoints(ocsp_urls=["http://ocsp.test/"]),
    )
    status = HandshakeStatus.OK if measured else HandshakeStatus.TCP_REFUSED
    return SSLResult(
        host=host,
        port=port,
        starttls=starttls,
        status=status,
        start_time=0.0,
        end_time=0.1,
        measured=measured,
        handshake_ms=12.3 if measured else None,
        tls_version=tls_version if measured else TLSVersion.UNKNOWN,
        cipher_name="TLS_AES_256_GCM_SHA384" if measured else None,
        cipher_id=0x1302 if measured else None,
        hostname_match=HostnameMatch.MATCH if measured else HostnameMatch.NOT_CHECKED,
        certificate=certificate if measured else None,
    )


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def mock_check_targets(monkeypatch: pytest.MonkeyPatch) -> List[SSLTarget]:
    """Patches SSLCheckEngine.check_targets to return one healthy result per
    target requested, instantly. Returns the (mutable) list of SSLTarget
    objects the engine was actually called with, so a test can assert on
    what the CLI's option parsing constructed -- e.g. that --starttls
    actually reached the target list."""
    captured: List[SSLTarget] = []

    async def _mock_check_targets(self: Any, targets: Any) -> List[SSLResult]:
        captured.extend(targets)
        return [make_cli_result(host=t.host, port=t.port) for t in targets]

    monkeypatch.setattr(
        "net_benchmark.ssl_check.core.SSLCheckEngine.check_targets",
        _mock_check_targets,
    )
    return captured


@pytest.fixture
def mock_check_targets_failing(monkeypatch: pytest.MonkeyPatch) -> None:
    """A variant returning a result that will fail cert_expiry_days>30."""

    async def _mock_check_targets(self: Any, targets: Any) -> List[SSLResult]:
        return [
            make_cli_result(host=t.host, port=t.port, days_remaining=5) for t in targets
        ]

    monkeypatch.setattr(
        "net_benchmark.ssl_check.core.SSLCheckEngine.check_targets",
        _mock_check_targets,
    )


class TestBasicInvocation:
    def test_single_target_exits_zero(
        self, runner: CliRunner, mock_check_targets: List[SSLTarget], tmp_path: Path
    ) -> None:
        result = runner.invoke(
            ssl_group,
            ["check", "--targets", "example.test", "--output", str(tmp_path)],
        )
        assert result.exit_code == 0, result.output
        assert len(mock_check_targets) == 1
        assert mock_check_targets[0].host == "example.test"

    def test_multiple_comma_separated_targets(
        self, runner: CliRunner, mock_check_targets: List[SSLTarget], tmp_path: Path
    ) -> None:
        result = runner.invoke(
            ssl_group,
            [
                "check",
                "--targets",
                "a.test,b.test,c.test",
                "--output",
                str(tmp_path),
                "--quiet",
            ],
        )
        assert result.exit_code == 0, result.output
        assert {t.host for t in mock_check_targets} == {"a.test", "b.test", "c.test"}

    def test_use_defaults(
        self, runner: CliRunner, mock_check_targets: List[SSLTarget], tmp_path: Path
    ) -> None:
        result = runner.invoke(
            ssl_group,
            ["check", "--use-defaults", "--output", str(tmp_path), "--quiet"],
        )
        assert result.exit_code == 0, result.output
        assert len(mock_check_targets) > 0

    def test_no_targets_and_no_use_defaults(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        """Raises click.UsageError (exit 2) -- a config with neither
        --targets nor --use-defaults is a usage error, the same class as
        every other malformed-input case in this command, not a silent
        no-op with exit 0. See TestOptionValidationErrors's module note on
        why this changed from the original soft-fail behavior."""
        result = runner.invoke(ssl_group, ["check", "--output", str(tmp_path)])
        assert result.exit_code == 2
        assert "Provide --targets" in result.output

    def test_nonexistent_targets_file(self, runner: CliRunner, tmp_path: Path) -> None:
        result = runner.invoke(
            ssl_group,
            ["check", "--targets", str(tmp_path / "does-not-exist.txt")],
        )
        assert result.exit_code == 2
        assert "not found" in result.output.lower()

    def test_invalid_formats_value(
        self, runner: CliRunner, mock_check_targets: List[SSLTarget], tmp_path: Path
    ) -> None:
        result = runner.invoke(
            ssl_group,
            [
                "check",
                "--targets",
                "example.test",
                "--formats",
                "yaml",
                "--output",
                str(tmp_path),
            ],
        )
        assert result.exit_code == 2
        assert "invalid format" in result.output.lower()

    def test_all_ports_scans_the_common_port_set(
        self, runner: CliRunner, mock_check_targets: List[SSLTarget], tmp_path: Path
    ) -> None:
        from net_benchmark.ssl_check.core import DEFAULT_SCAN_PORTS

        result = runner.invoke(
            ssl_group,
            [
                "check",
                "--targets",
                "example.test",
                "--all-ports",
                "--output",
                str(tmp_path),
                "--quiet",
            ],
        )
        assert result.exit_code == 0, result.output
        assert {t.port for t in mock_check_targets} == set(DEFAULT_SCAN_PORTS)

    def test_explicit_ports_overrides_all_ports(
        self, runner: CliRunner, mock_check_targets: List[SSLTarget], tmp_path: Path
    ) -> None:
        """An explicit --ports is a more specific instruction than the
        broad --all-ports default and must win, per _parse_ports's own
        docstring."""
        result = runner.invoke(
            ssl_group,
            [
                "check",
                "--targets",
                "example.test",
                "--all-ports",
                "--ports",
                "8443",
                "--output",
                str(tmp_path),
                "--quiet",
            ],
        )
        assert result.exit_code == 0, result.output
        assert {t.port for t in mock_check_targets} == {8443}

    def test_empty_ports_value_falls_back_to_443(
        self, runner: CliRunner, mock_check_targets: List[SSLTarget], tmp_path: Path
    ) -> None:
        """--ports "," parses to no usable entries, not a crash."""
        result = runner.invoke(
            ssl_group,
            [
                "check",
                "--targets",
                "example.test",
                "--ports",
                ",,",
                "--output",
                str(tmp_path),
                "--quiet",
            ],
        )
        assert result.exit_code == 0, result.output
        assert {t.port for t in mock_check_targets} == {443}


class TestOptionValidationErrors:
    """Every _parse_* helper that raises click.UsageError -- exit code 2,
    caught before or during the run, and re-raised rather than swallowed."""

    def test_invalid_starttls(self, runner: CliRunner) -> None:
        result = runner.invoke(
            ssl_group, ["check", "--targets", "x", "--starttls", "bogus"]
        )
        assert result.exit_code == 2
        assert "invalid --starttls" in result.output

    def test_invalid_min_tls_version(self, runner: CliRunner) -> None:
        result = runner.invoke(
            ssl_group, ["check", "--targets", "x", "--min-tls-version", "bogus"]
        )
        assert result.exit_code == 2
        assert "invalid --min-tls-version" in result.output

    def test_invalid_as_of(self, runner: CliRunner) -> None:
        result = runner.invoke(
            ssl_group, ["check", "--targets", "x", "--as-of", "not-a-date"]
        )
        assert result.exit_code == 2
        assert "invalid --as-of" in result.output

    def test_invalid_port_in_ports_flag(self, runner: CliRunner) -> None:
        result = runner.invoke(ssl_group, ["check", "--targets", "x", "--ports", "abc"])
        assert result.exit_code == 2
        assert "invalid port" in result.output

    def test_unknown_threshold_metric(
        self, runner: CliRunner, mock_check_targets: List[SSLTarget], tmp_path: Path
    ) -> None:
        result = runner.invoke(
            ssl_group,
            [
                "check",
                "--targets",
                "example.test",
                "--threshold",
                "not_a_real_metric>5",
                "--output",
                str(tmp_path),
            ],
        )
        assert result.exit_code == 2
        assert "unknown metric" in result.output

    def test_unknown_threshold_metric_suggests_close_match(
        self, runner: CliRunner, mock_check_targets: List[SSLTarget], tmp_path: Path
    ) -> None:
        """A near-miss typo of a real metric name should trigger the
        "Did you mean" suggestion path, not just the bare error."""
        result = runner.invoke(
            ssl_group,
            [
                "check",
                "--targets",
                "example.test",
                "--threshold",
                "cert_expiry_day>5",  # missing the trailing 's'
                "--output",
                str(tmp_path),
            ],
        )
        assert result.exit_code == 2
        assert "Did you mean" in result.output

    def test_malformed_threshold_expression_syntax(
        self, runner: CliRunner, mock_check_targets: List[SSLTarget], tmp_path: Path
    ) -> None:
        """Distinct from an unknown metric: this is a --threshold value
        parse_threshold() itself cannot parse at all, e.g. no operator."""
        result = runner.invoke(
            ssl_group,
            [
                "check",
                "--targets",
                "example.test",
                "--threshold",
                "this is not an expression",
                "--output",
                str(tmp_path),
            ],
        )
        assert result.exit_code == 2

    def test_malformed_resolve_flag(self, runner: CliRunner) -> None:
        """Was a soft-fail (exit 0) inherited from sharing a try block with
        target-file loading, inconsistent with every other option parser in
        this command. Fixed: the target-parsing try block now re-raises
        FileNotFoundError/ValueError as click.UsageError, so this is exit 2
        like --ports/--min-tls-version/--as-of/--starttls/--threshold."""
        result = runner.invoke(
            ssl_group, ["check", "--targets", "x", "--resolve", "not-enough-parts"]
        )
        assert result.exit_code == 2
        assert "invalid --resolve" in result.output


class TestStarttlsOverride:
    def test_starttls_override_applied_to_every_target(
        self, runner: CliRunner, mock_check_targets: List[SSLTarget], tmp_path: Path
    ) -> None:
        result = runner.invoke(
            ssl_group,
            [
                "check",
                "--targets",
                "mail.test:2525",
                "--starttls",
                "smtp",
                "--output",
                str(tmp_path),
                "--quiet",
            ],
        )
        assert result.exit_code == 0, result.output
        assert mock_check_targets[0].starttls is StartTLSProtocol.SMTP

    def test_auto_leaves_port_based_guess(
        self, runner: CliRunner, mock_check_targets: List[SSLTarget], tmp_path: Path
    ) -> None:
        result = runner.invoke(
            ssl_group,
            [
                "check",
                "--targets",
                "mail.test:587",
                "--output",
                str(tmp_path),
                "--quiet",
            ],
        )
        assert result.exit_code == 0, result.output
        assert mock_check_targets[0].starttls is StartTLSProtocol.SMTP


class TestResolveOverride:
    def test_resolve_pins_target_ip(
        self, runner: CliRunner, mock_check_targets: List[SSLTarget], tmp_path: Path
    ) -> None:
        result = runner.invoke(
            ssl_group,
            [
                "check",
                "--targets",
                "example.test:443",
                "--resolve",
                "example.test:443:203.0.113.5",
                "--output",
                str(tmp_path),
                "--quiet",
            ],
        )
        assert result.exit_code == 0, result.output
        assert mock_check_targets[0].pinned_ip == "203.0.113.5"


class TestThresholdGating:
    def test_passing_threshold_exits_zero(
        self, runner: CliRunner, mock_check_targets: List[SSLTarget], tmp_path: Path
    ) -> None:
        result = runner.invoke(
            ssl_group,
            [
                "check",
                "--targets",
                "example.test",
                "--threshold",
                "cert_expiry_days>30",
                "--output",
                str(tmp_path),
                "--quiet",
            ],
        )
        assert result.exit_code == 0, result.output

    def test_passing_threshold_prints_report_when_not_quiet(
        self, runner: CliRunner, mock_check_targets: List[SSLTarget], tmp_path: Path
    ) -> None:
        result = runner.invoke(
            ssl_group,
            [
                "check",
                "--targets",
                "example.test",
                "--threshold",
                "cert_expiry_days>30",
                "--output",
                str(tmp_path),
            ],
        )
        assert result.exit_code == 0, result.output
        assert "PASS" in result.output
        assert "Thresholds" in result.output

    def test_failing_threshold_prints_report_when_not_quiet(
        self, runner: CliRunner, mock_check_targets_failing: None, tmp_path: Path
    ) -> None:
        result = runner.invoke(
            ssl_group,
            [
                "check",
                "--targets",
                "example.test",
                "--threshold",
                "cert_expiry_days>30",
                "--output",
                str(tmp_path),
            ],
        )
        assert result.exit_code == 1
        assert "FAIL" in result.output

    def test_failing_threshold_exits_one_and_writes_csv(
        self,
        runner: CliRunner,
        mock_check_targets_failing: None,
        tmp_path: Path,
    ) -> None:
        result = runner.invoke(
            ssl_group,
            [
                "check",
                "--targets",
                "example.test",
                "--threshold",
                "cert_expiry_days>30",
                "--output",
                str(tmp_path),
                "--quiet",
            ],
        )
        assert result.exit_code == 1
        threshold_files = list(tmp_path.glob("*_thresholds.csv"))
        assert len(threshold_files) == 1
        with open(threshold_files[0]) as handle:
            rows = list(csv.DictReader(handle))
        assert rows[0]["passed"] == "False"

    def test_exports_still_written_on_threshold_failure(
        self,
        runner: CliRunner,
        mock_check_targets_failing: None,
        tmp_path: Path,
    ) -> None:
        """The whole point of evaluating exports before the threshold gate:
        a failing CI run still leaves its artifacts for inspection."""
        result = runner.invoke(
            ssl_group,
            [
                "check",
                "--targets",
                "example.test",
                "--formats",
                "csv",
                "--threshold",
                "cert_expiry_days>30",
                "--output",
                str(tmp_path),
                "--quiet",
            ],
        )
        assert result.exit_code == 1
        assert list(tmp_path.glob("*_raw.csv")), "raw export missing despite failure"
        assert list(
            tmp_path.glob("*_summary.csv")
        ), "summary export missing despite failure"


class TestExportFormats:
    def test_json_flag_writes_json(
        self, runner: CliRunner, mock_check_targets: List[SSLTarget], tmp_path: Path
    ) -> None:
        result = runner.invoke(
            ssl_group,
            [
                "check",
                "--targets",
                "example.test",
                "--formats",
                "csv",
                "--json",
                "--output",
                str(tmp_path),
                "--quiet",
            ],
        )
        assert result.exit_code == 0, result.output
        json_files = list(tmp_path.glob("*.json"))
        assert len(json_files) == 1
        payload = json.loads(json_files[0].read_text())
        assert payload["schema_version"] == 1

    def test_excel_with_charts(
        self, runner: CliRunner, mock_check_targets: List[SSLTarget], tmp_path: Path
    ) -> None:
        result = runner.invoke(
            ssl_group,
            [
                "check",
                "--targets",
                "example.test",
                "--formats",
                "excel",
                "--include-charts",
                "--output",
                str(tmp_path),
                "--quiet",
            ],
        )
        assert result.exit_code == 0, result.output
        assert list(tmp_path.glob("*.xlsx"))

    def test_pdf_export(
        self, runner: CliRunner, mock_check_targets: List[SSLTarget], tmp_path: Path
    ) -> None:
        result = runner.invoke(
            ssl_group,
            [
                "check",
                "--targets",
                "example.test",
                "--formats",
                "pdf",
                "--output",
                str(tmp_path),
                "--quiet",
            ],
        )
        assert result.exit_code == 0, result.output
        assert list(tmp_path.glob("*.pdf"))


class TestQuietMode:
    def test_quiet_suppresses_progress_and_summary(
        self, runner: CliRunner, mock_check_targets: List[SSLTarget], tmp_path: Path
    ) -> None:
        result = runner.invoke(
            ssl_group,
            [
                "check",
                "--targets",
                "example.test",
                "--output",
                str(tmp_path),
                "--quiet",
            ],
        )
        assert result.exit_code == 0
        assert "Configuration:" not in result.output

    def test_not_quiet_shows_configuration_and_summary(
        self, runner: CliRunner, mock_check_targets: List[SSLTarget], tmp_path: Path
    ) -> None:
        result = runner.invoke(
            ssl_group,
            ["check", "--targets", "example.test", "--output", str(tmp_path)],
        )
        assert result.exit_code == 0
        assert "Configuration:" in result.output


class TestAsOf:
    def test_as_of_shown_in_configuration_output(
        self, runner: CliRunner, mock_check_targets: List[SSLTarget], tmp_path: Path
    ) -> None:
        result = runner.invoke(
            ssl_group,
            [
                "check",
                "--targets",
                "example.test",
                "--as-of",
                "2026-09-01",
                "--output",
                str(tmp_path),
            ],
        )
        assert result.exit_code == 0, result.output
        assert "2026-09-01" in result.output


class TestExceptionHandling:
    def test_keyboard_interrupt_handled_gracefully(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        async def _raise_keyboard_interrupt(self: Any, targets: Any) -> Any:
            raise KeyboardInterrupt()

        monkeypatch.setattr(
            "net_benchmark.ssl_check.core.SSLCheckEngine.check_targets",
            _raise_keyboard_interrupt,
        )
        result = runner.invoke(
            ssl_group,
            ["check", "--targets", "example.test", "--output", str(tmp_path)],
        )
        assert result.exit_code == 0
        assert "interrupted" in result.output.lower()

    def test_generic_exception_reraised(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        async def _raise_value_error(self: Any, targets: Any) -> Any:
            raise ValueError("something went genuinely wrong")

        monkeypatch.setattr(
            "net_benchmark.ssl_check.core.SSLCheckEngine.check_targets",
            _raise_value_error,
        )
        result = runner.invoke(
            ssl_group,
            ["check", "--targets", "example.test", "--output", str(tmp_path)],
        )
        assert result.exit_code != 0
        assert result.exception is not None
