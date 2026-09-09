"""SSL/TLS checking CLI.

Mirrors `http_bench.cli` and `dns_benchmark.cli`: a `click.Group`, shared
`--targets`/`--use-defaults` target selection, the `--threshold` CI-gate
pattern with typo detection against a known metric set, and exports evaluated
before the threshold gate so a failing run still leaves its artifacts behind.

Deliberately one command, `ssl check`. The roadmap's 0.6.1 items (version and
cipher enumeration, chain-of-trust reporting, revocation, baseline
monitoring) each want a different default shape of output — a `versions`
table is not a `check` row — and are better served by their own subcommands
when they land than by overloading this one with flags for features that
don't exist yet.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import replace as dataclass_replace
from datetime import datetime, timezone
from difflib import get_close_matches
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

import click

from net_benchmark.http_bench.analysis import Threshold, ThresholdResult
from net_benchmark.ssl_check.analysis import (
    SSLAnalyzer,
    parse_threshold,
    ssl_metric_names,
    thresholds_passed,
)
from net_benchmark.ssl_check.core import (
    DEFAULT_SCAN_PORTS,
    PolicyConfig,
    SSLCheckEngine,
    SSLResult,
    SSLTarget,
    TargetManager,
    evaluate_policy,
    parse_resolve_flags,
)
from net_benchmark.ssl_check.exporters import (
    SSLCSVExporter,
    SSLExcelExporter,
    SSLExportBundle,
    SSLPDFExporter,
    build_provenance,
)
from net_benchmark.ssl_check.handshake import StartTLSProtocol, TLSVersion
from net_benchmark.utils.helpers import create_progress_bar
from net_benchmark.utils.messages import error, info, success, summary_box, warning

# ── SSL command group ───────────────────────────────────────────────────────


@click.group(name="ssl")
def ssl() -> None:
    """Check SSL/TLS endpoints — handshake, certificate, and policy audit."""
    pass


# ── shared parsing helpers ──────────────────────────────────────────────────


def _parse_thresholds(specs: Sequence[str]) -> List[Threshold]:
    """Parse --threshold values, failing loudly on a bad expression or an
    unknown metric name. Mirrors http_bench.cli._parse_thresholds exactly —
    same reasoning applies: a typo should cost a second at parse time, not a
    full scan.
    """
    known = ssl_metric_names()
    out: List[Threshold] = []
    for spec in specs:
        try:
            threshold = parse_threshold(spec)
        except ValueError as e:
            raise click.UsageError(str(e))
        if threshold.metric not in known:
            suggestions = get_close_matches(threshold.metric, sorted(known), n=3)
            hint = f" Did you mean: {', '.join(suggestions)}?" if suggestions else ""
            raise click.UsageError(
                f"unknown metric {threshold.metric!r} in --threshold "
                f"{spec!r}.{hint}"
            )
        out.append(threshold)
    return out


def _report_thresholds(label: str, results: List[ThresholdResult], quiet: bool) -> bool:
    """Print threshold outcomes and return whether they all passed. Mirrors
    http_bench.cli._report_thresholds."""
    if not results:
        return True
    if not quiet:
        click.echo(info(f"Thresholds — {label}"))
        for r in results:
            mark = "PASS" if r.passed else "FAIL"
            actual = "n/a" if r.actual is None else f"{r.actual:.2f}"
            line = f"  [{mark}] {r.threshold}  actual={actual}"
            if r.error:
                line += f"  ({r.error})"
            click.echo(success(line) if r.passed else error(line))
    return thresholds_passed(results)


def _parse_ports(raw: Optional[str], all_ports: bool) -> List[int]:
    """--ports and --all-ports (item 41).

    --all-ports scans DEFAULT_SCAN_PORTS; an explicit --ports overrides it if
    both are given, since an explicit list is a more specific instruction than
    a broad default and should win rather than be silently ignored.
    """
    if raw:
        ports: List[int] = []
        for part in raw.split(","):
            part = part.strip()
            if not part:
                continue
            try:
                ports.append(int(part))
            except ValueError:
                raise click.UsageError(f"invalid port {part!r} in --ports")
        return ports or [443]
    if all_ports:
        return list(DEFAULT_SCAN_PORTS)
    return [443]


def _parse_tls_version(raw: Optional[str], flag_name: str) -> Optional[TLSVersion]:
    """--min-tls-version. Values match the TLSVersion enum's own spelling
    (TLSv1, TLSv1.1, TLSv1.2, TLSv1.3) so a value copied from an export's
    tls_version field is always a valid input here too."""
    if raw is None:
        return None
    for member in TLSVersion:
        if member.value.lower() == raw.lower():
            return member
    valid = ", ".join(m.value for m in TLSVersion if m is not TLSVersion.UNKNOWN)
    raise click.UsageError(f"invalid {flag_name} {raw!r}. Use one of: {valid}")


def _parse_as_of(raw: Optional[str]) -> Optional[datetime]:
    """--as-of (item 55). Accepts an ISO 8601 date or datetime.

    A bare date ('2026-03-15') is accepted and treated as midnight UTC that
    day — most --as-of uses are "what does this look like on renewal deadline
    day", where a date is the natural unit to reach for, and Python's own
    fromisoformat() rejects a bare date under a datetime type without this.
    A naive datetime is assumed UTC rather than raising, for the same
    "the natural thing to type should work" reason.
    """
    if raw is None:
        return None
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        raise click.UsageError(
            f"invalid --as-of {raw!r}. Use ISO 8601, e.g. 2026-03-15 or "
            "2026-03-15T00:00:00Z"
        )
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _parse_starttls_override(raw: Optional[str]) -> Optional[StartTLSProtocol]:
    """--starttls. None means "leave the per-port default from
    starttls_for_port() alone" — 'auto' is the CLI spelling of that, since an
    unset flag and an explicitly-requested default should read the same way
    to a user checking --help.

    Exists because the port-based default (item 41) only covers well-known
    ports. A mail server running SMTP STARTTLS on a non-587/25 port —
    common enough in enterprise deployments — has no other way to be checked
    correctly: without this, it defaults to implicit TLS, the handshake is
    sent nothing but ciphertext where SMTP expects a plaintext greeting, and
    the result is a confusing TLS_ERROR that names no cause a reader could
    act on.
    """
    if raw is None or raw.lower() == "auto":
        return None
    try:
        return StartTLSProtocol(raw.lower())
    except ValueError:
        valid = ", ".join(
            p.value for p in StartTLSProtocol if p is not StartTLSProtocol.NONE
        )
        raise click.UsageError(
            f"invalid --starttls {raw!r}. Use one of: auto, none, {valid}"
        )


# ── check ────────────────────────────────────────────────────────────────


@ssl.command()
@click.option(
    "--targets",
    "-t",
    default=None,
    help="Comma-separated hosts (host, host:port, or URL) or path to a file, "
    "one target per line.",
)
@click.option("--use-defaults", is_flag=True, help="Use built-in default targets.")
@click.option(
    "--ports",
    default=None,
    help="Comma-separated ports applied to targets with no explicit port. "
    "Default: 443.",
)
@click.option(
    "--all-ports",
    is_flag=True,
    help=f"Scan the common TLS/STARTTLS port set "
    f"({', '.join(str(p) for p in DEFAULT_SCAN_PORTS)}) for targets with no "
    "explicit port. Overridden by an explicit --ports.",
)
@click.option(
    "--resolve",
    "resolve_specs",
    multiple=True,
    default=None,
    help="Pin a target to an IP without DNS lookup: 'host:port:ip' "
    "(repeatable). IPv6 addresses are supported.",
)
@click.option(
    "--starttls",
    "starttls_override",
    default=None,
    help="Force the STARTTLS protocol for every target instead of guessing "
    "from the port: auto (default), none, smtp, imap, pop3, ldap, ftp. "
    "Needed for a mail/directory server running STARTTLS on a non-standard "
    "port.",
)
# ── transport ──
@click.option(
    "--connect-timeout",
    default=10.0,
    show_default=True,
    help="TCP connect timeout (s).",
)
@click.option(
    "--handshake-timeout",
    default=15.0,
    show_default=True,
    help="TLS handshake timeout (s).",
)
@click.option(
    "--starttls-timeout",
    default=15.0,
    show_default=True,
    help="Plaintext STARTTLS negotiation timeout (s).",
)
@click.option(
    "--max-concurrent", default=20, show_default=True, help="Maximum concurrent checks."
)
@click.option(
    "--retries",
    default=1,
    show_default=True,
    help="Retries for timeout-class failures.",
)
@click.option(
    "--per-host-serial",
    is_flag=True,
    help="Check all ports of one host before moving to the next, instead of "
    "fanning out across ports too. Halves throughput; use this for scanning "
    "someone else's infrastructure.",
)
@click.option(
    "--no-backoff",
    is_flag=True,
    help="Disable the delay before re-probing a host that has been timing out.",
)
# ── sampling (items 4, 38, 47, 57) ──
@click.option(
    "--handshake-samples",
    default=1,
    show_default=True,
    help="Handshakes per target for the timing distribution. Percentiles are "
    "withheld below --min-samples.",
)
@click.option(
    "--warmup-handshakes",
    default=1,
    show_default=True,
    help="Discarded handshakes before timing samples begin.",
)
@click.option(
    "--min-samples",
    default=5,
    show_default=True,
    help="Minimum handshake samples before percentiles are reported, rather "
    "than withheld as unreliable.",
)
@click.option(
    "--check-resumption",
    is_flag=True,
    help="Run a dedicated pair of handshakes to test TLS session resumption "
    "support, separate from the timing samples.",
)
# ── TLS negotiation ──
@click.option(
    "--alpn",
    default=None,
    help="Comma-separated ALPN protocols to offer, e.g. 'h2,http/1.1'.",
)
@click.option(
    "--ciphers",
    default=None,
    help="OpenSSL cipher string restricting the TLS 1.2-and-below suites "
    "offered. Does not affect TLS 1.3, whose suites cannot be selected "
    "individually through this mechanism.",
)
@click.option(
    "--sni-hostname",
    default=None,
    help="Override the SNI value sent (and the name checked against the "
    "certificate). Default: the target's own hostname.",
)
@click.option("--no-sni", is_flag=True, help="Send no SNI value at all.")
# ── policy (item 50) ──
@click.option(
    "--min-days-remaining",
    type=int,
    default=None,
    help="Flag a certificate with fewer days remaining than this.",
)
@click.option(
    "--max-lifetime-days",
    type=int,
    default=None,
    help="Flag a certificate whose total validity period exceeds this.",
)
@click.option(
    "--min-tls-version",
    default=None,
    help="Flag a negotiated version below this floor, e.g. 'TLSv1.2'.",
)
@click.option(
    "--expected-issuer",
    default=None,
    help="Flag a certificate whose issuer does not contain this substring.",
)
@click.option(
    "--expected-fingerprint",
    default=None,
    help="Flag a certificate that does not match this SHA-256 fingerprint "
    "(certificate or SPKI, hex or base64).",
)
@click.option(
    "--allow-hostname-mismatch",
    is_flag=True,
    help="Do not flag a certificate that does not cover the target hostname.",
)
@click.option(
    "--require-forward-secrecy",
    is_flag=True,
    help="Flag a negotiated cipher suite without forward secrecy.",
)
@click.option(
    "--allow-weak-key", is_flag=True, help="Do not flag an under-strength public key."
)
@click.option(
    "--allow-weak-signature",
    is_flag=True,
    help="Do not flag a broken certificate signature hash (MD5/SHA-1).",
)
@click.option(
    "--allow-deprecated-tls",
    is_flag=True,
    help="Do not flag a deprecated negotiated version (TLS 1.0/1.1, SSLv3).",
)
@click.option(
    "--require-revocation-source",
    is_flag=True,
    help="Flag a certificate with no OCSP or CRL URL. Certificates within "
    "the CA/B short-lived exemption are never flagged by this.",
)
# ── item 55 ──
@click.option(
    "--as-of",
    default=None,
    help="Evaluate every certificate as of this date/time (ISO 8601) instead "
    "of now, e.g. to check what breaks at a future renewal deadline. Fixed "
    "once for the whole run.",
)
# ── output ──
@click.option(
    "--output",
    "-o",
    default="./benchmark_results",
    show_default=True,
    help="Output directory for results.",
)
@click.option(
    "--formats",
    "-f",
    default="csv,excel,pdf",
    show_default=True,
    help="Output formats (csv, excel, pdf).",
)
@click.option("--json", "json_output", is_flag=True, help="Export results to JSON.")
@click.option(
    "--include-charts", is_flag=True, help="Include charts in the Excel export."
)
@click.option(
    "--threshold",
    "thresholds",
    multiple=True,
    help="Pass/fail criterion, e.g. 'cert_expiry_days>30' or "
    "'success_rate>=95'. Repeatable. Any failure exits with code 1.",
)
@click.option("--quiet", is_flag=True, help="Suppress progress output.")
def check(
    targets: Optional[str],
    use_defaults: bool,
    ports: Optional[str],
    all_ports: bool,
    resolve_specs: Tuple[str, ...],
    starttls_override: Optional[str],
    connect_timeout: float,
    handshake_timeout: float,
    starttls_timeout: float,
    max_concurrent: int,
    retries: int,
    per_host_serial: bool,
    no_backoff: bool,
    handshake_samples: int,
    warmup_handshakes: int,
    min_samples: int,
    check_resumption: bool,
    alpn: Optional[str],
    ciphers: Optional[str],
    sni_hostname: Optional[str],
    no_sni: bool,
    min_days_remaining: Optional[int],
    max_lifetime_days: Optional[int],
    min_tls_version: Optional[str],
    expected_issuer: Optional[str],
    expected_fingerprint: Optional[str],
    allow_hostname_mismatch: bool,
    require_forward_secrecy: bool,
    allow_weak_key: bool,
    allow_weak_signature: bool,
    allow_deprecated_tls: bool,
    require_revocation_source: bool,
    as_of: Optional[str],
    output: str,
    formats: str,
    json_output: bool,
    include_charts: bool,
    thresholds: Tuple[str, ...],
    quiet: bool,
) -> None:
    """Check SSL/TLS handshake, certificate, and policy for one or more targets."""

    # ── input validation ────────────────────────────────────────────────
    # Every validation failure below raises click.UsageError (exit code 2),
    # the same class as _parse_ports/_parse_tls_version/_parse_as_of/
    # _parse_starttls_override/_parse_thresholds. An earlier version of this
    # command printed some of these and returned with an implicit exit 0 --
    # indistinguishable, to a CI pipeline checking only the exit code, from
    # a clean run that found nothing wrong. Given this tool is run mostly in
    # CI/CD, a config typo silently reporting success is worse than a script
    # that has to handle a nonzero exit it wasn't expecting.
    if not use_defaults and not targets:
        raise click.UsageError("Provide --targets or use --use-defaults.")

    output_formats = [f.strip().lower() for f in formats.split(",") if f.strip()]
    for fmt in output_formats:
        if fmt not in ("csv", "excel", "pdf"):
            raise click.UsageError(
                f"invalid format {fmt!r} in --formats. Must be csv, excel, or pdf."
            )

    output_path = Path(output)
    output_path.mkdir(parents=True, exist_ok=True)

    port_list = _parse_ports(ports, all_ports)
    tls_floor = _parse_tls_version(min_tls_version, "--min-tls-version")
    evaluation_instant = _parse_as_of(as_of)
    starttls_forced = _parse_starttls_override(starttls_override)

    # ── parse targets ───────────────────────────────────────────────────
    try:
        resolve_map = parse_resolve_flags(resolve_specs) if resolve_specs else None
        if use_defaults:
            target_list = [
                SSLTarget(host=host, port=port_list[0])
                for host in TargetManager.get_default_targets()
            ]
            if not quiet:
                click.echo(success(f"Using default targets ({len(target_list)})"))
        else:
            assert targets is not None
            manager = TargetManager.parse_targets_input(
                targets, ports=port_list, resolve_map=resolve_map
            )
            target_list = manager.targets
            if not quiet:
                click.echo(success(f"Loaded {len(target_list)} targets"))
        # --starttls overrides the per-port guess from starttls_for_port()
        # for every target, applied after either construction path so
        # --use-defaults and --targets behave identically here. SSLTarget is
        # frozen, so this rebuilds each entry rather than mutating it.
        if starttls_forced is not None:
            target_list = [
                dataclass_replace(t, starttls=starttls_forced) for t in target_list
            ]
    except FileNotFoundError as e:
        raise click.UsageError(str(e))
    except ValueError as e:
        # Covers both a malformed target (TargetManager.parse_targets_input)
        # and a malformed --resolve value (parse_resolve_flags) -- both are
        # the user having typed something the parser cannot make sense of,
        # the same class of problem as an invalid --ports or
        # --min-tls-version value, and now handled identically.
        raise click.UsageError(str(e))
    except Exception as e:
        raise click.UsageError(f"error loading targets: {e}")

    alpn_protocols = [p.strip() for p in alpn.split(",") if p.strip()] if alpn else None

    if not quiet:
        click.echo(info("Configuration:"))
        click.echo(info(f"  Targets:            {len(target_list)}"))
        click.echo(info(f"  Handshake samples:  {handshake_samples}"))
        click.echo(info(f"  Check resumption:   {'yes' if check_resumption else 'no'}"))
        if evaluation_instant is not None:
            click.echo(info(f"  Evaluated as of:    {evaluation_instant.isoformat()}"))

    if not quiet:
        click.echo(warning("Starting SSL/TLS check…"))

    start_time = time.time()

    try:
        engine = SSLCheckEngine(
            max_concurrent=max_concurrent,
            connect_timeout=connect_timeout,
            handshake_timeout=handshake_timeout,
            starttls_timeout=starttls_timeout,
            max_retries=retries,
            handshake_samples=handshake_samples,
            warmup_handshakes=warmup_handshakes,
            min_samples=min_samples,
            per_host_serial=per_host_serial,
            backoff_on_timeout=not no_backoff,
            check_resumption=check_resumption,
            alpn_protocols=alpn_protocols,
            cipher_string=ciphers,
            send_sni=not no_sni,
            server_hostname=sni_hostname,
            as_of=evaluation_instant,
        )

        progress_bar = None
        if not quiet:
            progress_bar = create_progress_bar(len(target_list), "SSL Checks")

            def _progress_cb(completed: int, total: int) -> None:
                try:
                    if progress_bar:
                        progress_bar.n = completed
                        progress_bar.refresh()
                except Exception:
                    pass

            engine.set_progress_callback(_progress_cb)

        async def _run() -> List[SSLResult]:
            return await engine.check_targets(target_list)

        results = asyncio.run(_run())

        if progress_bar:
            progress_bar.close()

        duration = time.time() - start_time
        if not quiet:
            click.echo(success(f"Check completed in {duration:.2f}s"))

        # ── policy ───────────────────────────────────────────────────────
        policy = PolicyConfig(
            min_days_remaining=min_days_remaining,
            max_cert_lifetime_days=max_lifetime_days,
            min_tls_version=tls_floor,
            expected_issuer=expected_issuer,
            expected_fingerprint=expected_fingerprint,
            require_hostname_match=not allow_hostname_mismatch,
            require_forward_secrecy=require_forward_secrecy,
            reject_weak_key=not allow_weak_key,
            reject_weak_signature=not allow_weak_signature,
            reject_deprecated_tls=not allow_deprecated_tls,
            require_revocation_source=require_revocation_source,
        )
        for result in results:
            evaluate_policy(result, policy)

        # ── analysis ─────────────────────────────────────────────────────
        analyzer = SSLAnalyzer(results)
        overall = analyzer.get_overall_statistics()

        if not quiet:
            expiry_min = overall.get("cert_expiry_days_min")
            summary_lines = [
                f"Total targets:     {overall['total_checks']}",
                f"Measured:          {overall['measured_checks']}",
                f"Compliant:         {overall['compliant_checks']} "
                f"of {overall['policy_evaluated_checks']} evaluated",
                f"Certificates seen: {overall['certificates_observed']}",
                f"Soonest expiry:    "
                f"{f'{expiry_min} days' if expiry_min is not None else 'n/a'}",
                f"Deprecated TLS:    {overall['deprecated_tls_targets']}",
                f"Weak keys:         {overall['weak_key_targets']}",
                f"Expired certs:     {overall['expired_targets']}",
                f"Hostname mismatch: {overall['hostname_mismatch_targets']}",
            ]
            click.echo(summary_box(summary_lines))

        # ── export ───────────────────────────────────────────────────────
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base = f"net_benchmark.ssl_check_{timestamp}"
        provenance = build_provenance()

        if not quiet:
            click.echo(warning("Exporting results…"))

        export_count = len(output_formats) + (1 if json_output else 0)
        export_progress = (
            create_progress_bar(export_count, "Exporting") if not quiet else None
        )

        parsed_thresholds = _parse_thresholds(thresholds)
        threshold_report: Dict[str, List[ThresholdResult]] = {}
        if parsed_thresholds:
            threshold_report = analyzer.get_thresholds_report(parsed_thresholds)

        try:
            if "csv" in output_formats:
                SSLCSVExporter.export_raw_results(
                    results, str(output_path / f"{base}_raw.csv")
                )
                SSLCSVExporter.export_summary_statistics(
                    analyzer, str(output_path / f"{base}_summary.csv")
                )
                SSLCSVExporter.export_expiry_timeline(
                    results, str(output_path / f"{base}_expiry_timeline.csv")
                )
                if export_progress:
                    export_progress.update(1)

            if "excel" in output_formats:
                SSLExcelExporter.export_results(
                    results,
                    analyzer,
                    str(output_path / f"{base}.xlsx"),
                    threshold_results=threshold_report or None,
                    provenance=provenance,
                    include_charts=include_charts,
                )
                if export_progress:
                    export_progress.update(1)

            if "pdf" in output_formats:
                try:
                    SSLPDFExporter.export_results(
                        results,
                        analyzer,
                        str(output_path / f"{base}.pdf"),
                        provenance=provenance,
                    )
                except Exception as e:
                    click.echo(error(f"PDF export failed: {e}"))
                finally:
                    if export_progress:
                        export_progress.update(1)

            if json_output:
                SSLExportBundle.export_json(
                    results,
                    analyzer,
                    str(output_path / f"{base}.json"),
                    threshold_results=threshold_report or None,
                    provenance=provenance,
                )
                if export_progress:
                    export_progress.update(1)

            if not quiet:
                click.echo(success("All exports completed!"))
                click.echo(info(f"Results saved to: {output_path}"))

        finally:
            if export_progress:
                export_progress.close()

        # Threshold gate, evaluated AFTER exports — same ordering as
        # http_bench.cli.benchmark and for the same reason: a failing run
        # still leaves its artifacts behind for inspection, and the non-zero
        # exit is what makes this usable as a CI step. A `raise SystemExit(1)`
        # inside the `finally` above would replace any exception already
        # propagating from a genuine export failure, so this stays outside it.
        if threshold_report:
            try:
                SSLExportBundle.export_threshold_results(
                    threshold_report, str(output_path), base
                )
            except OSError as exc:
                click.echo(warning(f"Could not write thresholds CSV: {exc}"))
            all_ok = True
            for target_name, target_results in threshold_report.items():
                if not _report_thresholds(target_name, target_results, quiet):
                    all_ok = False
            if not all_ok:
                click.echo(error("Thresholds failed."))
                raise SystemExit(1)

    except click.UsageError:
        raise
    except KeyboardInterrupt:
        click.echo(warning("\nCheck interrupted by user"))
    except Exception as e:
        click.echo(error(f"Check error: {e}"))
        raise
