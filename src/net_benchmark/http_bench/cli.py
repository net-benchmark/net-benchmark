"""HTTP benchmarking CLI."""

import asyncio
import json
import time
from dataclasses import replace
from datetime import datetime
from difflib import get_close_matches  # --- 0.5.2: --threshold typo hints
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple

import click
from colorama import Fore, Style

from net_benchmark.dns_benchmark.core import QueryStatus
from net_benchmark.http_bench.analysis import (
    HTTPAnalyzer,
    Threshold,
    ThresholdResult,
    parse_threshold,
    thresholds_passed,
)
from net_benchmark.http_bench.core import HTTPBenchmarkEngine, HTTPResult, TargetManager

# --- 0.5.2: local multi-process load generation. Only used when --workers > 1;
# the single-process path below is unchanged.
from net_benchmark.http_bench.distributed import (
    DistributedResult,
    TargetDistribution,
    WorkerConfig,
    load_payload_files,
    merge_payloads,
    run_distributed,
    run_worker_async,
)
from net_benchmark.http_bench.exporters import (
    HTTPCSVExporter,
    HTTPExcelExporter,
    HTTPExportBundle,
    HTTPPDFExporter,
)
from net_benchmark.http_bench.load_test import (
    known_metric_names,  # --- 0.5.2: parse-time --threshold validation
)
from net_benchmark.http_bench.load_test import (
    IntervalStats,
    LoadTestSummary,
)
from net_benchmark.http_bench.load_test_exporters import (
    LoadTestCSVExporter,
    LoadTestExcelExporter,
    LoadTestExportBundle,
    LoadTestPDFExporter,
    export_latency_histograms,
)
from net_benchmark.utils.helpers import create_progress_bar
from net_benchmark.utils.messages import (
    error,
    info,
    success,
    summary_box,
    warning,
)


# ── HTTP command group ────────────────────────────────────────────────────────
@click.group(name="http")
def http() -> None:
    """Benchmark HTTP/HTTPS endpoints — latency, TTFB, security headers."""
    pass


def _parse_thresholds(specs: Sequence[str]) -> List[Threshold]:
    """0.5.2 — parse --threshold values, failing loudly on a bad expression.

    A typo must not silently become a threshold that never fires; that would
    make a green CI run meaningless.

    --- 0.5.2: the metric NAME is checked here too, not only the syntax.
    parse_threshold validates the shape of the expression, so `p95_latenci<500`
    parsed cleanly and only failed at evaluation — after a 30s load test had
    already run. A typo should cost a second, not a full run.

    Checked against a SUPERSET of every metric that can exist (see
    load_test.known_metric_names). A name that is real but absent from this
    particular run — sample-dependent on a failed run, dropped_rate on an
    unpaced one, an un-mergeable one on a merged run — still reaches
    evaluate_thresholds, which fails it with a reason specific to what
    happened rather than a generic "unknown metric".
    """
    known = known_metric_names()
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
    """0.5.2 — print threshold outcomes and return whether they all passed."""
    if not results:
        return True
    if not quiet:
        click.echo(info(f"Thresholds — {label}"))
        for r in results:
            mark = "PASS" if r.passed else "FAIL"
            actual = "n/a" if r.actual is None else f"{r.actual:.2f}"
            line = f"  [{mark}] {r.threshold}  actual={actual}"
            if r.error:
                # --- 0.5.2: append, do not overwrite. This was a plain
                # assignment, so any threshold with an error message lost its
                # [FAIL] marker and the expression itself — the reader saw a
                # bare parenthetical and no indication which criterion it
                # belonged to, or that it had failed at all.
                line += f"  ({r.error})"

            click.echo(success(line) if r.passed else error(line))
    return thresholds_passed(results)


def _parse_expected_statuses(raw: Optional[str]) -> Optional[Set[int]]:
    """0.5.2 — parse --expected-status: '200,404' or '200-299,404'."""
    if not raw:
        return set(range(200, 400))
    out: Set[int] = set()
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, _, hi = part.partition("-")
            try:
                out.update(range(int(lo), int(hi) + 1))
            except ValueError:
                raise click.UsageError(f"invalid status range {part!r}")
        else:
            try:
                out.add(int(part))
            except ValueError:
                raise click.UsageError(f"invalid status code {part!r}")
    return out or None


# ── benchmark ─────────────────────────────────────────────────────────────────
@http.command()
@click.option(
    "--targets",
    "-t",
    default=None,
    help="Comma-separated URLs or path to a text file (one URL per line).",
)
@click.option(
    "--use-defaults",
    is_flag=True,
    help="Use built-in default target URLs.",
)
@click.option(
    "--method",
    "-m",
    default="GET",
    show_default=True,
    help="HTTP method (GET, POST, HEAD, …).",
)
@click.option(
    "--headers",
    default=None,
    help='Extra request headers as "Key:Value,Key:Value".',
)
@click.option(
    "--body",
    default=None,
    help="Request body string (e.g. JSON).",
)
@click.option(
    "--body-file",
    default=None,
    help="Path to a file containing the request body.",
)
# ----------------
@click.option(
    "--auth",
    default=None,
    help="Authentication: 'basic:user:pass' or 'bearer:token'.",
)
@click.option(
    "--cert",
    default=None,
    help="Path to client certificate file (PEM) for mTLS.",
)
@click.option(
    "--cert-key",
    default=None,
    help="Path to client certificate private key file (if not combined with cert).",
)
@click.option(
    "--cookie",
    multiple=True,
    default=None,
    help="Cookie to include (repeatable, e.g. --cookie 'session=abc').",
)
@click.option(
    "--user-agent",
    default=None,
    help="Custom User-Agent header.",
)
@click.option(
    "--proxy",
    default=None,
    help="Proxy URL (e.g. http://127.0.0.1:8080).",
)
@click.option(
    "--sni",
    default=None,
    help="Override TLS SNI hostname.",
)
@click.option(
    "--local-address",
    default=None,
    help="Local IP address/interface to bind to.",
)
@click.option(
    "--inject-request-id",
    is_flag=True,
    help="Add an X-Request-ID header to each request.",
)
@click.option(
    "--assert",
    "assertions_raw",
    multiple=True,
    default=None,
    help="Assertion to check (repeatable). Format: 'type=value'. "
    "Types: status, body_contains, header_exists, max_latency.",
)
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
@click.option(
    "--timeout", default=10.0, show_default=True, help="Request timeout in seconds."
)
@click.option(
    "--max-concurrent",
    default=50,
    show_default=True,
    help="Maximum concurrent requests.",
)
@click.option(
    "--retries", default=2, show_default=True, help="Retries for failed requests."
)
@click.option(
    "--iterations",
    "-i",
    default=1,
    show_default=True,
    help="Number of iterations per target.",
)
@click.option(
    "--warmup", is_flag=True, help="Run full warmup requests before benchmark."
)
@click.option(
    "--warmup-fast", is_flag=True, help="Run lightweight HEAD warmup per target."
)
@click.option("--no-http2", is_flag=True, help="Disable HTTP/2 (force HTTP/1.1).")
@click.option(
    "--no-verify-ssl", is_flag=True, help="Skip TLS certificate verification."
)
@click.option(
    "--connect-timeout", type=float, default=None, help="Connection timeout (seconds)."
)
@click.option(
    "--read-timeout", type=float, default=None, help="Read timeout (seconds)."
)
@click.option(
    "--write-timeout", type=float, default=None, help="Write timeout (seconds)."
)
@click.option(
    "--params", default=None, help='Query parameters as "key=value,key2=value2".'
)
@click.option(
    "--include-charts", is_flag=True, help="Include charts in Excel and PDF exports."
)
# -------
@click.option(
    "--max-connections",
    type=int,
    default=None,
    help="Connection-pool size (default: --max-concurrent). Requests beyond "
    "this queue inside the pool and are reported as blocked_ms.",
)
@click.option(
    "--no-phase-trace",
    is_flag=True,
    help="Disable per-request phase timings (blocked/sending/waiting). "
    "Removes a small per-event callback cost; blocked_ms and waiting_ms "
    "become unavailable.",
)
@click.option("--json", "json_output", is_flag=True, help="Export results to JSON.")
# CI gate. Repeatable; every threshold must pass or the command exits 1.
@click.option(
    "--threshold",
    "thresholds",
    multiple=True,
    help="Pass/fail criterion, e.g. 'p95_latency<500' or 'error_rate<=1'. "
    "Repeatable. Any failure exits with code 1. Metrics include "
    "p95_latency, p99_latency, avg_latency, p95_duration_ms, "
    "avg_blocked_ms, avg_waiting_ms, p95_waiting_ms, error_rate, "
    "transport_error_rate, success_rate, "
    "avg_ttfb_ms, connection_reuse_rate, cert_expiry_days.",
)
# which status codes count as a healthy response.
@click.option(
    "--expected-status",
    default=None,
    help="Status codes treated as expected, e.g. '200,404' or '200-299,401'. "
    "Default 200-399. Affects transport_error_rate / "
    "unexpected_status_rate, which separate a real connection failure from "
    "an endpoint that legitimately returns 4xx.",
)
@click.option("--quiet", is_flag=True, help="Suppress progress output.")
def benchmark(
    targets: Optional[str],
    use_defaults: bool,
    method: str,
    headers: Optional[str],
    body: Optional[str],
    body_file: Optional[str],
    auth: Optional[str],
    cert: Optional[str],
    cert_key: Optional[str],
    cookie: Optional[Tuple[str]],  # (multiple)
    user_agent: Optional[str],
    proxy: Optional[str],
    sni: Optional[str],
    local_address: Optional[str],
    inject_request_id: bool,
    assertions_raw: Optional[Tuple[str]],
    output: str,
    formats: str,
    timeout: float,
    max_concurrent: int,
    retries: int,
    iterations: int,
    warmup: bool,
    warmup_fast: bool,
    no_http2: bool,
    no_verify_ssl: bool,
    connect_timeout: Optional[float],
    read_timeout: Optional[float],
    write_timeout: Optional[float],
    params: Optional[str],
    include_charts: bool,
    json_output: bool,
    max_connections: Optional[int],
    no_phase_trace: bool,
    thresholds: Tuple[str, ...],
    expected_status: Optional[str],
    quiet: bool,
) -> None:
    """Run HTTP benchmark test."""

    # ── input validation ──────────────────────────────────────────────────────
    if not use_defaults and not targets:
        click.echo(error("Provide --targets or use --use-defaults."))
        return

    output_formats = [f.strip().lower() for f in formats.split(",")]
    for fmt in output_formats:
        if fmt not in ("csv", "excel", "pdf"):
            click.echo(error(f"Invalid format '{fmt}'. Must be csv, excel, or pdf."))
            return

    output_path = Path(output)
    output_path.mkdir(parents=True, exist_ok=True)

    # ── parse targets ─────────────────────────────────────────────────────────
    try:
        if use_defaults:
            target_list = TargetManager.get_default_targets()
            if not quiet:
                click.echo(success(f"Using default targets ({len(target_list)} URLs)"))
        else:
            target_list = TargetManager.parse_targets_input(targets).targets
            if not quiet:
                click.echo(success(f"Loaded {len(target_list)} targets"))
    except FileNotFoundError as e:
        click.echo(error(str(e)))
        return
    except Exception as e:
        click.echo(error(f"Error loading targets: {e}"))
        return

    # ── parse extra headers ───────────────────────────────────────────────────
    extra_headers: Dict[str, str] = {}
    if headers:
        for pair in headers.split(","):
            if ":" in pair:
                k, _, v = pair.partition(":")
                extra_headers[k.strip()] = v.strip()

    # ── parse query params ──────────────────────────────────────────────
    query_params: Dict[str, str] = {}
    if params:
        for pair in params.split(","):
            if "=" in pair:
                k, _, v = pair.partition("=")
                query_params[k.strip()] = v.strip()

    # ── parse authentication ────────────────────────────────────────────────
    auth_obj = None
    if auth:
        parts = auth.split(":", 1)
        if parts[0].lower() == "basic":
            if len(parts) != 2 or ":" not in parts[1]:
                click.echo(error("Invalid basic auth format. Use 'basic:user:pass'."))
                return
            user, pwd = parts[1].split(":", 1)
            from httpx import BasicAuth

            auth_obj = BasicAuth(user, pwd)
        elif parts[0].lower() == "bearer":
            if len(parts) != 2:
                click.echo(error("Invalid bearer auth format. Use 'bearer:token'."))
                return
            token = parts[1]
            # Use a custom header injection? Actually httpx doesn't have BearerAuth, we can just set the header.
            # Better: we'll pass a bearer auth object or set the header ourselves.
            # We'll set extra_headers["Authorization"] = f"Bearer {token}"
            extra_headers["Authorization"] = f"Bearer {token}"
        else:
            click.echo(
                error(f"Unknown auth type '{parts[0]}'. Use 'basic' or 'bearer'.")
            )
            return
    # For Basic auth, we pass auth_obj to the engine; for Bearer we already set the header.

    # ── parse cookies ───────────────────────────────────────────────────────
    cookies: Dict[str, str] = {}
    if cookie:
        for c in cookie:
            if "=" not in c:
                click.echo(error(f"Invalid cookie '{c}'. Use name=value."))
                return
            name, val = c.split("=", 1)
            cookies[name.strip()] = val.strip()

    # ── parse assertions ────────────────────────────────────────────────────
    assertions: Dict[str, Any] = {}
    if assertions_raw:
        for a in assertions_raw:
            if "=" not in a:
                click.echo(error(f"Invalid assertion '{a}'. Use type=value."))
                return
            typ, val = a.split("=", 1)
            typ = typ.strip().lower()
            if typ == "status":
                assertions["status_code"] = int(val)
            elif typ == "body_contains":
                assertions["body_contains"] = val
            elif typ == "header_exists":
                assertions["header_exists"] = val
            elif typ == "max_latency":
                try:
                    assertions["max_latency"] = float(val)
                except ValueError:
                    click.echo(error("max_latency must be a number (ms)."))
                    return
            elif typ == "header_value":
                # format: header_value:X-Cache=HIT
                if "=" not in val:
                    click.echo(error("header_value assertion requires header=value."))
                    return
                hdr, hval = val.split("=", 1)
                assertions["header_value"] = {
                    "header": hdr.strip(),
                    "value": hval.strip(),
                }
            elif typ == "content_type":
                assertions["content_type"] = val.strip()
            elif typ == "response_size_min":
                assertions["response_size_min"] = int(val)
            elif typ == "response_size_max":
                assertions["response_size_max"] = int(val)

            else:
                click.echo(error(f"Unknown assertion type '{typ}'."))
                return

    # ── set user-agent if provided ──────────────────────────────────────────
    if user_agent:
        extra_headers["User-Agent"] = user_agent

    if body and body_file:
        click.echo(error("Provide either --body or --body-file, not both."))
        return

    body_bytes: Optional[bytes] = None

    if body_file:
        try:
            body_bytes = Path(body_file).read_bytes()
        except Exception as e:
            click.echo(error(f"Cannot read body file: {e}"))
            return
    elif body is not None:  # empty string is allowed
        body_bytes = body.encode("utf-8")

    # Auto‑set Content‑Type for JSON‑looking bodies if the user didn't provide one
    if body_bytes and "content-type" not in {k.lower() for k in extra_headers}:
        if (body_file and Path(body_file).suffix.lower() == ".json") or (
            body_bytes
            and (
                body_bytes.lstrip().startswith(b"{")
                or body_bytes.lstrip().startswith(b"[")
            )
        ):
            extra_headers["Content-Type"] = "application/json"

    total_requests = len(target_list) * iterations

    if not quiet:
        click.echo(info("Configuration:"))
        click.echo(info(f"  Targets:      {len(target_list)}"))
        click.echo(info(f"  Method:       {method.upper()}"))
        click.echo(info(f"  Iterations:   {iterations}"))
        click.echo(info(f"  Total reqs:   {total_requests}"))
        click.echo(info(f"  HTTP/2:       {'disabled' if no_http2 else 'enabled'}"))
        click.echo(info(f"  Verify SSL:   {'no' if no_verify_ssl else 'yes'}"))
        if warmup_fast:
            click.echo(info("  Warmup:       fast (HEAD per target)"))
        elif warmup:
            click.echo(info("  Warmup:       full"))

    if not quiet:
        click.echo(warning("Starting HTTP benchmark…"))

    start_time = time.time()

    try:
        engine = HTTPBenchmarkEngine(
            max_concurrent=max_concurrent,
            timeout=timeout,
            connect_timeout=connect_timeout,
            read_timeout=read_timeout,
            write_timeout=write_timeout,
            query_params=query_params,
            max_retries=retries,
            method=method.upper(),
            headers=extra_headers,
            http2=not no_http2,
            verify_ssl=not no_verify_ssl,
            auth=auth_obj,
            cookies=cookies,
            proxy=proxy,
            sni_hostname=sni,
            mtls_cert=cert,
            mtls_key=cert_key,
            local_address=local_address,
            inject_request_id=inject_request_id,
            assertions=assertions,
            body=body_bytes,
            max_connections=max_connections,
            enable_phase_trace=not no_phase_trace,
            # --- 0.5.2: given to the engine, not just the analyzer, so
            # HTTPResult.status agrees with the summary. Previously the raw
            # CSV called an expected 404 a failure while the summary CSV
            # called it expected.
            expected_statuses=_parse_expected_statuses(expected_status),
        )

        progress_bar = None
        if not quiet:
            progress_bar = create_progress_bar(total_requests, "HTTP Requests")

            def _progress_cb(completed: int, total: int) -> None:
                try:
                    if progress_bar:
                        progress_bar.n = completed
                        progress_bar.refresh()
                except Exception:
                    pass

            engine.set_progress_callback(_progress_cb)

        async def _run() -> List[HTTPResult]:
            results = await engine.run_benchmark(
                targets=target_list,
                iterations=iterations,
                warmup=warmup,
                warmup_fast=warmup_fast,
            )
            await engine.close()
            return results

        results = asyncio.run(_run())

        if progress_bar:
            progress_bar.close()

        duration = time.time() - start_time
        if not quiet:
            click.echo(success(f"Benchmark completed in {duration:.2f}s"))

        # ── analysis ──────────────────────────────────────────────────────────
        analyzer = HTTPAnalyzer(
            results, expected_statuses=_parse_expected_statuses(expected_status)
        )
        overall = analyzer.get_overall_statistics()

        if not quiet:
            summary_lines = [
                f"Total requests:   {overall['total_requests']}",
                # --- 0.5.2: without this line the box is unreadable when a
                # target answers with an unexpected status: "Successful: 0"
                # next to a non-zero avg latency looks like a contradiction.
                # Successful = matched --expected-status; Responded = got an
                # HTTP reply at all. Total minus Responded is transport failure.
                f"Responded:        {overall['responded_requests']}",
                f"Successful:       {overall['successful_requests']} ({overall['overall_success_rate']:.2f}%)",
                f"Avg latency:      {overall['overall_avg_latency']:.2f} ms",
                f"Avg TTFB:         {overall['overall_avg_ttfb']:.2f} ms",
                f"HTTP/2 rate:      {overall['http2_rate']:.1f}%",
                f"HSTS coverage:    {overall['hsts_coverage']:.1f}%",
                f"Fastest target:   {overall['fastest_target']}",
                f"Slowest target:   {overall['slowest_target']}",
            ]
            click.echo(summary_box(summary_lines))

        # ── export ────────────────────────────────────────────────────────────
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base = f"net_benchmark.http_benchmark_{timestamp}"

        if not quiet:
            click.echo(warning("Exporting results…"))

        export_count = len(output_formats) + (1 if json_output else 0)
        export_progress = (
            create_progress_bar(export_count, "Exporting") if not quiet else None
        )

        try:
            if "csv" in output_formats:
                HTTPCSVExporter.export_raw_results(
                    results, str(output_path / f"{base}_raw.csv")
                )
                HTTPCSVExporter.export_summary_statistics(
                    analyzer, str(output_path / f"{base}_summary.csv")
                )
                HTTPCSVExporter.export_security_statistics(
                    analyzer, str(output_path / f"{base}_security.csv")
                )
                HTTPCSVExporter.export_ttfb_statistics(
                    analyzer, str(output_path / f"{base}_ttfb.csv")
                )
                HTTPCSVExporter.export_protocol_statistics(
                    analyzer, str(output_path / f"{base}_protocols.csv")
                )
                if export_progress:
                    export_progress.update(1)

            if "excel" in output_formats:
                HTTPExcelExporter.export_results(
                    results,
                    analyzer,
                    str(output_path / f"{base}.xlsx"),
                    include_charts=include_charts,
                )
                if export_progress:
                    export_progress.update(1)

            if "pdf" in output_formats:
                try:
                    HTTPPDFExporter.export_results(
                        results,
                        analyzer,
                        str(output_path / f"{base}.pdf"),
                        include_charts=include_charts,
                    )
                except Exception as e:
                    click.echo(error(f"PDF export failed: {e}"))
                finally:
                    if export_progress:
                        export_progress.update(1)

            if json_output:
                HTTPExportBundle.export_json(
                    results,
                    analyzer,
                    str(output_path / f"{base}.json"),
                )
                if export_progress:
                    export_progress.update(1)

            if not quiet:
                click.echo(success("All exports completed!"))
                click.echo(info(f"Results saved to: {output_path}"))

        finally:
            if export_progress:
                export_progress.close()

        # --- 0.5.2: threshold gate. Evaluated AFTER exports so a failing run
        # still leaves its artifacts behind for inspection; the non-zero exit
        # is what makes this usable as a CI step.
        #
        # Dedented out of the `finally:` above, where it previously sat. A
        # `raise SystemExit(1)` inside a finally block replaces whatever
        # exception was already propagating, so a genuine failure during
        # export would have been silently swallowed and reported as a
        # threshold failure instead.
        parsed_thresholds = _parse_thresholds(thresholds)
        if parsed_thresholds:
            report = analyzer.get_thresholds_report(
                parsed_thresholds, duration_s=duration
            )
            # Machine-readable record of the gate. stdout is gone by the time
            # anyone investigates a red build.
            try:
                HTTPExportBundle.export_threshold_results(
                    report, str(output_path), base
                )
            except OSError as exc:
                click.echo(warning(f"Could not write thresholds CSV: {exc}"))
            all_ok = True
            for target_url, results_for_target in report.items():
                if not _report_thresholds(target_url, results_for_target, quiet):
                    all_ok = False
            if not all_ok:
                click.echo(error("Thresholds failed."))
                raise SystemExit(1)

    except click.UsageError:
        raise
    except KeyboardInterrupt:
        click.echo(warning("\nBenchmark interrupted by user"))
    except Exception as e:
        click.echo(error(f"Benchmark error: {e}"))
        raise


# ── top ───────────────────────────────────────────────────────────────────────
@http.command()
@click.option("--targets", "-t", default=None, help="Targets inline or file.")
@click.option("--use-defaults", is_flag=True, help="Use built-in default targets.")
@click.option(
    "--limit",
    "-n",
    default=5,
    show_default=True,
    help="Number of top targets to display.",
)
@click.option(
    "--metric",
    default="latency",
    type=click.Choice(["latency", "ttfb", "success"], case_sensitive=False),
    show_default=True,
    help="Metric to rank by.",
)
@click.option("--quiet", is_flag=True, help="Suppress progress output.")
def top(
    targets: Optional[str],
    use_defaults: bool,
    limit: int,
    metric: str,
    quiet: bool,
) -> None:
    """Run a quick benchmark and show the top N targets by a metric.

    Mirrors: dns top --limit N
    """
    if not use_defaults and not targets:
        click.echo(error("Provide --targets or use --use-defaults."))
        return

    try:
        target_list = (
            TargetManager.get_default_targets()
            if use_defaults
            else TargetManager.parse_targets_input(targets).targets
        )
    except Exception as e:
        click.echo(error(f"Error loading targets: {e}"))
        return

    if not quiet:
        click.echo(info(f"Running quick benchmark across {len(target_list)} targets…"))

    async def _run() -> List[HTTPResult]:
        engine = HTTPBenchmarkEngine(max_concurrent=20, timeout=10.0, max_retries=1)
        results = await engine.run_benchmark(
            target_list, iterations=3, warmup_fast=True
        )
        await engine.close()
        return results

    results = asyncio.run(_run())
    analyzer = HTTPAnalyzer(results)
    stats = analyzer.get_target_statistics()

    # Sort by chosen metric
    metric_key = {
        "latency": lambda s: s.avg_latency,
        "ttfb": lambda s: s.avg_ttfb_ms,
        "success": lambda s: -s.success_rate,  # negate so sort ascending = best first
    }[metric.lower()]
    # --- 0.5.2: responded_requests, not successful_requests. A target that
    # answers every request with an unexpected status still has a measured
    # avg_latency and avg_ttfb_ms and belongs in the ranking; gating on
    # success dropped it entirely and produced an empty table for, say, a
    # rate-limited endpoint. Also guarantees avg_latency is not NaN, so the
    # sort key is well defined.

    ranked = sorted(
        [s for s in stats if s.responded_requests > 0],
        key=metric_key,
    )[:limit]

    click.echo(info(f"\nTop {limit} targets by {metric}:"))
    click.echo(
        f"  {'#':<4} {'Target':<45} {'Avg ms':>8} {'TTFB ms':>9} {'Success':>8} {'H/2':>6}"
    )
    click.echo("  " + "─" * 82)
    for i, s in enumerate(ranked, 1):
        label = s.target.replace("https://", "").replace("http://", "")[:44]
        click.echo(
            f"  {i:<4} {label:<45} {s.avg_latency:>8.1f} "
            f"{s.avg_ttfb_ms:>9.1f} {s.success_rate:>7.1f}% "
            f"{'✓' if s.http2_rate > 50 else '✗':>6}"
        )


# ── monitoring ───────────────────────────────────────────────────────────────────
@http.command()
@click.option("--targets", "-t", default=None, help="Targets inline or file.")
@click.option("--use-defaults", is_flag=True, help="Use built-in default targets.")
@click.option(
    "--interval",
    default=60,
    show_default=True,
    help="Seconds between checks.",
)
@click.option(
    "--duration",
    default=0,
    show_default=True,
    help="Total monitoring duration in seconds (0 = run until Ctrl-C).",
)
@click.option(
    "--alert-latency",
    default=0.0,
    show_default=True,
    help="Alert when avg latency exceeds N ms (0 = disabled).",
)
@click.option(
    "--alert-failure-rate",
    default=0.0,
    show_default=True,
    help=(
        "Alert when failure rate (transport errors + unexpected statuses) "
        "exceeds N%% (0 = disabled)."
    ),
)
@click.option(
    "--alert-transport-error-rate",
    default=0.0,
    show_default=True,
    help=(
        "Alert only when the TRANSPORT error rate exceeds N%% (0 = disabled). "
        "Use this to page on 'the origin is unreachable' without also paging "
        "on 'the origin answered 403'."
    ),
)
@click.option(
    "--expected-status",
    default=None,
    help=(
        "Comma-separated status codes to treat as successful, e.g. '200,401'. "
        "Same semantics as `benchmark --expected-status`."
    ),
)
@click.option(
    "--output",
    "-o",
    default="./monitoring_results",
    show_default=True,
    help="Directory to write per-interval JSON snapshots.",
)
def monitoring(
    targets: Optional[str],
    use_defaults: bool,
    interval: int,
    duration: int,
    alert_latency: float,
    alert_failure_rate: float,
    alert_transport_error_rate: float,
    expected_status: Optional[str],
    output: str,
) -> None:
    """Continuously monitoring HTTP targets. Mirrors: dns monitoring.

    Runs a benchmark every --interval seconds and prints a live summary.
    Press Ctrl-C to stop.
    """
    if not use_defaults and not targets:
        click.echo(error("Provide --targets or use --use-defaults."))
        return

    try:
        target_list = (
            TargetManager.get_default_targets()
            if use_defaults
            else TargetManager.parse_targets_input(targets).targets
        )
    except Exception as e:
        click.echo(error(f"Error loading targets: {e}"))
        return

    expected_statuses = _parse_expected_statuses(expected_status)
    output_path = Path(output)
    output_path.mkdir(parents=True, exist_ok=True)

    click.echo(info(f"Monitoring {len(target_list)} targets every {interval}s"))
    click.echo(info("Press Ctrl-C to stop.\n"))

    start_wall = time.time()
    iteration = 0

    try:
        while True:
            iteration += 1
            tick = time.time()

            async def _run() -> List[HTTPResult]:
                engine = HTTPBenchmarkEngine(
                    max_concurrent=20,
                    timeout=10.0,
                    max_retries=1,
                    # --- 0.5.2: monitoring had no way to say which statuses
                    # are acceptable, so an endpoint that legitimately answers
                    # 401 alerted forever.
                    expected_statuses=expected_statuses,
                )
                res = await engine.run_benchmark(target_list, iterations=1)
                await engine.close()
                return res

            results = asyncio.run(_run())
            analyzer = HTTPAnalyzer(results, expected_statuses=expected_statuses)
            overall = analyzer.get_overall_statistics()

            now_str = datetime.now().strftime("%H:%M:%S")
            status_colour = (
                Fore.GREEN
                if overall["overall_success_rate"] >= 95
                else Fore.YELLOW if overall["overall_success_rate"] >= 80 else Fore.RED
            )
            click.echo(
                f"[{now_str}] "
                f"{status_colour}success={overall['overall_success_rate']:.1f}%{Style.RESET_ALL}  "
                f"avg={overall['overall_avg_latency']:.1f}ms  "
                f"ttfb={overall['overall_avg_ttfb']:.1f}ms  "
                f"h2={overall['http2_rate']:.0f}%"
            )

            # ── alerts ────────────────────────────────────────────────────────
            if alert_latency and overall["overall_avg_latency"] > alert_latency:
                click.echo(
                    warning(
                        f"ALERT: avg latency {overall['overall_avg_latency']:.1f}ms "
                        f"> threshold {alert_latency:.1f}ms"
                    )
                )
            # --- 0.5.2: "failure rate" was 100 - success_rate, which lumps
            # two unrelated conditions together. A rate-limited endpoint that
            # answers every request promptly over HTTP/2 with a 403 scored a
            # 100% "failure rate" while its transport error rate was 0.00%.
            # Monitoring is what pages someone, and "the origin is
            # unreachable" and "the origin refused us" want different
            # responses.
            #
            # --alert-failure-rate keeps its exact previous trigger condition
            # so nothing that alerted before goes quiet; only the message now
            # says which half is responsible. --alert-transport-error-rate is
            # the new, narrower signal.
            total = overall["total_requests"] or 1
            transport_error_rate = (
                (total - overall["responded_requests"]) / total * 100.0
            )
            unexpected_status_rate = (
                (overall["responded_requests"] - overall["successful_requests"])
                / total
                * 100.0
            )
            failure_rate = 100.0 - overall["overall_success_rate"]
            if alert_failure_rate and failure_rate > alert_failure_rate:
                click.echo(
                    warning(
                        f"ALERT: failure rate {failure_rate:.1f}% "
                        f"> threshold {alert_failure_rate:.1f}% "
                        f"(transport {transport_error_rate:.1f}%, "
                        f"unexpected status {unexpected_status_rate:.1f}%)"
                    )
                )
            if (
                alert_transport_error_rate
                and transport_error_rate > alert_transport_error_rate
            ):
                click.echo(
                    warning(
                        f"ALERT: transport error rate "
                        f"{transport_error_rate:.1f}% "
                        f"> threshold {alert_transport_error_rate:.1f}%"
                    )
                )

            # ── persist snapshot ──────────────────────────────────────────────
            snapshot_path = (
                output_path
                / f"http_monitor_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            )
            with open(snapshot_path, "w", encoding="utf-8") as f:
                json.dump(
                    {"timestamp": datetime.now().isoformat(), "overall": overall},
                    f,
                    indent=2,
                )

            # ── duration check ────────────────────────────────────────────────
            if duration and (time.time() - start_wall) >= duration:
                click.echo(info("Monitoring duration reached. Stopping."))
                break

            # ── sleep until next interval ──────────────────────────────────────
            elapsed = time.time() - tick
            sleep_for = max(0.0, interval - elapsed)
            time.sleep(sleep_for)

    except KeyboardInterrupt:
        click.echo(warning("\nMonitoring stopped by user."))


# ── compare ───────────────────────────────────────────────────────────────────────
@http.command()
@click.argument("urls", nargs=-1, required=True)
@click.option("--method", "-m", default="GET", show_default=True, help="HTTP method.")
@click.option(
    "--headers", default=None, help='Extra request headers as "Key:Value,Key:Value".'
)
@click.option("--body", default=None, help="Request body string (e.g. JSON).")
@click.option(
    "--body-file", default=None, help="Path to a file containing the request body."
)
@click.option(
    "--auth", default=None, help="Authentication: 'basic:user:pass' or 'bearer:token'."
)
@click.option(
    "--cert", default=None, help="Path to client certificate file (PEM) for mTLS."
)
@click.option(
    "--cert-key", default=None, help="Path to client certificate private key file."
)
@click.option(
    "--cookie", multiple=True, default=None, help="Cookie to include (repeatable)."
)
@click.option("--user-agent", default=None, help="Custom User-Agent header.")
@click.option("--proxy", default=None, help="Proxy URL.")
@click.option("--sni", default=None, help="Override TLS SNI hostname.")
@click.option(
    "--inject-request-id",
    is_flag=True,
    help="Add an X-Request-ID header to each request.",
)
@click.option(
    "--iterations",
    "-i",
    default=3,
    show_default=True,
    help="Number of iterations per target.",
)
@click.option(
    "--timeout", default=10.0, show_default=True, help="Request timeout in seconds."
)
@click.option(
    "--max-concurrent",
    default=20,
    show_default=True,
    help="Maximum concurrent requests.",
)
@click.option("--no-http2", is_flag=True, help="Disable HTTP/2.")
@click.option(
    "--no-verify-ssl", is_flag=True, help="Skip TLS certificate verification."
)
@click.option(
    "--output",
    "-o",
    default=None,
    help="Optional: save comparison to file (.csv, .json, .txt).",
)
@click.option("--quiet", is_flag=True, help="Suppress progress output.")
@click.option("--show-details", is_flag=True, help="Show per-iteration breakdown.")
def compare(
    urls: Tuple[str],
    method: str,
    headers: Optional[str],
    body: Optional[str],
    body_file: Optional[str],
    auth: Optional[str],
    cert: Optional[str],
    cert_key: Optional[str],
    cookie: Optional[Tuple[str]],
    user_agent: Optional[str],
    proxy: Optional[str],
    sni: Optional[str],
    inject_request_id: bool,
    iterations: int,
    timeout: float,
    max_concurrent: int,
    no_http2: bool,
    no_verify_ssl: bool,
    output: Optional[str],
    quiet: bool,
    show_details: bool,
) -> None:
    """Compare specific HTTP targets side‑by‑side.

    You can specify targets by full URL or just hostname (https:// is added if missing).

    Examples:
        net-benchmark http compare https://example.com https://httpbin.org/get
        net-benchmark http compare api.example.com api2.example.com --iterations 5
    """
    # Normalize URLs – add scheme if missing
    target_list = []
    for u in urls:
        u = u.strip()
        if not u.startswith(("http://", "https://")):
            u = "https://" + u
        target_list.append(u)

    if len(target_list) < 2:
        click.echo(error("Need at least 2 targets to compare."))
        return

    # Parse extra headers
    extra_headers: Dict[str, str] = {}
    if headers:
        for pair in headers.split(","):
            if ":" in pair:
                k, _, v = pair.partition(":")
                extra_headers[k.strip()] = v.strip()

    # Body / body-file conflict
    if body and body_file:
        click.echo(error("Provide either --body or --body-file, not both."))
        return

    body_bytes: Optional[bytes] = None
    if body_file:
        try:
            body_bytes = Path(body_file).read_bytes()
        except Exception as e:
            click.echo(error(f"Cannot read body file: {e}"))
            return
    elif body is not None:
        body_bytes = body.encode("utf-8")

    if body_bytes and "content-type" not in {k.lower() for k in extra_headers}:
        if (body_file and Path(body_file).suffix.lower() == ".json") or (
            body_bytes.lstrip().startswith(b"{") or body_bytes.lstrip().startswith(b"[")
        ):
            extra_headers["Content-Type"] = "application/json"

    # Auth
    auth_obj = None
    if auth:
        parts = auth.split(":", 1)
        if parts[0].lower() == "basic":
            if len(parts) != 2 or ":" not in parts[1]:
                click.echo(error("Invalid basic auth format. Use 'basic:user:pass'."))
                return
            user, pwd = parts[1].split(":", 1)
            from httpx import BasicAuth

            auth_obj = BasicAuth(user, pwd)
        elif parts[0].lower() == "bearer":
            if len(parts) != 2:
                click.echo(error("Invalid bearer auth format. Use 'bearer:token'."))
                return
            extra_headers["Authorization"] = f"Bearer {parts[1]}"
        else:
            click.echo(error(f"Unknown auth type '{parts[0]}'."))
            return

    # Cookies
    cookies: Dict[str, str] = {}
    if cookie:
        for c in cookie:
            if "=" not in c:
                click.echo(error(f"Invalid cookie '{c}'."))
                return
            name, val = c.split("=", 1)
            cookies[name.strip()] = val.strip()

    # User-Agent
    if user_agent:
        extra_headers["User-Agent"] = user_agent

    if not quiet:
        click.echo(info(f"🔬 Comparing {len(target_list)} targets…"))
        click.echo(info(f"   Iterations: {iterations}"))

    total_requests = len(target_list) * iterations

    progress_bar = None
    if not quiet:
        progress_bar = create_progress_bar(total_requests, "Comparing")

    try:
        engine = HTTPBenchmarkEngine(
            max_concurrent=max_concurrent,
            timeout=timeout,
            max_retries=2,
            method=method.upper(),
            headers=extra_headers,
            http2=not no_http2,
            verify_ssl=not no_verify_ssl,
            auth=auth_obj,
            cookies=cookies,
            proxy=proxy,
            sni_hostname=sni,
            mtls_cert=cert,
            mtls_key=cert_key,
            inject_request_id=inject_request_id,
            body=body_bytes,
        )

        if progress_bar:

            def _progress_cb(completed: int, total: int) -> None:
                try:
                    if progress_bar:
                        progress_bar.n = completed
                        progress_bar.refresh()
                except Exception:
                    pass

            engine.set_progress_callback(_progress_cb)

        async def _run() -> List[HTTPResult]:
            results = await engine.run_benchmark(
                targets=target_list,
                iterations=iterations,
                warmup_fast=True,
            )
            await engine.close()
            return results

        results = asyncio.run(_run())

        if progress_bar:
            progress_bar.close()

        analyzer = HTTPAnalyzer(results)
        target_stats = analyzer.get_target_statistics()

        # Sort by avg_latency (only targets that produced a measurement)
        # --- 0.5.2: see `top` — responded_requests, not successful_requests.
        # most_reliable below intentionally stays on success_rate: that is an
        # outcome question, not a measurement one.
        valid = [s for s in target_stats if s.responded_requests > 0]

        if not valid:
            click.echo(error("No successful requests – nothing to compare."))
            return

        sorted_stats = sorted(valid, key=lambda s: s.avg_latency)

        if not quiet:
            click.echo(success("📊 Comparison Results:\n"))
            # Table header
            header = f"{'Target':<45} {'Avg (ms)':>8} {'TTFB (ms)':>9} {'Success':>8} {'H/2':>5}"
            click.echo(Fore.CYAN + header + Style.RESET_ALL)
            click.echo("-" * len(header))
            for s in sorted_stats:
                target_short = s.target.replace("https://", "").replace("http://", "")[
                    :44
                ]
                h2 = "✓" if s.http2_rate > 50 else "✗"
                click.echo(
                    f"{target_short:<45} {s.avg_latency:>8.1f} {s.avg_ttfb_ms:>9.1f} {s.success_rate:>7.1f}% {h2:>5}"
                )
            click.echo()
            fastest = sorted_stats[0]
            most_reliable = max(valid, key=lambda s: s.success_rate)
            click.echo(
                Fore.GREEN
                + "🏆 Fastest: "
                + Style.RESET_ALL
                + f"{fastest.target} ({fastest.avg_latency:.1f} ms)"
            )
            click.echo(
                Fore.GREEN
                + "🛡️  Most Reliable: "
                + Style.RESET_ALL
                + f"{most_reliable.target} ({most_reliable.success_rate:.1f}%)"
            )

            if show_details:
                click.echo(success("\n📋 Per-Iteration Breakdown:\n"))
                for target in target_list:
                    target_results = [
                        r
                        for r in results
                        if r.target == target and r.status == QueryStatus.SUCCESS
                    ]
                    if not target_results:
                        continue
                    click.echo(Fore.CYAN + f"{target}:" + Style.RESET_ALL)
                    for i, r in enumerate(target_results, 1):
                        click.echo(
                            f"  Iter {i}: {r.total_ms:.1f} ms (TTFB {r.ttfb_ms:.1f} ms)"
                        )

        # Export if requested
        if output:
            output_path = Path(output)
            ext = output_path.suffix.lower()
            if ext == ".json":
                data = {
                    "timestamp": datetime.now().isoformat(),
                    "iterations": iterations,
                    "comparison": [
                        {
                            "target": s.target,
                            "avg_latency_ms": s.avg_latency,
                            "avg_ttfb_ms": s.avg_ttfb_ms,
                            "success_rate": s.success_rate,
                            "http2_rate": s.http2_rate,
                            "successful_requests": s.successful_requests,
                            "total_requests": s.total_requests,
                        }
                        for s in target_stats
                    ],
                }
                with open(output_path, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2)
            elif ext == ".csv":
                HTTPCSVExporter.export_summary_statistics(analyzer, str(output_path))
            else:  # .txt
                with open(output_path, "w", encoding="utf-8") as f:
                    f.write("HTTP Target Comparison\n")
                    f.write(
                        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
                    )
                    f.write(
                        f"{'Target':<45} {'Avg (ms)':>8} {'TTFB (ms)':>9} {'Success':>8} {'H/2':>5}\n"
                    )
                    f.write("-" * 80 + "\n")
                    for s in sorted_stats:
                        target_short = s.target.replace("https://", "").replace(
                            "http://", ""
                        )[:44]
                        h2 = "✓" if s.http2_rate > 50 else "✗"
                        f.write(
                            f"{target_short:<45} {s.avg_latency:>8.1f} {s.avg_ttfb_ms:>9.1f} {s.success_rate:>7.1f}% {h2:>5}\n"
                        )
            if not quiet:
                click.echo(success(f"Comparison saved to: {output_path}"))

    except click.UsageError:
        raise
    except KeyboardInterrupt:
        if progress_bar:
            progress_bar.close()
        click.echo(warning("\nComparison interrupted by user"))
    except Exception as e:
        if progress_bar:
            progress_bar.close()
        click.echo(error(f"Error during comparison: {e}"))
        raise


# ── load-test ──────────────────────────────────────────────────────────────
@http.command(name="load-test")
# --- 0.5.1: same --targets/--use-defaults pattern as `benchmark`/`compare`,
# via TargetManager — multiple targets run concurrently (one LoadTestEngine
# per target, fanned out with asyncio.gather).
@click.option(
    "--targets",
    "-t",
    default=None,
    help="Comma-separated URLs or path to a text file (one URL per line).",
)
@click.option("--use-defaults", is_flag=True, help="Use built-in default target URLs.")
# --- 0.5.1: mode selects which of the three load-shaping strategies runs —
# see net_benchmark.http_bench.load_test.LoadTestEngine for the actual logic.
@click.option(
    "--mode",
    type=click.Choice(["throughput", "sustained", "ramp-up"], case_sensitive=False),
    default="throughput",
    show_default=True,
    help="Load test mode: throughput (saturate), sustained (fixed rate), "
    "ramp-up (gradually increase concurrency).",
)
@click.option(
    "--duration",
    default=10.0,
    show_default=True,
    help="Duration in seconds (throughput/sustained modes).",
)
@click.option(
    "--rps",
    type=float,
    default=None,
    help="Target requests/sec — required for --mode sustained.",
)
@click.option(
    "--max-concurrency",
    default=200,
    show_default=True,
    help="Max in-flight concurrent requests (throughput mode).",
)
@click.option(
    "--start-concurrency",
    default=10,
    show_default=True,
    help="Starting concurrency (ramp-up mode).",
)
@click.option(
    "--ramp-concurrency",
    default=200,
    show_default=True,
    help="Peak concurrency to ramp up to (ramp-up mode).",
)
@click.option(
    "--ramp-duration",
    default=30.0,
    show_default=True,
    help="Seconds spent ramping up to peak concurrency (ramp-up mode).",
)
@click.option(
    "--max-total-rps",
    type=float,
    default=None,
    help="Safety ceiling on aggregate requests/sec during ramp-up (default: "
    "ramp-concurrency * 50). Not a target rate — use --mode sustained for "
    "that. Only matters against very fast targets where request latency "
    "alone wouldn't otherwise bound throughput.",
)
@click.option(
    "--hold-duration",
    default=10.0,
    show_default=True,
    help="Seconds to hold at peak concurrency after ramping (ramp-up mode).",
)
@click.option("--method", "-m", default="GET", show_default=True, help="HTTP method.")
@click.option(
    "--headers",
    default=None,
    help='Extra request headers as "Key:Value,Key:Value".',
)
@click.option(
    "--timeout", default=10.0, show_default=True, help="Request timeout in seconds."
)
@click.option("--no-http2", is_flag=True, help="Disable HTTP/2 (force HTTP/1.1).")
@click.option(
    "--no-verify-ssl", is_flag=True, help="Skip TLS certificate verification."
)
# --- 0.5.1: these three toggle the correctness-sensitive/best-effort
# detection features added in core.py — off by default since they add
# per-request overhead (extra dict lookups, session-id bookkeeping) that
# isn't worth paying for on a pure throughput/sustained run unless the
# person actually wants the data.
@click.option(
    "--enable-connection-reuse",
    is_flag=True,
    help="DEPRECATED: no effect. Connection reuse is always tracked.",
)
@click.option(
    "--enable-tls-resumption",
    is_flag=True,
    help="Best-effort TLS session resumption detection (item 6) — "
    "heuristic based on repeated session IDs, not a certainty.",
)
@click.option(
    "--enable-push-detection",
    is_flag=True,
    help="Best-effort HTTP/2 server push detection (item 8) — requires the "
    "optional 'h2' package; silently reports zero pushes if unavailable.",
)
@click.option(
    "--output",
    "-o",
    default="./http_load_test_results",
    show_default=True,
    help="Output directory for results.",
)
@click.option(
    "--formats",
    "-f",
    default="csv,excel",
    show_default=True,
    help="Output formats (csv, excel, pdf, json).",
)
@click.option(
    "--include-charts", is_flag=True, help="Include charts in Excel and PDF exports."
)
# --- 0.5.2 ------------------------
@click.option(
    "--max-connections",
    type=int,
    default=None,
    help="Connection-pool size (default: --max-concurrent). Requests beyond "
    "this queue inside the pool and are reported as blocked_ms.",
)
@click.option(
    "--no-phase-trace",
    is_flag=True,
    help="Disable per-request phase timings (blocked/sending/waiting). "
    "Removes a small per-event callback cost; blocked_ms and waiting_ms "
    "become unavailable.",
)
# --- load-shaping and safety controls -------------------------------
@click.option(
    "--max-backlog",
    type=int,
    default=None,
    help="Sustained mode: how many scheduled requests may wait for a free "
    "worker before further fires are DROPPED and counted (default: one per "
    "worker). Dropping rather than queueing is what keeps the reported "
    "latency honest when the target cannot keep up.",
)
@click.option(
    "--graceful-stop",
    default=30.0,
    show_default=True,
    help="Seconds to let in-flight requests finish after the run ends, "
    "before cancelling them. Prevents one hung request from hanging the "
    "whole run.",
)
@click.option(
    "--no-retain-results",
    is_flag=True,
    help="Drop per-request results from the summary once statistics and "
    "intervals are computed. Statistics are unaffected, but raw-result "
    "exports (CSV raw, per-target Excel sheets) will be empty.",
)
@click.option(
    "--live",
    is_flag=True,
    help="Print each one-second interval as it completes, instead of only "
    "at the end.",
)
# --- 0.5.2: interpretation controls ----------------------------------------
@click.option(
    "--expected-status",
    default=None,
    help="Status codes treated as expected, e.g. '200,404' or '200-299,401'. "
    "Default 200-399.",
)
@click.option(
    "--threshold",
    "thresholds",
    multiple=True,
    help="Pass/fail criterion, e.g. 'p95_latency<500', 'dropped_rate<1', "
    "'error_rate<=1'. Repeatable. Any failure exits with code 1. Load-test "
    "metrics also include achieved_rps, p95_duration_ms, avg_blocked_ms, "
    "avg_waiting_ms, p95_waiting_ms, max_queue_delay_ms, "
    "transport_error_rate, received_bytes_per_s.",
)
# --- 0.5.2: local multi-process load generation ----------------------------
@click.option(
    "--workers",
    type=int,
    default=1,
    show_default=True,
    help="Generate the load from N separate PROCESSES on this machine, "
    "started in sync and merged at the end. Above 1 this is what escapes the "
    "single-process ceiling (GIL, one event loop). Concurrency options are "
    "PER WORKER, so --workers 4 --max-concurrency 50 is 200 in flight; --rps "
    "is the TOTAL and is split across workers.",
)
@click.option(
    "--worker-id",
    default=None,
    help="Label prefix for this generator's workers, carried into the merged "
    "result's per-worker breakdown. Defaults to local-<pid>.",
)
@click.option(
    "--start-at",
    type=float,
    default=None,
    help="Absolute Unix epoch (seconds, UTC) at which to begin. This is the "
    "CROSS-MACHINE start barrier: give every node the same value and they "
    "start together and share one timeline. Mutually exclusive with "
    "--start-delay.",
)
@click.option(
    "--start-delay",
    type=float,
    default=None,
    help="Begin this many seconds from now — a --start-at you do not have to "
    "compute. Prints the resulting epoch so the other nodes can be given it.",
)
@click.option(
    "--warmup",
    type=int,
    default=0,
    show_default=True,
    help="Requests to issue per target BEFORE the start barrier, to open "
    "connections. Without it a synchronised start is a synchronised COLD "
    "start and the first seconds measure TLS handshakes. Warmup results are "
    "discarded and its connections are excluded from the reuse figures.",
)
@click.option(
    "--interval-bucket",
    type=float,
    default=1.0,
    show_default=True,
    help="Width of one timeline bucket, in seconds. Workers that will be "
    "merged together MUST agree on this — merging mismatched widths is "
    "refused, because window_index then means a different number of seconds "
    "on each side.",
)
@click.option(
    "--emit-summary",
    default=None,
    help="Write this run's summaries as JSON to PATH ('-' for stdout), for a "
    "collector to merge later with `http merge-load-test`. This is the "
    "cross-machine path: same --start-at on every node, then merge the "
    "emitted files.",
)
@click.option(
    "--target-distribution",
    type=click.Choice([d.value for d in TargetDistribution]),
    default=TargetDistribution.REPLICATE.value,
    show_default=True,
    help="With --workers > 1 and several targets: 'replicate' runs every "
    "target in every worker, so N workers offer N times the concurrency to "
    "EACH target (use this to saturate one origin). 'shard' deals targets "
    "round-robin, so each target is driven by one worker and the load per "
    "target is unchanged (use this to get more targets done in parallel). "
    "Under 'shard' --rps is the rate PER TARGET and is not divided.",
)
@click.option(
    "--region",
    default=None,
    help="Label for where this generator runs (e.g. 'hel1'). Recorded per "
    "worker so a merged run stays attributable to its origin.",
)
@click.option("--json", "json_output", is_flag=True, help="Export results to JSON.")
@click.option("--quiet", is_flag=True, help="Suppress progress output.")
def load_test(
    targets: Optional[str],
    use_defaults: bool,
    mode: str,
    duration: float,
    rps: Optional[float],
    max_concurrency: int,
    start_concurrency: int,
    ramp_concurrency: int,
    ramp_duration: float,
    hold_duration: float,
    max_total_rps: Optional[float],
    method: str,
    headers: Optional[str],
    timeout: float,
    no_http2: bool,
    no_verify_ssl: bool,
    enable_connection_reuse: bool,
    enable_tls_resumption: bool,
    enable_push_detection: bool,
    output: str,
    formats: str,
    include_charts: bool,
    max_connections: Optional[int],
    no_phase_trace: bool,
    max_backlog: Optional[int],
    graceful_stop: float,
    no_retain_results: bool,
    live: bool,
    expected_status: Optional[str],
    thresholds: Tuple[str, ...],
    workers: int,
    worker_id: Optional[str],
    region: Optional[str],
    target_distribution: str,
    start_at: Optional[float],
    start_delay: Optional[float],
    warmup: int,
    interval_bucket: float,
    emit_summary: Optional[str],
    json_output: bool,
    quiet: bool,
) -> None:
    """Run a load test against one or more targets — throughput, sustained
    rate, or ramp-up (0.5.1). Multiple targets run concurrently.

    Examples:
        net-benchmark http load-test -t https://example.com --mode throughput --duration 15
        net-benchmark http load-test -t a.com,b.com --mode sustained --rps 50 --duration 30
        net-benchmark http load-test --use-defaults --mode ramp-up \\
            --start-concurrency 5 --ramp-concurrency 100 --ramp-duration 20 --hold-duration 10
    """
    if not use_defaults and not targets:
        click.echo(error("Provide --targets or use --use-defaults."))
        return

    try:
        target_list = (
            TargetManager.get_default_targets()
            if use_defaults
            else TargetManager.parse_targets_input(targets).targets
        )
    except Exception as e:
        click.echo(error(f"Error loading targets: {e}"))
        return

    # --- 0.5.1: normalize each target the same way `compare` does, so bare
    # hostnames work without forcing the person to type https://.
    target_list = [
        t if t.startswith(("http://", "https://")) else "https://" + t
        for t in (t.strip() for t in target_list)
    ]

    # 0.5.2 — parse these BEFORE running anything. A malformed --threshold or
    # --expected-status should fail immediately, not after a 60-second run.
    parsed_thresholds = _parse_thresholds(thresholds)
    expected_statuses = _parse_expected_statuses(expected_status)

    mode_normalized = mode.lower().replace("-", "_")  # "ramp-up" -> "ramp_up"

    if mode_normalized == "sustained" and not rps:
        click.echo(error("--mode sustained requires --rps."))
        return
    # --- 0.5.2: validated before anything runs, like the thresholds above.
    if workers < 1:
        click.echo(error("--workers must be >= 1."))
        return

    if start_at is not None and start_delay is not None:
        click.echo(error("Use --start-at or --start-delay, not both."))
        return
    if start_delay is not None:
        start_at = time.time() + start_delay
    if start_at is not None and not quiet:
        # Printed so the value can be pasted onto the other nodes. Sub-second
        # precision matters: rounding to a whole second would put the nodes'
        # barriers up to a second apart, which is a whole interval bucket.
        click.echo(info(f"  Start barrier: {start_at:.3f} (epoch seconds, UTC)"))
    if workers > 1 and live:
        # The interval callback is a Python closure; it cannot be pickled into
        # a spawned child. Said out loud rather than silently printing nothing.
        click.echo(warning("--live has no effect with --workers > 1; ignoring it."))

    output_formats = [f.strip().lower() for f in formats.split(",")]
    allowed = {"csv", "excel", "pdf", "json"}
    for fmt in output_formats:
        if fmt not in allowed:
            click.echo(
                error(f"Invalid format '{fmt}'. Must be csv, excel, pdf, or json.")
            )
            return
    if "json" in output_formats:
        json_output = True

    output_path = Path(output)
    output_path.mkdir(parents=True, exist_ok=True)

    extra_headers: Dict[str, str] = {}
    if headers:
        for pair in headers.split(","):
            if ":" in pair:
                k, _, v = pair.partition(":")
                extra_headers[k.strip()] = v.strip()

    if not quiet:
        click.echo(info("Configuration:"))
        click.echo(info(f"  Targets:      {len(target_list)}"))
        click.echo(info(f"  Mode:         {mode_normalized}"))
        if mode_normalized == "throughput":
            click.echo(info(f"  Duration:     {duration}s"))
            click.echo(info(f"  Max conc.:    {max_concurrency}"))
        elif mode_normalized == "sustained":
            click.echo(info(f"  Duration:     {duration}s"))
            click.echo(info(f"  Target RPS:   {rps}"))
        else:  # ramp_up
            click.echo(
                info(f"  Concurrency:  {start_concurrency} -> {ramp_concurrency}")
            )
            click.echo(info(f"  Ramp:         {ramp_duration}s, hold {hold_duration}s"))
            if max_total_rps:
                click.echo(info(f"  Max total RPS ceiling: {max_total_rps}"))
        click.echo(
            info(
                f"  TLS resumption detection:  {'on' if enable_tls_resumption else 'off'}"
            )
        )
        click.echo(
            info(
                f"  HTTP/2 push detection:     {'on' if enable_push_detection else 'off'}"
            )
        )
        if enable_connection_reuse:
            click.echo(
                warning("--enable-connection-reuse is deprecated and has no effect.")
            )
        click.echo(info("  Connection reuse tracking: always on"))
        click.echo(warning(f"Starting load test ({mode_normalized})…"))

    start_wall = time.time()

    try:
        # --- 0.5.1: one HTTPBenchmarkEngine + LoadTestEngine per target
        # (each origin gets its own connection pool, per core.py's design),
        # all run concurrently via asyncio.gather.
        #
        # --- 0.5.2: the run is described once, as a WorkerConfig, and
        # distributed.py builds the engines from it — for the local run and for
        # every spawned worker alike.
        #
        # This block used to construct HTTPBenchmarkEngine and LoadTestEngine
        # inline (`_run_one`). Once a distributed path existed, that made the
        # mapping from CLI options to engine arguments exist in two places, and
        # the two would drift: a new option wired up here would silently not
        # apply under --workers > 1, which is the worst kind of drift because
        # the run still succeeds and just measures something else.
        worker_config = WorkerConfig(
            targets=target_list,
            mode=mode_normalized,
            duration_s=duration,
            # The TOTAL offered rate. run_distributed decides how it divides,
            # which depends on the topology — see TargetDistribution.
            target_rps=rps,
            max_concurrency=max_concurrency,
            max_backlog=max_backlog,
            start_concurrency=start_concurrency,
            ramp_concurrency=ramp_concurrency,
            ramp_duration_s=ramp_duration,
            hold_duration_s=hold_duration,
            max_total_rps=max_total_rps,
            graceful_stop_s=graceful_stop,
            method=method.upper(),
            headers=extra_headers,
            timeout=timeout,
            http2=not no_http2,
            verify_ssl=not no_verify_ssl,
            max_connections=max_connections,
            enable_phase_trace=not no_phase_trace,
            enable_tls_resumption=enable_tls_resumption,
            enable_push_detection=enable_push_detection,
            expected_statuses=(
                sorted(expected_statuses) if expected_statuses else None
            ),
            start_epoch=start_at,
            warmup_requests=warmup,
            interval_bucket_s=interval_bucket,
            worker_id=worker_id,
            region=region,
            # Unchanged from the pre-0.5.2 behaviour for a local run. Workers
            # override this to False: per-request rows are the one thing you do
            # not want N processes pickling back to the parent, so with
            # --workers > 1 the raw CSV and per-target Excel sheets are empty
            # regardless. Every statistic, interval and histogram survives.
            retain_results=not no_retain_results,
        )

        # --- 0.5.2: one live-printing callback per target, built here because
        # a closure cannot cross a process boundary. In-process only; --workers
        # > 1 refuses --live above rather than silently printing nothing.
        interval_factory: Optional[
            Callable[[str], Optional[Callable[["IntervalStats"], None]]]
        ] = None
        if live and not quiet:

            def _make_interval_cb(
                t: str,
            ) -> Optional[Callable[["IntervalStats"], None]]:
                short = t.replace("https://", "").replace("http://", "")[:28]

                def _print_interval(iv: "IntervalStats", _label: str = short) -> None:
                    st = iv.stats
                    click.echo(
                        info(
                            f"  [{_label}] t={iv.window_index:>3}s "
                            f"req={st.total_requests:>5} "
                            f"ok={st.success_rate:5.1f}% "
                            f"avg={st.avg_latency:7.1f}ms "
                            f"p95={st.p95_latency:7.1f}ms "
                            f"wait={st.avg_waiting_ms:7.1f}ms "
                            f"blocked={st.avg_blocked_ms:6.1f}ms"
                        )
                    )

                return _print_interval

            interval_factory = _make_interval_cb

        distributed_results: List[DistributedResult] = []
        # --- 0.5.2: kept so the exporters can write the per-worker breakdown
        # alongside the merged summary.
        worker_summaries: List["LoadTestSummary"] = []
        if workers > 1:
            distributed_results = run_distributed(
                replace(worker_config, retain_results=False),
                workers=workers,
                distribution=TargetDistribution(target_distribution),
                on_warning=lambda msg: click.echo(warning(msg)),
            )
            summaries = [r.merged for r in distributed_results]
            worker_summaries = [
                w.summary for r in distributed_results for w in r.workers
            ]
        else:
            summaries = list(
                asyncio.run(run_worker_async(worker_config, interval_factory))
            )

        wall_elapsed = time.time() - start_wall
        if not quiet:
            click.echo(success(f"Load test completed in {wall_elapsed:.2f}s"))
            # --- 0.5.1: summary.stats is a TargetStats (net_benchmark.http_bench.analysis)
            # — same stats engine as `http benchmark`. success_rate and
            # connection_reuse_rate are already 0-100 (percentages); TargetStats
            # has no p50/p90 fields — median_latency is the p50 equivalent.
            for summary in summaries:
                summary_lines = [
                    f"Target:           {summary.target}",
                    f"Mode:             {summary.mode.value}",
                    f"Total requests:   {summary.stats.total_requests}",
                    # --- 0.5.2: same reason as the benchmark box. Without this
                    # line "Successful: 0 (0.00%)" sits directly above a real
                    # median and p95, which reads as a contradiction. Responded
                    # is the sample count those latencies were computed from.
                    f"Responded:        {summary.stats.responded_requests}",
                    f"Successful:       {summary.stats.successful_requests} ({summary.stats.success_rate:.2f}%)",
                    f"Achieved RPS:     {summary.achieved_rps:.1f}",
                ]
                if summary.target_rps:
                    summary_lines.append(f"Target RPS:       {summary.target_rps:.1f}")
                summary_lines += [
                    f"Median latency:   {summary.stats.median_latency:.1f} ms",
                    f"P95 latency:      {summary.stats.p95_latency:.1f} ms",
                    f"P99 latency:      {summary.stats.p99_latency:.1f} ms",
                ]
                # --- 0.5.2: phase split. p95_latency above includes connection
                # setup on whichever requests happened to open a connection,
                # so it partly tracks the reuse ratio; p95 duration does not.
                # --- 0.5.2: p95_duration_ms does not survive a merge —
                # _merge_target_stats leaves it at 0.0 because no arithmetic
                # recovers a phase percentile from per-worker summaries. It was
                # still PRINTED as "0.0 ms", directly above the line saying the
                # phase p95s are not merged: the same misleading zero the
                # namespace gate exists to prevent, one layer up.
                if summary.merged:
                    summary_lines.append(
                        "P95 duration:     n/a (not merged — read it per worker)"
                    )
                else:
                    summary_lines.append(
                        f"P95 duration:     {summary.stats.p95_duration_ms:.1f} ms"
                        " (excl. setup)"
                    )
                # --- 0.5.2: blocked_ms is the wait on the HTTPBenchmarkEngine's
                # own max_concurrent semaphore. In a load test the worker pool
                # is what bounds concurrency, so that semaphore is normally
                # uncontended and this is ~0 — client-side queueing shows up as
                # queue delay below instead. Printed only when it is actually
                # non-zero, so it doesn't read as "no queueing anywhere".
                # --- 0.5.2: the pool-vs-server split. `waiting` is the target's
                # own response time with local queueing excluded; `blocked` is
                # time spent waiting for a connection from the pool. Blocked
                # high while waiting stays flat means this machine saturated
                # and the run stopped measuring the target.
                if summary.stats.avg_waiting_ms > 0:
                    summary_lines.append(
                        f"Avg waiting:      {summary.stats.avg_waiting_ms:.1f} ms"
                        " (server)"
                    )
                if summary.stats.avg_blocked_ms > 0.05:
                    note = ""
                    if (
                        summary.stats.avg_waiting_ms > 0
                        and summary.stats.avg_blocked_ms > summary.stats.avg_waiting_ms
                    ):
                        note = "  <- generator is the bottleneck, not the target"
                    summary_lines.append(
                        f"Avg blocked:      {summary.stats.avg_blocked_ms:.1f} ms"
                        f" (pool queue){note}"
                    )
                # --- 0.5.2: only worth showing when the pacer actually fell
                # behind — on a healthy run these are all zero and just add
                # noise.
                c = summary.counters
                if c.dropped:
                    summary_lines.append(
                        f"Dropped:          {c.dropped} of {c.scheduled}"
                        f" ({summary.dropped_rate:.1f}%) — target could not"
                        " keep up"
                    )
                if c.max_queue_delay_ms > 0:
                    summary_lines.append(
                        f"Queue delay:      avg {c.avg_queue_delay_ms:.1f} ms,"
                        f" max {c.max_queue_delay_ms:.1f} ms"
                    )
                if c.interrupted:
                    summary_lines.append(f"Interrupted:      {c.interrupted}")
                if c.worker_errors:
                    summary_lines.append(
                        f"Worker errors:    {c.worker_errors} — concurrency was"
                        " reduced mid-run"
                    )
                if summary.stats.transport_error_rate > 0:
                    summary_lines.append(
                        f"Transport errors: {summary.stats.transport_error_rate:.2f}%"
                    )
                if summary.stats.unexpected_status_rate > 0:
                    summary_lines.append(
                        "Unexpected status:"
                        f" {summary.stats.unexpected_status_rate:.2f}%"
                    )

                summary_lines += [
                    f"Received:         {summary.received_bytes_per_s / 1024:.0f} KB/s",
                    f"Connections open: {summary.connection_reuse.connections_opened}",
                ]
                # --- 0.5.2: always shown. Reuse is tracked unconditionally in
                # core.py now (the connect/handshake attribution depends on
                # it), so gating the display on --enable-connection-reuse hid
                # a number that had already been computed.
                summary_lines.append(
                    f"Reuse rate:       {summary.connection_reuse.reuse_rate * 100:.1f}%"
                )
                if enable_tls_resumption:
                    summary_lines.append(
                        f"TLS resumption:   {summary.stats.tls_resumption_rate:.1f}%"
                    )

                # --- 0.5.2: provenance for a merged run. Without these lines a
                # distributed summary reads exactly like a single-process one,
                # including in the ways that matter: how many workers it came
                # from, and which numbers are structurally absent rather than
                # measured.
                if summary.merged:
                    result = next(
                        (r for r in distributed_results if r.target == summary.target),
                        None,
                    )
                    if result is not None:
                        summary_lines.append(
                            f"Workers merged:   {result.worker_count}"
                            f"  [{', '.join(w.worker_id for w in result.workers)}]"
                        )

                    if summary.start_offset_s > 0.05:
                        # --- 0.5.2: a synchronised run that was not actually
                        # synchronised. The shared window has a gap at the
                        # front that no worker covered.
                        summary_lines.append(
                            f"Worst start skew: {summary.start_offset_s * 1000:.0f}"
                            " ms — the shared window opens before the slowest"
                            " worker did"
                        )

                    summary_lines.append(
                        "Not merged:       std/jitter/consistency and the phase"
                        " p95s — read those per worker"
                    )

                click.echo(summary_box(summary_lines))

            # --- 0.5.2: a dead worker offered none of its share. Reported
            # loudly: a merged summary from a run that lost half its processes
            # otherwise reads as a target that coped comfortably.
            for result in distributed_results:
                for failure in result.failures:
                    click.echo(
                        error(
                            f"{result.target}: worker failed ({failure}) — the"
                            " offered load was lower than requested"
                        )
                    )

        # --- 0.5.2: the cross-machine path. Emitting the wire payload is all a
        # node has to do; `http merge-load-test` on the collector turns N of
        # these into one correct summary. Written before the exporters so a
        # node used purely as a generator still produces the one artifact that
        # matters even if its own exports are turned off.
        if emit_summary:
            payload = [s.to_dict() for s in summaries]
            if emit_summary == "-":
                click.echo(json.dumps(payload, default=str))
            else:
                with open(emit_summary, "w", encoding="utf-8") as fh:
                    json.dump(payload, fh, default=str)
                if not quiet:
                    click.echo(success(f"Worker summary written to: {emit_summary}"))

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = f"net_benchmark.load_test_{mode_normalized}_{timestamp}"

        if not quiet:
            click.echo(warning("Exporting results…"))

        if "csv" in output_formats:
            LoadTestCSVExporter.export_raw_results(
                summaries, str(output_path / f"{base_name}_raw.csv")
            )
            LoadTestCSVExporter.export_summary(
                summaries, str(output_path / f"{base_name}_summary.csv")
            )
            # --- 0.5.2: the per-worker rows behind the merged one. Same
            # exporter, so the columns line up and the two files concatenate;
            # the worker_id/merged columns tell them apart. This is where the
            # un-mergeable fields still have real values.
            if worker_summaries:
                LoadTestCSVExporter.export_summary(
                    worker_summaries, str(output_path / f"{base_name}_workers.csv")
                )
            LoadTestCSVExporter.export_intervals(
                summaries, str(output_path / f"{base_name}_timeline.csv")
            )
            LoadTestCSVExporter.export_error_breakdown(
                summaries, str(output_path / f"{base_name}_errors.csv")
            )
            # --- 0.5.2: mergeable histogram buckets. This is the artifact a
            # distributed run folds together; percentiles cannot be averaged.
            # --- 0.5.2: per-worker histograms as well as the merged one, so
            # the merge can be re-derived (or re-checked) from the CSV alone.
            export_latency_histograms(
                summaries + worker_summaries, str(output_path), base_name
            )

        if "excel" in output_formats:
            LoadTestExcelExporter.export_results(
                summaries,
                str(output_path / f"{base_name}.xlsx"),
                include_charts=include_charts,
            )

        if "pdf" in output_formats:
            try:
                LoadTestPDFExporter.export_results(
                    summaries,
                    str(output_path / f"{base_name}.pdf"),
                    include_charts=include_charts,
                )
            except Exception as e:
                click.echo(error(f"PDF export failed: {e}"))

        if json_output:
            LoadTestExportBundle.export_json(
                summaries, str(output_path / f"{base_name}.json")
            )
            if not quiet:
                click.echo(success("JSON export completed!"))

        if not quiet:
            click.echo(success("All exports completed!"))
            click.echo(info(f"Results saved to: {output_path}"))

        # -- 0.5.2: threshold gate, after exports so a failing run still leaves
        # its artifacts behind. Non-zero exit is what makes this a CI step.
        if parsed_thresholds:
            report = {
                summary.target: summary.check_thresholds(parsed_thresholds)
                for summary in summaries
            }
            # --- 0.5.2: see the benchmark path.
            try:
                HTTPExportBundle.export_threshold_results(
                    report, str(output_path), base_name
                )
            except OSError as exc:
                click.echo(warning(f"Could not write thresholds CSV: {exc}"))
            all_ok = True
            for target_url, target_results in report.items():
                if not _report_thresholds(target_url, target_results, quiet):
                    all_ok = False
            if not all_ok:
                click.echo(error("Thresholds failed."))
                raise SystemExit(1)

    except click.UsageError:
        raise
    except KeyboardInterrupt:
        click.echo(warning("\nLoad test interrupted by user"))
    except Exception as e:
        click.echo(error(f"Load test error: {e}"))
        raise


# ── merge-load-test ────────────────────────────────────────────────────────
# --- 0.5.2: the collector half of a cross-machine run. Each node runs
# `load-test --start-at <shared epoch> --emit-summary node.json`; this folds
# those files into one summary and runs the ordinary exporters and thresholds
# over it, so a distributed result is consumed by exactly the same code as a
# local one.
@http.command(name="merge-load-test")
@click.argument("payloads", nargs=-1, required=True, type=click.Path(exists=True))
@click.option(
    "--output",
    "-o",
    default="./http_load_test_results",
    show_default=True,
    help="Output directory for merged results.",
)
@click.option(
    "--formats",
    "-f",
    default="csv,json",
    show_default=True,
    help="Output formats (csv, excel, pdf, json).",
)
@click.option(
    "--threshold",
    "thresholds",
    multiple=True,
    help="Pass/fail criterion evaluated against the MERGED summary. Note that "
    "std_latency, jitter, consistency_score and the phase p95s do not survive "
    "a merge and are rejected here as unknown metrics — evaluate those per "
    "worker. p95_latency/p99_latency DO survive: they are recomputed from the "
    "merged histogram.",
)
@click.option("--json", "json_output", is_flag=True, help="Export results to JSON.")
@click.option("--quiet", is_flag=True, help="Suppress progress output.")
def merge_load_test(
    payloads: Tuple[str, ...],
    output: str,
    formats: str,
    thresholds: Tuple[str, ...],
    json_output: bool,
    quiet: bool,
) -> None:
    """Merge worker summaries from a distributed load test into one result.

    Percentiles are recomputed from the merged latency histograms, never
    averaged — averaging P95s across workers does not give the P95 of their
    union, and no arithmetic recovers it.

    Examples:
        net-benchmark http merge-load-test hel1.json ash.json sin.json
        net-benchmark http merge-load-test nodes/*.json --threshold 'p95_latency<500'
    """
    parsed_thresholds = _parse_thresholds(thresholds)
    output_formats = [f.strip().lower() for f in formats.split(",") if f.strip()]
    for fmt in output_formats:
        if fmt not in {"csv", "excel", "pdf", "json"}:
            click.echo(error(f"Invalid format '{fmt}'."))
            return

    if "json" in output_formats:
        json_output = True

    # --- 0.5.2: reading and merging are separate try blocks. They used to
    # share one, with the merge handler first — and json.JSONDecodeError
    # subclasses ValueError, so a truncated payload file was reported as
    # "Cannot merge: ...", blaming the merge logic for a bad file.

    try:
        payload_dicts = load_payload_files(list(payloads))
    except (OSError, ValueError) as exc:
        click.echo(error(f"Could not read payloads: {exc}"))
        raise SystemExit(2)
    try:
        results = merge_payloads(payload_dicts)
    except ValueError as exc:
        # merge_summaries refuses mismatched modes, targets, epochs, bucket
        # widths and measured clock skew. Every one of those means the inputs
        # do not describe one run, and a number produced anyway would look
        # perfectly plausible.
        click.echo(error(f"Cannot merge: {exc}"))
        raise SystemExit(2)

    output_path = Path(output)
    output_path.mkdir(parents=True, exist_ok=True)
    summaries = [r.merged for r in results]
    worker_summaries = [w.summary for r in results for w in r.workers]

    if not quiet:
        for result in results:
            merged = result.merged
            lines = [
                f"Target:           {result.target}",
                f"Workers merged:   {result.worker_count}"
                f"  [{', '.join(merged.merged_from)}]",
                f"Window:           {merged.duration_s:.2f}s (shared wall clock)",
                f"Total requests:   {merged.stats.total_requests}",
                f"Responded:        {merged.stats.responded_requests}",
                # --- 0.5.2: the box reported volume and latency but no
                # OUTCOME, so a merged run in which a third of the requests
                # were rejected read as a clean result. Success rate survives a
                # merge exactly — it is recomputed from the summed numerator
                # and denominator — so there is no reason to omit it.
                f"Successful:       {merged.stats.successful_requests}"
                f" ({merged.stats.success_rate:.2f}%)",
                f"Achieved RPS:     {merged.achieved_rps:.1f}",
                f"Median latency:   {merged.stats.median_latency:.1f} ms",
                f"P95 latency:      {merged.stats.p95_latency:.1f} ms"
                " (from merged histogram)",
                f"P99 latency:      {merged.stats.p99_latency:.1f} ms"
                " (from merged histogram)",
            ]
            # --- 0.5.2: shown only when non-zero, like the load-test box.
            # This is the line that names an upstream rate limit outright
            # instead of leaving it to be inferred from the success rate.
            if merged.stats.unexpected_status_rate > 0:
                lines.append(
                    f"Unexpected status: {merged.stats.unexpected_status_rate:.2f}%"
                )
            if merged.stats.transport_error_rate > 0:
                lines.append(
                    f"Transport errors: {merged.stats.transport_error_rate:.2f}%"
                )
            if merged.start_offset_s > 0.05:
                lines.append(f"Worst start skew: {merged.start_offset_s * 1000:.0f} ms")
            click.echo(summary_box(lines))
            if merged.stats.latency_overflow_count:
                click.echo(
                    warning(
                        f"{merged.stats.latency_overflow_count} latencies exceeded"
                        " the histogram range — the tail is truncated and p99"
                        " understates it"
                    )
                )

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_name = f"net_benchmark.load_test_merged_{timestamp}"

    if "csv" in output_formats:
        LoadTestCSVExporter.export_summary(
            summaries, str(output_path / f"{base_name}_summary.csv")
        )
        LoadTestCSVExporter.export_summary(
            worker_summaries, str(output_path / f"{base_name}_workers.csv")
        )
        LoadTestCSVExporter.export_intervals(
            summaries, str(output_path / f"{base_name}_timeline.csv")
        )
        LoadTestCSVExporter.export_error_breakdown(
            summaries, str(output_path / f"{base_name}_errors.csv")
        )
        export_latency_histograms(
            summaries + worker_summaries, str(output_path), base_name
        )
    if "excel" in output_formats:
        LoadTestExcelExporter.export_results(
            summaries, str(output_path / f"{base_name}.xlsx")
        )
    if "pdf" in output_formats:
        try:
            LoadTestPDFExporter.export_results(
                summaries, str(output_path / f"{base_name}.pdf")
            )
        except Exception as exc:
            click.echo(error(f"PDF export failed: {exc}"))
    if json_output:
        LoadTestExportBundle.export_json(
            summaries, str(output_path / f"{base_name}.json")
        )
        if not quiet:
            click.echo(success("JSON export completed!"))

    if not quiet:
        click.echo(success(f"Merged results saved to: {output_path}"))

    if parsed_thresholds:
        all_ok = True
        for merged in summaries:
            if not _report_thresholds(
                merged.target, merged.check_thresholds(parsed_thresholds), quiet
            ):
                all_ok = False
        if not all_ok:
            click.echo(error("Thresholds failed."))
            raise SystemExit(1)


# alias for backward compatibility with tests and old scripts
cli = http
