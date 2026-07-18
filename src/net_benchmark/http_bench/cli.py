"""HTTP benchmarking CLI."""

import asyncio
import json
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import click
from colorama import Fore, Style

from net_benchmark.dns_benchmark.core import QueryStatus
from net_benchmark.http_bench.analysis import HTTPAnalyzer
from net_benchmark.http_bench.core import HTTPBenchmarkEngine, HTTPResult, TargetManager
from net_benchmark.http_bench.exporters import (
    HTTPCSVExporter,
    HTTPExcelExporter,
    HTTPExportBundle,
    HTTPPDFExporter,
)
from net_benchmark.http_bench.load_test import LoadTestEngine, LoadTestSummary
from net_benchmark.http_bench.load_test_exporters import (
    LoadTestCSVExporter,
    LoadTestExcelExporter,
    LoadTestExportBundle,
    LoadTestPDFExporter,
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
@click.option("--json", "json_output", is_flag=True, help="Export results to JSON.")
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
        analyzer = HTTPAnalyzer(results)
        overall = analyzer.get_overall_statistics()

        if not quiet:
            summary_lines = [
                f"Total requests:   {overall['total_requests']}",
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

    ranked = sorted(
        [s for s in stats if s.successful_requests > 0],
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
    help="Alert when failure rate exceeds N% (0 = disabled).",
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
                    max_concurrent=20, timeout=10.0, max_retries=1
                )
                res = await engine.run_benchmark(target_list, iterations=1)
                await engine.close()
                return res

            results = asyncio.run(_run())
            analyzer = HTTPAnalyzer(results)
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
            failure_rate = 100.0 - overall["overall_success_rate"]
            if alert_failure_rate and failure_rate > alert_failure_rate:
                click.echo(
                    warning(
                        f"ALERT: failure rate {failure_rate:.1f}% "
                        f"> threshold {alert_failure_rate:.1f}%"
                    )
                )

            # ── persist snapshot ──────────────────────────────────────────────
            snapshot_path = (
                output_path
                / f"http_monitor_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            )
            with open(snapshot_path, "w") as f:
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

        # Sort by avg_latency (only successful)
        valid = [s for s in target_stats if s.successful_requests > 0]
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
                with open(output_path, "w") as f:
                    json.dump(data, f, indent=2)
            elif ext == ".csv":
                HTTPCSVExporter.export_summary_statistics(analyzer, str(output_path))
            else:  # .txt
                with open(output_path, "w") as f:
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
    help="Track keep-alive / connection reuse rate (item 4).",
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

    mode_normalized = mode.lower().replace("-", "_")  # "ramp-up" -> "ramp_up"

    if mode_normalized == "sustained" and not rps:
        click.echo(error("--mode sustained requires --rps."))
        return

    output_formats = [f.strip().lower() for f in formats.split(",")]
    for fmt in output_formats:
        if fmt not in ("csv", "excel", "pdf", "json"):
            click.echo(
                error(f"Invalid format '{fmt}'. Must be csv, excel, pdf, or json.")
            )
            return

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
                f"  Connection reuse tracking: {'on' if enable_connection_reuse else 'off'}"
            )
        )
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
        click.echo(warning(f"Starting load test ({mode_normalized})…"))

    start_wall = time.time()

    try:
        # --- 0.5.1: one HTTPBenchmarkEngine + LoadTestEngine per target
        # (each origin gets its own connection pool, per core.py's design),
        # all run concurrently via asyncio.gather.
        async def _run_one(t: str) -> "LoadTestSummary":
            http_engine = HTTPBenchmarkEngine(
                max_concurrent=max(max_concurrency, ramp_concurrency, 50),
                timeout=timeout,
                method=method.upper(),
                headers=extra_headers,
                http2=not no_http2,
                verify_ssl=not no_verify_ssl,
                enable_connection_reuse=enable_connection_reuse,
                enable_tls_resumption=enable_tls_resumption,
                enable_push_detection=enable_push_detection,
            )
            load_engine = LoadTestEngine(t, http_engine=http_engine)
            if mode_normalized == "throughput":
                s = await load_engine.run_throughput(
                    duration_s=duration, max_concurrency=max_concurrency
                )
            elif mode_normalized == "sustained":
                # type narrowing: we already validated that --rps is present when
                # mode == "sustained" (see the check above), so mypy would otherwise
                # complain that `rps` might be None.  The assertion removes that
                # ambiguity at static‑analysis level and also acts as a safety net
                # in case someone later moves the validation without adjusting this path.
                assert rps is not None, "rps must be set for sustained mode"
                s = await load_engine.run_sustained(target_rps=rps, duration_s=duration)
            else:  # ramp_up
                s = await load_engine.run_ramp_up(
                    start_concurrency=start_concurrency,
                    max_concurrency=ramp_concurrency,
                    ramp_duration_s=ramp_duration,
                    hold_duration_s=hold_duration,
                    max_total_rps=max_total_rps,
                )
            await load_engine.close()
            return s

        async def _run_all() -> List["LoadTestSummary"]:
            return await asyncio.gather(*(_run_one(t) for t in target_list))

        summaries = list(asyncio.run(_run_all()))

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
                    f"Successful:       {summary.stats.successful_requests} ({summary.stats.success_rate:.2f}%)",
                    f"Achieved RPS:     {summary.achieved_rps:.1f}",
                ]
                if summary.target_rps:
                    summary_lines.append(f"Target RPS:       {summary.target_rps:.1f}")
                summary_lines += [
                    f"Median latency:   {summary.stats.median_latency:.1f} ms",
                    f"P95 latency:      {summary.stats.p95_latency:.1f} ms",
                    f"P99 latency:      {summary.stats.p99_latency:.1f} ms",
                    f"Connections open: {summary.connection_reuse.connections_opened}",
                ]
                if enable_connection_reuse:
                    summary_lines.append(
                        f"Reuse rate:       {summary.connection_reuse.reuse_rate * 100:.1f}%"
                    )
                if enable_tls_resumption:
                    summary_lines.append(
                        f"TLS resumption:   {summary.stats.tls_resumption_rate:.1f}%"
                    )
                click.echo(summary_box(summary_lines))

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
            LoadTestCSVExporter.export_intervals(
                summaries, str(output_path / f"{base_name}_timeline.csv")
            )
            LoadTestCSVExporter.export_error_breakdown(
                summaries, str(output_path / f"{base_name}_errors.csv")
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

        if "json" in output_formats:
            LoadTestExportBundle.export_json(
                summaries, str(output_path / f"{base_name}.json")
            )

        if not quiet:
            click.echo(success("All exports completed!"))
            click.echo(info(f"Results saved to: {output_path}"))

    except click.UsageError:
        raise
    except KeyboardInterrupt:
        click.echo(warning("\nLoad test interrupted by user"))
    except Exception as e:
        click.echo(error(f"Load test error: {e}"))
        raise


# alias for backward compatibility with tests and old scripts
cli = http
