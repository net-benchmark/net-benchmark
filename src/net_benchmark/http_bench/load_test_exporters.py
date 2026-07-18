"""
CSV/Excel/PDF/JSON export for load test results. Takes
List[LoadTestSummary] (one per target) so Excel gets a per-URL sheet.
Reuses base.py's table/chart helpers; adds a local line-chart helper
for time-series (base.py's generate_bar_chart is bar-only).
"""

import base64
import os
import re
import tempfile
from collections import Counter
from datetime import datetime
from typing import Dict, List, Optional, Set

import matplotlib
import matplotlib.pyplot as plt
import pandas as pd
from openpyxl import Workbook

from net_benchmark.dns_benchmark.core import QueryStatus
from net_benchmark.exporters.base import (
    add_simple_table_sheet,
    embed_charts_sheet,
    generate_bar_chart,
    html_page,
)
from net_benchmark.http_bench.load_test import LoadTestSummary

try:
    from weasyprint import HTML
except ImportError:
    HTML = None


matplotlib.use("Agg")

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_EXCEL_INVALID_CHARS = re.compile(r"[:\\/?*\[\]]")


def _sheet_name(target: str, suffix: str = "", used: Optional[Set[str]] = None) -> str:
    """Excel sheet names: max 31 chars, no : \\ / ? * [ ]. Truncates and
    de-dupes against `used` (mutated in place) so multiple targets that
    truncate to the same prefix don't collide.
    """
    stripped = target.replace("https://", "").replace("http://", "")
    clean = _EXCEL_INVALID_CHARS.sub("_", stripped)
    max_len = 31 - len(suffix)
    name = (clean[:max_len] + suffix) if max_len > 0 else clean[:31]
    if used is None:
        return name
    base_name = name
    i = 2
    while name in used:
        candidate_suffix = f"~{i}"
        name = base_name[: 31 - len(candidate_suffix)] + candidate_suffix
        i += 1
    used.add(name)
    return name


def error_breakdown(summary: LoadTestSummary) -> Dict[str, int]:
    """Error message counts for a single target's load test — mirrors
    HTTPAnalyzer.get_error_statistics() but works directly off
    LoadTestSummary.results since load tests don't go through HTTPAnalyzer
    for the raw-result path (only for the aggregate stats).
    """
    counts = Counter(
        r.error_message or f"HTTP {r.http_status_code}"
        for r in summary.results
        if r.status != QueryStatus.SUCCESS
    )
    return dict(counts)


def combined_error_breakdown(summaries: List[LoadTestSummary]) -> Dict[str, int]:
    total: Counter[str] = Counter()
    for s in summaries:
        total.update(error_breakdown(s))
    return dict(total)


def _generate_line_chart(
    x_values: List[float],
    series: Dict[str, List[float]],
    xlabel: str,
    ylabel: str,
    title: str,
    output_path: str,
) -> str:
    """Local line-chart helper (see module docstring for why this isn't in
    base.py). Same contract as generate_bar_chart: saves a PNG, returns the
    path. Multiple named series are overlaid on one axis.
    """

    fig, ax = plt.subplots(figsize=(10, 6))
    for label, y_values in series.items():
        ax.plot(x_values, y_values, label=label, linewidth=1.6)
    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    ax.grid(True, alpha=0.3)
    if len(series) > 1:
        ax.legend(loc="best", fontsize=8)
    fig.tight_layout()
    fig.savefig(output_path, dpi=150)
    plt.close(fig)
    return output_path


def _latency_timeline_chart(summary: LoadTestSummary, output_path: str) -> str:
    x = [float(iv.window_index) for iv in summary.intervals]
    series = {
        "avg (ms)": [iv.stats.avg_latency for iv in summary.intervals],
        "p95 (ms)": [iv.stats.p95_latency for iv in summary.intervals],
        "p99 (ms)": [iv.stats.p99_latency for iv in summary.intervals],
    }
    return _generate_line_chart(
        x,
        series,
        "Elapsed (s)",
        "Latency (ms)",
        f"Latency over time — {summary.target}",
        output_path,
    )


def _throughput_timeline_chart(summary: LoadTestSummary, output_path: str) -> str:
    x = [float(iv.window_index) for iv in summary.intervals]
    # Each interval bucket is ~1s, so request count in that bucket ≈ RPS for
    # that second.
    series = {
        "Achieved RPS": [float(iv.stats.total_requests) for iv in summary.intervals]
    }
    if summary.target_rps:
        series["Target RPS"] = [summary.target_rps for _ in summary.intervals]
    return _generate_line_chart(
        x,
        series,
        "Elapsed (s)",
        "Requests/sec",
        f"Throughput over time — {summary.target}",
        output_path,
    )


def _status_code_chart(summary: LoadTestSummary, output_path: str) -> str:
    # status_code_distribution is a List[Dict] from
    # HTTPAnalyzer.get_status_code_distribution(): [{"status_code": 200, "count": N, "pct": ...}, ...]
    dist = sorted(summary.status_code_distribution, key=lambda row: row["status_code"])
    names = [str(row["status_code"]) for row in dist]
    values = [row["count"] for row in dist]
    return generate_bar_chart(
        names=names,
        values=values,
        ylabel="Request count",
        title=f"Status code distribution — {summary.target}",
        output_path=output_path,
    )


# ---------------------------------------------------------------------------
# JSON bundle
# ---------------------------------------------------------------------------


class LoadTestExportBundle:
    @staticmethod
    def export_json(summaries: List[LoadTestSummary], output_path: str) -> None:
        import json

        payload = {
            "targets": [s.to_dict() for s in summaries],
            "combined_error_breakdown": combined_error_breakdown(summaries),
            "generated_at": datetime.now().isoformat(),
        }
        with open(output_path, "w") as f:
            json.dump(payload, f, indent=2, default=str)


# ---------------------------------------------------------------------------
# CSV
# ---------------------------------------------------------------------------


class LoadTestCSVExporter:
    """One static method per export type, mirroring HTTPCSVExporter."""

    @staticmethod
    def export_raw_results(summaries: List[LoadTestSummary], output_path: str) -> None:
        rows = []
        for s in summaries:
            for r in s.results:
                row = r.to_dict()
                row["load_test_mode"] = s.mode.value
                row["load_test_target_rps"] = s.target_rps
                rows.append(row)
        pd.DataFrame(rows).to_csv(output_path, index=False)

    @staticmethod
    def export_summary(summaries: List[LoadTestSummary], output_path: str) -> None:
        rows = []
        for s in summaries:
            rows.append(
                {
                    "target": s.target,
                    "mode": s.mode.value,
                    "duration_s": round(s.duration_s, 2),
                    "total_requests": s.stats.total_requests,
                    "successful_requests": s.stats.successful_requests,
                    "success_rate_pct": round(s.stats.success_rate, 2),
                    "achieved_rps": round(s.achieved_rps, 2),
                    "target_rps": s.target_rps,
                    "min_latency_ms": round(s.stats.min_latency, 2),
                    "avg_latency_ms": round(s.stats.avg_latency, 2),
                    "median_latency_ms": round(s.stats.median_latency, 2),
                    "p95_latency_ms": round(s.stats.p95_latency, 2),
                    "p99_latency_ms": round(s.stats.p99_latency, 2),
                    "max_latency_ms": round(s.stats.max_latency, 2),
                    "jitter_ms": round(s.stats.jitter, 2),
                    "connections_opened": s.connection_reuse.connections_opened,
                    "connections_reused": s.connection_reuse.connections_reused,
                    "reuse_rate_pct": round(s.connection_reuse.reuse_rate * 100, 2),
                    # From analysis.py's TargetStats — computed from the
                    # per-request connection_reused/tls_resumed flags,
                    # distinct from connection_reuse (raw TCP-connect counts)
                    "connection_reuse_rate_pct": round(
                        s.stats.connection_reuse_rate, 2
                    ),
                    "tls_resumption_rate_pct": round(s.stats.tls_resumption_rate, 2),
                    "http2_push_total": s.stats.http2_push_total,
                }
            )
        pd.DataFrame(rows).to_csv(output_path, index=False)

    @staticmethod
    def export_intervals(summaries: List[LoadTestSummary], output_path: str) -> None:
        rows = []
        for s in summaries:
            for iv in s.intervals:
                rows.append(
                    {
                        "target": s.target,
                        "window_index": iv.window_index,
                        "request_count": iv.stats.total_requests,
                        "success_count": iv.stats.successful_requests,
                        "error_count": iv.stats.total_requests
                        - iv.stats.successful_requests,
                        "avg_latency_ms": round(iv.stats.avg_latency, 2),
                        "p95_latency_ms": round(iv.stats.p95_latency, 2),
                        "p99_latency_ms": round(iv.stats.p99_latency, 2),
                    }
                )
        pd.DataFrame(rows).to_csv(output_path, index=False)

    @staticmethod
    def export_error_breakdown(
        summaries: List[LoadTestSummary], output_path: str
    ) -> None:
        rows = []
        for s in summaries:
            for message, count in error_breakdown(s).items():
                rows.append(
                    {"target": s.target, "error_message": message, "count": count}
                )
        pd.DataFrame(rows).to_csv(output_path, index=False)


# ---------------------------------------------------------------------------
# Excel — one raw-requests sheet per target ("per-URL Excel sheet", item 15)
# ---------------------------------------------------------------------------


class LoadTestExcelExporter:
    @staticmethod
    def export_results(
        summaries: List[LoadTestSummary],
        output_path: str,
        include_charts: bool = True,
    ) -> None:
        wb = Workbook()
        wb.remove(wb.active)

        temp_dir = None
        chart_paths: List[str] = []

        try:
            LoadTestExcelExporter._add_comparison_sheet(wb, summaries)

            used_names: Set[str] = set()
            for s in summaries:
                LoadTestExcelExporter._add_target_raw_sheet(wb, s, used_names)
                LoadTestExcelExporter._add_target_timeline_sheet(wb, s, used_names)

            error_dist = combined_error_breakdown(summaries)
            if error_dist:
                add_simple_table_sheet(
                    wb,
                    "Errors",
                    pd.DataFrame(
                        [{"error": k, "count": v} for k, v in error_dist.items()]
                    ),
                )

            if include_charts:
                temp_dir = tempfile.mkdtemp()
                chart_paths = LoadTestExcelExporter._add_charts_sheet(
                    wb, summaries, temp_dir
                )

            wb.save(output_path)
        finally:
            for p in chart_paths:
                try:
                    if os.path.exists(p):
                        os.remove(p)
                except OSError:
                    pass
            if temp_dir and os.path.exists(temp_dir):
                try:
                    os.rmdir(temp_dir)
                except OSError:
                    pass

    @staticmethod
    def _add_comparison_sheet(wb: Workbook, summaries: List[LoadTestSummary]) -> None:
        rows = []
        for s in summaries:
            rows.append(
                {
                    "Target": s.target,
                    "Mode": s.mode.value,
                    "Duration (s)": round(s.duration_s, 2),
                    "Total Requests": s.stats.total_requests,
                    "Success Rate (%)": round(s.stats.success_rate, 2),
                    "Achieved RPS": round(s.achieved_rps, 2),
                    "Target RPS": s.target_rps if s.target_rps else "",
                    "Avg (ms)": round(s.stats.avg_latency, 2),
                    "P95 (ms)": round(s.stats.p95_latency, 2),
                    "P99 (ms)": round(s.stats.p99_latency, 2),
                    "Connections Opened": s.connection_reuse.connections_opened,
                    "Reuse Rate (%)": round(s.connection_reuse.reuse_rate * 100, 2),
                    "TLS Resumption Rate (%)": round(s.stats.tls_resumption_rate, 2),
                }
            )
        add_simple_table_sheet(wb, "Summary", pd.DataFrame(rows))

    @staticmethod
    def _add_target_raw_sheet(
        wb: Workbook, summary: LoadTestSummary, used_names: Set[str]
    ) -> None:
        data = []
        for r in summary.results:
            data.append(
                {
                    "Status": r.status.value,
                    "HTTP Code": r.http_status_code or "",
                    "Total (ms)": round(r.total_ms, 2),
                    "TTFB (ms)": round(r.ttfb_ms, 2) if r.ttfb_ms else "",
                    "Connection Reused": r.connection_reused,
                    "Connection ID": r.connection_id or "",
                    "TLS Resumed": r.tls_resumed,
                    "Protocol": r.protocol.value,
                    "Error": r.error_message or "",
                }
            )
        name = _sheet_name(summary.target, suffix=" Raw", used=used_names)
        add_simple_table_sheet(wb, name, pd.DataFrame(data))

    @staticmethod
    def _add_target_timeline_sheet(
        wb: Workbook, summary: LoadTestSummary, used_names: Set[str]
    ) -> None:
        data = []
        for iv in summary.intervals:
            data.append(
                {
                    "Second": iv.window_index,
                    "Requests": iv.stats.total_requests,
                    "Success": iv.stats.successful_requests,
                    "Errors": iv.stats.total_requests - iv.stats.successful_requests,
                    "Avg (ms)": round(iv.stats.avg_latency, 2),
                    "P95 (ms)": round(iv.stats.p95_latency, 2),
                    "P99 (ms)": round(iv.stats.p99_latency, 2),
                }
            )
        name = _sheet_name(summary.target, suffix=" Timeline", used=used_names)
        add_simple_table_sheet(wb, name, pd.DataFrame(data))

    @staticmethod
    def _add_charts_sheet(
        wb: Workbook, summaries: List[LoadTestSummary], temp_dir: str
    ) -> List[str]:
        chart_paths: List[str] = []
        entries: List[str] = []

        for i, s in enumerate(summaries):
            safe_name = re.sub(r"[^a-zA-Z0-9]", "_", s.target)[:40]
            if s.intervals:
                lat_path = _latency_timeline_chart(
                    s, os.path.join(temp_dir, f"latency_{i}_{safe_name}.png")
                )
                thr_path = _throughput_timeline_chart(
                    s, os.path.join(temp_dir, f"throughput_{i}_{safe_name}.png")
                )
                chart_paths.extend([lat_path, thr_path])
                entries.append(lat_path)
                entries.append(thr_path)
            if s.status_code_distribution:
                status_path = _status_code_chart(
                    s, os.path.join(temp_dir, f"status_{i}_{safe_name}.png")
                )
                chart_paths.append(status_path)
                entries.append(status_path)

        # embed_charts_sheet's loop unpacks (heading_cell, anchor_cell, path)
        # — first cell gets bold formatting, second is where the image is
        # anchored, 20 rows apart, matching the spacing HTTPExcelExporter
        # uses ("A3","A4"), ("A23","A24"), etc.
        anchored = []
        row = 3
        for path in entries:
            anchored.append((f"A{row}", f"A{row + 1}", path))
            row += 20

        if anchored:
            embed_charts_sheet(wb, "Charts", anchored, "Load Test Charts")

        return chart_paths


# ---------------------------------------------------------------------------
# PDF
# ---------------------------------------------------------------------------


class LoadTestPDFExporter:
    @staticmethod
    def export_results(
        summaries: List[LoadTestSummary],
        output_path: str,
        include_charts: bool = True,
    ) -> None:
        if HTML is None:
            raise RuntimeError(
                "PDF export requires 'weasyprint'. "
                "Install with: pip install net-benchmark[pdf]"
            )

        charts_dir = tempfile.mkdtemp()
        chart_paths: List[str] = []

        try:
            chart_b64_by_target: Dict[str, Dict[str, str]] = {}

            if include_charts:
                for i, s in enumerate(summaries):
                    safe_name = re.sub(r"[^a-zA-Z0-9]", "_", s.target)[:40]
                    target_charts: Dict[str, str] = {}

                    if s.intervals:
                        lat_path = _latency_timeline_chart(
                            s, os.path.join(charts_dir, f"latency_{i}_{safe_name}.png")
                        )
                        thr_path = _throughput_timeline_chart(
                            s,
                            os.path.join(charts_dir, f"throughput_{i}_{safe_name}.png"),
                        )
                        chart_paths.extend([lat_path, thr_path])
                        with open(lat_path, "rb") as f:
                            target_charts["latency"] = base64.b64encode(
                                f.read()
                            ).decode()
                        with open(thr_path, "rb") as f:
                            target_charts["throughput"] = base64.b64encode(
                                f.read()
                            ).decode()

                    if s.status_code_distribution:
                        status_path = _status_code_chart(
                            s, os.path.join(charts_dir, f"status_{i}_{safe_name}.png")
                        )
                        chart_paths.append(status_path)
                        with open(status_path, "rb") as f:
                            target_charts["status"] = base64.b64encode(
                                f.read()
                            ).decode()

                    chart_b64_by_target[s.target] = target_charts

            html_content = LoadTestPDFExporter._generate_html(
                summaries, chart_b64_by_target
            )
            HTML(string=html_content).write_pdf(output_path)

        finally:
            for p in chart_paths:
                try:
                    if os.path.exists(p):
                        os.remove(p)
                except OSError:
                    pass
            try:
                os.rmdir(charts_dir)
            except OSError:
                pass

    @staticmethod
    def _generate_html(
        summaries: List[LoadTestSummary],
        chart_b64_by_target: Dict[str, Dict[str, str]],
    ) -> str:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        errors = combined_error_breakdown(summaries)

        summary_rows = "".join(
            f"<tr><td>{s.target}</td><td>{s.mode.value}</td>"
            f"<td>{s.stats.total_requests}</td><td>{s.stats.success_rate:.1f}%</td>"
            f"<td>{s.achieved_rps:.1f}</td>"
            f"<td>{s.target_rps if s.target_rps else 'N/A'}</td>"
            f"<td>{s.stats.avg_latency:.1f}</td><td>{s.stats.p95_latency:.1f}</td>"
            f"<td>{s.stats.p99_latency:.1f}</td>"
            f"<td>{s.connection_reuse.reuse_rate * 100:.1f}%</td></tr>"
            for s in summaries
        )

        error_rows = (
            "".join(
                f"<tr><td>{message}</td><td>{count}</td></tr>"
                for message, count in sorted(errors.items(), key=lambda kv: -kv[1])
            )
            or "<tr><td colspan='2'>No errors recorded</td></tr>"
        )

        chart_sections = ""
        for s in summaries:
            charts = chart_b64_by_target.get(s.target, {})
            if not charts:
                continue
            chart_sections += f"<div class='section'><h2>Charts — {s.target}</h2>"
            if "latency" in charts:
                chart_sections += (
                    f"<div class='chart'><img src='data:image/png;base64,"
                    f"{charts['latency']}' alt='Latency over time'></div>"
                )
            if "throughput" in charts:
                chart_sections += (
                    f"<div class='chart'><img src='data:image/png;base64,"
                    f"{charts['throughput']}' alt='Throughput over time'></div>"
                )
            if "status" in charts:
                chart_sections += (
                    f"<div class='chart'><img src='data:image/png;base64,"
                    f"{charts['status']}' alt='Status code distribution'></div>"
                )
            chart_sections += "</div>"

        total_requests = sum(s.stats.total_requests for s in summaries)
        total_errors = sum(
            s.stats.total_requests - s.stats.successful_requests for s in summaries
        )

        body = f"""
        <div class="header">
        <h1>Load Test Report</h1>
        <p>Generated: {now}</p>
        </div>

        <div class="section">
        <h2>Executive Summary</h2>
        <p><strong>Targets tested:</strong> {len(summaries)}</p>
        <p><strong>Total requests:</strong> {total_requests}</p>
        <p><strong>Total errors:</strong> {total_errors}</p>
        </div>

        <div class="section">
        <h2>Target Comparison</h2>
        <table>
        <tr><th>Target</th><th>Mode</th><th>Requests</th><th>Success</th>
        <th>Achieved RPS</th><th>Target RPS</th><th>Avg (ms)</th>
        <th>P95 (ms)</th><th>P99 (ms)</th><th>Reuse Rate</th></tr>
            {summary_rows}
        </table>
        </div>

        {chart_sections}

        <div class="section">
        <h2>Error Breakdown</h2>
        <table>
            <tr><th>Error</th><th>Count</th></tr>
            {error_rows}
        </table>
        </div>
        """
        return html_page("Load Test Report", body)
