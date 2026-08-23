"""
CSV/Excel/PDF/JSON export for load test results. Takes
List[LoadTestSummary] (one per target) so Excel gets a per-URL sheet.
Reuses base.py's table/chart helpers; adds a local line-chart helper
for time-series (base.py's generate_bar_chart is bar-only).
"""

import base64
import csv
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

    # --- 0.5.2: prefer LoadTestSummary.error_breakdown, which _summarize()
    # builds while the results are still in hand. The earlier fallback to the
    # status code distribution only recovered 4xx/5xx: transport failures
    # (DNS, connection refused, TLS, timeout) carry no status code and
    # vanished entirely, so with retain_results=False the errors file looked
    # complete while omitting every real failure — worse than being empty.
    if summary.error_breakdown:
        return dict(summary.error_breakdown)
    if not summary.results:
        return {}

    counts = Counter(
        r.error_message or f"HTTP {r.http_status_code}"
        for r in summary.results
        if r.status != QueryStatus.SUCCESS
    )
    return dict(counts)


def export_latency_histograms(
    summaries: List[LoadTestSummary],
    output_path: str,
    filename_prefix: str,
) -> str:
    """--- 0.5.2: write the mergeable latency histogram buckets to CSV.

    The histogram previously reached JSON only. It is the artifact a
    distributed run consumes — several workers or nodes each emit one, and
    LatencyHistogram.merge_all() folds them into correct global percentiles
    (averaging p95s does not work). A flat CSV makes that usable from outside
    Python too.

    One row per non-empty bucket. The layout parameters are repeated on every
    row because merging is only valid between histograms that share them.
    """
    path = os.path.join(output_path, f"{filename_prefix}_histogram.csv")
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(
            [
                "target",
                # --- 0.5.2: identity, so rows from several workers can share
                # a file and still be told apart.
                "worker_id",
                "region",
                "lowest_ms",
                "sub_buckets",
                "max_exponent",
                "bucket_index",
                "lower_ms",
                "upper_ms",
                "count",
                "total_count",
                "overflow_count",
                # --- 0.5.2: tracked exactly, not bucketed. Without these an
                # external collector merging from this CSV could recover
                # correct percentiles but had to reconstruct mean/min/max from
                # bucket midpoints — losing the one property LatencyHistogram
                # advertises as exact, in the very file written for
                # cross-process merging. Repeated per row so a single row is
                # enough to rebuild a mergeable histogram.
                "min_ms",
                "max_ms",
                "total_ms",
            ]
        )
        for s in summaries:
            h = s.latency_histogram
            if h is None or not h.counts:
                continue
            for idx in sorted(h.counts):
                lo, hi = h.bucket_bounds(idx)
                writer.writerow(
                    [
                        s.target,
                        s.worker_id or "",
                        s.region or "",
                        h.lowest_ms,
                        h.sub_buckets,
                        h.max_exponent,
                        idx,
                        round(lo, 6),
                        round(hi, 6),
                        h.counts[idx],
                        h.count,
                        h.overflow_count,
                        h.min_ms if h.min_ms is not None else "",
                        h.max_ms if h.max_ms is not None else "",
                        round(h.total, 6),
                    ]
                )
    return path


def _phase_timeline_chart(summary: LoadTestSummary, output_path: str) -> str:
    """--- 0.5.2: waiting vs blocked over time.

    The single most useful load-test chart the tool was missing. `waiting` is
    the target's own response time with local queueing excluded; `blocked` is
    time spent waiting for a connection from the pool. If blocked climbs while
    waiting stays flat, the generator has saturated and the run has stopped
    measuring the target — which is exactly the single-node limitation, made
    visible rather than inferred.
    """
    # --- 0.5.2: a run shorter than one interval bucket has no completed
    # windows; plotting it produced a blank chart rather than being skipped.
    # Callers treat "" as "no chart".
    if not summary.intervals:
        return ""
    x = [float(iv.window_index) for iv in summary.intervals]
    series = {
        "waiting — server (ms)": [iv.stats.avg_waiting_ms for iv in summary.intervals],
        "blocked — pool queue (ms)": [
            iv.stats.avg_blocked_ms for iv in summary.intervals
        ],
        "duration excl. setup (ms)": [
            iv.stats.avg_duration_ms for iv in summary.intervals
        ],
    }
    return _generate_line_chart(
        x, series, "Seconds", "ms", f"Phase breakdown — {summary.target}", output_path
    )


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
        with open(output_path, "w", encoding="utf-8") as f:
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
                    # --- 0.5.2: identity and merge provenance. This exporter
                    # is now used for the merged summary AND the per-worker
                    # rows behind it, and a file where those two are
                    # indistinguishable is worse than no file.
                    "worker_id": s.worker_id or "",
                    "region": s.region or "",
                    "merged": s.merged,
                    "merged_from": ";".join(s.merged_from),
                    "start_offset_s": round(s.start_offset_s, 4),
                    "clock_offset_ms": (
                        round(s.clock_offset_s * 1000, 3)
                        if s.clock_offset_s is not None
                        else ""
                    ),
                    "interval_bucket_s": s.interval_bucket_s,
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
                    # --- 0.5.2: blank, not 0.0, on a merged row — see
                    # analysis.UNMERGEABLE_METRICS. 0.0 is also the
                    # "no samples" value, so writing it would make a
                    # merged run look like a measured zero.
                    "jitter_ms": ("" if s.merged else round(s.stats.jitter, 2)),
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
                    # --- 0.5.2: load-shaping health. Without these, achieved_rps
                    # cannot be interpreted — a run that dropped a third of
                    # its scheduled requests looks identical to one that
                    # didn't.
                    "scheduled_requests": s.counters.scheduled,
                    "started_requests": s.counters.started,
                    "dropped_requests": s.counters.dropped,
                    "dropped_rate_pct": round(s.dropped_rate, 2),
                    "interrupted_requests": s.counters.interrupted,
                    "worker_errors": s.counters.worker_errors,
                    "avg_queue_delay_ms": round(s.counters.avg_queue_delay_ms, 2),
                    "max_queue_delay_ms": round(s.counters.max_queue_delay_ms, 2),
                    # --- 0.5.2: phase timings. duration excludes connection
                    # setup, so it is the cross-run comparable latency;
                    # blocked is client-side queueing.
                    "avg_duration_ms": round(s.stats.avg_duration_ms, 2),
                    # --- 0.5.2: blank, not 0.0, on a merged row — see
                    # analysis.UNMERGEABLE_METRICS. 0.0 is also the
                    # "no samples" value, so writing it would make a
                    # merged run look like a measured zero.
                    "p95_duration_ms": (
                        "" if s.merged else round(s.stats.p95_duration_ms, 2)
                    ),
                    "avg_blocked_ms": round(s.stats.avg_blocked_ms, 2),
                    # --- 0.5.2: blank, not 0.0, on a merged row — see
                    # analysis.UNMERGEABLE_METRICS. 0.0 is also the
                    # "no samples" value, so writing it would make a
                    # merged run look like a measured zero.
                    "p95_blocked_ms": (
                        "" if s.merged else round(s.stats.p95_blocked_ms, 2)
                    ),
                    "avg_admission_wait_ms": round(s.stats.avg_admission_wait_ms, 2),
                    "avg_sending_ms": round(s.stats.avg_sending_ms, 2),
                    "avg_waiting_ms": round(s.stats.avg_waiting_ms, 2),
                    # --- 0.5.2: blank, not 0.0, on a merged row — see
                    # analysis.UNMERGEABLE_METRICS. 0.0 is also the
                    # "no samples" value, so writing it would make a
                    # merged run look like a measured zero.
                    "p95_waiting_ms": (
                        "" if s.merged else round(s.stats.p95_waiting_ms, 2)
                    ),
                    "avg_receiving_ms": round(s.stats.avg_receiving_ms, 2),
                    "avg_ttfb_ms": round(s.stats.avg_ttfb_ms, 2),
                    # --- 0.5.2: failure split. success_rate above counts a 404
                    # and a connection reset the same way.
                    "transport_error_rate_pct": round(s.stats.transport_error_rate, 2),
                    "unexpected_status_rate_pct": round(
                        s.stats.unexpected_status_rate, 2
                    ),
                    # --- 0.5.2: throughput in bytes
                    "total_response_bytes": s.stats.total_response_bytes,
                    "received_bytes_per_s": round(s.received_bytes_per_s, 2),
                    "sent_bytes_per_s": round(s.sent_bytes_per_s, 2),
                    # --- 0.5.2: setup-timing denominators. avg_tcp/avg_tls are
                    # now means over NEW connections only.
                    "connections_measured": s.stats.connections_measured,
                    "dns_lookups_measured": s.stats.dns_lookups_measured,
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
                        # --- 0.5.2: per-second phase view. A rising
                        # avg_blocked_ms with flat avg_duration_ms is the
                        # signature of the generator saturating rather than
                        # the target degrading.
                        "avg_duration_ms": round(iv.stats.avg_duration_ms, 2),
                        "avg_blocked_ms": round(iv.stats.avg_blocked_ms, 2),
                        "avg_waiting_ms": round(iv.stats.avg_waiting_ms, 2),
                        "avg_ttfb_ms": round(iv.stats.avg_ttfb_ms, 2),
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
                    # -- 0.5.2: duration excludes connection setup; see
                    # TargetStats.avg_duration_ms
                    "P95 Duration (ms)": round(s.stats.p95_duration_ms, 2),
                    "Avg Blocked (ms)": round(s.stats.avg_blocked_ms, 2),
                    "Avg Waiting (ms)": round(s.stats.avg_waiting_ms, 2),
                    "Connections Opened": s.connection_reuse.connections_opened,
                    "Reuse Rate (%)": round(s.connection_reuse.reuse_rate * 100, 2),
                    "TLS Resumption Rate (%)": round(s.stats.tls_resumption_rate, 2),
                    # -- 0.5.2: load-shaping health
                    "Dropped": s.counters.dropped,
                    "Dropped (%)": round(s.dropped_rate, 2),
                    "Interrupted": s.counters.interrupted,
                    "Max Queue Delay (ms)": round(s.counters.max_queue_delay_ms, 2),
                    "Transport Err (%)": round(s.stats.transport_error_rate, 2),
                    "Unexpected Status (%)": round(s.stats.unexpected_status_rate, 2),
                    "Recv (KB/s)": round(s.received_bytes_per_s / 1024, 1),
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
                    # -- 0.5.2: phase split. Blank rather than 0 when unset, so a
                    # missing measurement is not read as "zero milliseconds".
                    "Blocked (ms)": (
                        round(r.blocked_ms, 2) if r.blocked_ms is not None else ""
                    ),
                    "Duration (ms)": (
                        round(r.duration_ms, 2) if r.duration_ms is not None else ""
                    ),
                    "Sending (ms)": (
                        round(r.sending_ms, 2) if r.sending_ms is not None else ""
                    ),
                    "Waiting (ms)": (
                        round(r.waiting_ms, 2) if r.waiting_ms is not None else ""
                    ),
                    "TTFB (ms)": round(r.ttfb_ms, 2) if r.ttfb_ms else "",
                    "Receiving (ms)": (
                        round(r.receiving_ms, 2) if r.receiving_ms is not None else ""
                    ),
                    # -- 0.5.2: blank on reused connections: no connect happened,
                    # and repeating the original connection's cost here is
                    # what the core.py fix removed.
                    "TCP Connect (ms)": (
                        round(r.tcp_connect_ms, 2)
                        if r.tcp_connect_ms is not None
                        else ""
                    ),
                    "TLS Handshake (ms)": (
                        round(r.tls_handshake_ms, 2)
                        if r.tls_handshake_ms is not None
                        else ""
                    ),
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
                    # --- 0.5.2
                    "Avg Duration (ms)": round(iv.stats.avg_duration_ms, 2),
                    "Avg Blocked (ms)": round(iv.stats.avg_blocked_ms, 2),
                    "Avg Waiting (ms)": round(iv.stats.avg_waiting_ms, 2),
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
                phase_path = _phase_timeline_chart(
                    s, os.path.join(temp_dir, f"phase_{i}_{safe_name}.png")
                )
                chart_paths.extend([lat_path, thr_path, phase_path])
                entries.append(lat_path)
                entries.append(thr_path)
                entries.append(phase_path)

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
                        phase_path = _phase_timeline_chart(
                            s, os.path.join(charts_dir, f"phase_{i}_{safe_name}.png")
                        )
                        chart_paths.extend([lat_path, thr_path, phase_path])
                        with open(lat_path, "rb") as f:
                            target_charts["latency"] = base64.b64encode(
                                f.read()
                            ).decode()
                        with open(thr_path, "rb") as f:
                            target_charts["throughput"] = base64.b64encode(
                                f.read()
                            ).decode()
                        with open(phase_path, "rb") as f:
                            target_charts["phase"] = base64.b64encode(f.read()).decode()

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
            if "phase" in charts:
                chart_sections = (
                    f"<div class='chart'><img src='data:image/png;base64,"
                    f"{charts['phase']}' alt='Phase breakdown'></div>"
                )
            if "status" in charts:
                chart_sections += (
                    f"<div class='chart'><img src='data:image/png;base64,"
                    f"{charts['status']}' alt='Status code distribution'></div>"
                )
            chart_sections += "</div>"

        # -- 0.5.2: load-shaping health. A reader cannot judge "achieved 4800 RPS"
        # without knowing whether the pacer dropped requests to get there, or
        # whether the numbers describe the target or the generator's own
        # queue.
        health_rows = "".join(
            f"<tr><td>{s.target}</td>"
            f"<td>{s.counters.scheduled or s.counters.started}</td>"
            f"<td>{s.counters.started}</td>"
            f"<td>{s.counters.dropped} ({s.dropped_rate:.1f}%)</td>"
            f"<td>{s.counters.interrupted}</td>"
            f"<td>{s.counters.worker_errors}</td>"
            f"<td>{s.counters.max_queue_delay_ms:.0f}</td>"
            f"<td>{s.stats.avg_blocked_ms:.1f}</td>"
            f"<td>{s.stats.avg_waiting_ms:.1f}</td>"
            f"<td>{s.stats.p95_duration_ms:.1f}</td>"
            f"<td>{s.received_bytes_per_s / 1024:.0f}</td></tr>"
            for s in summaries
        )
        health_section = f"""
        <div class="section">
        <h2>Load Generation Health</h2>
        <p>Dropped requests were scheduled but never issued because every
        worker was busy — a non-zero figure means the achieved rate understates
        the requested load. Blocked is time waiting for a connection from the
        pool; Waiting is the target's own response time with that queueing
        excluded. Blocked climbing while Waiting stays flat means the load
        generator saturated and the run stopped measuring the target.
        Duration excludes DNS, TCP and TLS setup.</p>
        <table>
        <tr><th>Target</th><th>Scheduled</th><th>Started</th><th>Dropped</th>
        <th>Interrupted</th><th>Worker Errors</th><th>Max Queue Delay (ms)</th>
        <th>Avg Blocked (ms)</th><th>Avg Waiting (ms)</th><th>P95 Duration (ms)</th><th>Recv (KB/s)</th></tr>
            {health_rows}
        </table>
        </div>
        """
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

        {health_section}

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
