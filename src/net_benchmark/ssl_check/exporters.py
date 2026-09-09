"""Export SSL/TLS check results.

net-benchmark 0.6.0 — SSL items 42, 43, 51, 52, 54, 56.

Mirrors `dns_benchmark/exporters.py` and `http_bench/exporters.py`: a CSV
exporter, an Excel exporter, a JSON bundle and an optional PDF report, all
built on `net_benchmark.exporters.base` rather than a fourth private copy of
the same openpyxl helpers.

The Expiry Timeline sheet is the one `add_coloured_table_sheet` was written for
— its docstring names it explicitly alongside the DNS DNSSEC sheet and the HTTP
Security Headers sheet.

Provenance (item 56)
--------------------
Every JSON export carries a provenance block naming the trust store and its
version. A multi-store trust verdict is unreproducible without it, because the
answer changes when a store does — a chain that validated last month against
certifi 2025.x can legitimately fail against 2026.x, and without the recorded
version that reads as a regression in the target rather than a change in the
store.
"""

from __future__ import annotations

import csv
import json
import os
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence

import pandas as pd
from openpyxl import Workbook
from openpyxl.styles import Font

from net_benchmark.exporters.base import (
    FILL_AMBER,
    FILL_GREEN,
    FILL_RED,
    add_coloured_table_sheet,
    add_simple_table_sheet,
    autosize_columns,
    embed_charts_sheet,
    generate_bar_chart,
)
from net_benchmark.http_bench.analysis import ThresholdResult
from net_benchmark.ssl_check.analysis import SSLAnalyzer, expiry_timeline
from net_benchmark.ssl_check.certificate import ExpiryAlert
from net_benchmark.ssl_check.core import SSLResult

__all__ = [
    "SSLCSVExporter",
    "SSLExcelExporter",
    "SSLExportBundle",
    "SSLPDFExporter",
    "build_provenance",
]


# ---------------------------------------------------------------------------
# Provenance (item 56)
# ---------------------------------------------------------------------------


def build_provenance(
    trust_store_name: str = "certifi",
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Record what the run was validated against.

    `trust_store_version` is read from the installed package rather than
    hard-coded, and is None when it cannot be determined — a wrong version
    string is worse than an absent one, because a reader has no way to tell
    a fabricated value from a real one.
    """
    version: Optional[str] = None
    try:
        import certifi

        version = getattr(certifi, "__version__", None)
    except ImportError:
        version = None

    provenance: Dict[str, Any] = {
        "trust_store": trust_store_name,
        "trust_store_version": version,
        "retrieved_at": datetime.now(tz=timezone.utc).isoformat(),
        "tool": "net-benchmark",
    }
    try:
        import ssl as _ssl

        provenance["openssl_version"] = _ssl.OPENSSL_VERSION
    except Exception:  # pragma: no cover — defensive
        provenance["openssl_version"] = None
    if extra:
        provenance.update(extra)
    return provenance


# ---------------------------------------------------------------------------
# Row flattening
# ---------------------------------------------------------------------------


def _raw_rows(results: Sequence[SSLResult]) -> List[Dict[str, Any]]:
    """Flatten results for the raw CSV / Excel sheet.

    The nested certificate is flattened into `cert_*` columns rather than
    serialised as JSON in one cell: a CSV whose interesting content is a JSON
    blob is not a CSV anyone can filter or pivot, which is the point of the
    raw export.
    """
    rows: List[Dict[str, Any]] = []
    for result in results:
        certificate = result.certificate
        lifetime = certificate.lifetime if certificate is not None else None
        key = certificate.public_key if certificate is not None else None
        rows.append(
            {
                "target": result.target,
                "host": result.host,
                "port": result.port,
                "starttls": result.starttls.value,
                "status": result.status.value,
                "measured": result.measured,
                "compliant": result.compliant,
                "policy_failures": "; ".join(result.policy_failures),
                "resolved_ip": result.resolved_ip,
                "ip_version": result.ip_version,
                "dns_ms": result.dns_ms,
                "tcp_connect_ms": result.tcp_connect_ms,
                "starttls_ms": result.starttls_ms,
                "handshake_ms": result.handshake_ms,
                "handshake_samples": len(result.handshake_samples_ms),
                "handshake_p95_ms": result.handshake_p95_ms,
                "handshake_bytes_total": (
                    result.handshake_bytes_sent + result.handshake_bytes_received
                ),
                "chain_bytes": result.chain_bytes,
                "chain_observed": result.chain_observed,
                "chain_length": result.chain_length,
                "tls_version": result.tls_version.value,
                "tls_version_deprecated": result.tls_version_deprecated,
                "cipher_name": result.cipher_name,
                "cipher_iana_hex": (
                    f"0x{result.cipher_id:04x}"
                    if result.cipher_id is not None
                    else None
                ),
                "cipher_bits": result.cipher_bits,
                "forward_secrecy": result.forward_secrecy,
                "alpn": result.alpn_protocol,
                "session_reused": result.session_reused,
                "resumption_supported": result.resumption_supported,
                "hostname_match": result.hostname_match.value,
                "expiry_alert": result.expiry_alert.value,
                "cert_subject_cn": (
                    certificate.subject_cn if certificate is not None else None
                ),
                "cert_issuer_cn": (
                    certificate.issuer_cn if certificate is not None else None
                ),
                "cert_issuer_org": (
                    certificate.issuer_org if certificate is not None else None
                ),
                "cert_serial": (
                    certificate.serial_number if certificate is not None else None
                ),
                "cert_not_before": (
                    lifetime.not_before.isoformat() if lifetime is not None else None
                ),
                "cert_not_after": (
                    lifetime.not_after.isoformat() if lifetime is not None else None
                ),
                "cert_days_remaining": (
                    lifetime.days_remaining if lifetime is not None else None
                ),
                "cert_lifetime_days": (
                    lifetime.lifetime_days if lifetime is not None else None
                ),
                "cert_lifetime_verdict": (
                    lifetime.verdict.value if lifetime is not None else None
                ),
                "cert_short_lived": (
                    lifetime.short_lived if lifetime is not None else None
                ),
                "cert_key_type": key.key_type.value if key is not None else None,
                "cert_key_size": key.key_size if key is not None else None,
                "cert_key_weak": key.weak if key is not None else None,
                "cert_sig_hash": (
                    certificate.signature_hash if certificate is not None else None
                ),
                "cert_sig_weak": (
                    certificate.signature_weak if certificate is not None else None
                ),
                "cert_self_issued": (
                    certificate.self_issued if certificate is not None else None
                ),
                "cert_self_signed": (
                    certificate.self_signed if certificate is not None else None
                ),
                "cert_must_staple": (
                    certificate.revocation.must_staple
                    if certificate is not None
                    else None
                ),
                "cert_ocsp_urls": (
                    ", ".join(certificate.revocation.ocsp_urls)
                    if certificate is not None
                    else None
                ),
                "cert_crl_urls": (
                    ", ".join(certificate.revocation.crl_urls)
                    if certificate is not None
                    else None
                ),
                "cert_sans": (
                    ", ".join(certificate.san_dns) if certificate is not None else None
                ),
                "cert_wildcard": (
                    certificate.wildcard.present if certificate is not None else None
                ),
                "cert_sha256": (
                    certificate.fingerprints.cert_sha256
                    if certificate is not None and certificate.fingerprints
                    else None
                ),
                "cert_spki_sha256_b64": (
                    certificate.fingerprints.spki_sha256_b64
                    if certificate is not None and certificate.fingerprints
                    else None
                ),
                "error_message": result.error_message,
            }
        )
    return rows


# ---------------------------------------------------------------------------
# CSV
# ---------------------------------------------------------------------------


class SSLCSVExporter:
    """CSV export of raw results and per-target summaries (item 51)."""

    @staticmethod
    def export_raw_results(results: Sequence[SSLResult], output_path: str) -> None:
        pd.DataFrame(_raw_rows(results)).to_csv(output_path, index=False)

    @staticmethod
    def export_summary_statistics(analyzer: SSLAnalyzer, output_path: str) -> None:
        rows: List[Dict[str, Any]] = []
        for stats in analyzer.get_target_statistics():
            row = stats.to_dict()
            # Dicts do not belong in a CSV cell; the counts are exported as
            # their own sheet/file rather than stringified here.
            row.pop("status_counts", None)
            row.pop("policy_failure_counts", None)
            row.pop("expiry_alert_counts", None)
            rows.append(row)
        pd.DataFrame(rows).to_csv(output_path, index=False)

    @staticmethod
    def export_expiry_timeline(results: Sequence[SSLResult], output_path: str) -> None:
        rows = [
            {
                "bucket": group["label"],
                "max_days": group["max_days"],
                "count": group["count"],
                "targets": ", ".join(group["targets"]),
            }
            for group in expiry_timeline(results)
        ]
        pd.DataFrame(rows).to_csv(output_path, index=False)


# ---------------------------------------------------------------------------
# Excel
# ---------------------------------------------------------------------------


# Row colour for the Expiry Timeline sheet. UNKNOWN is amber, not red: a target
# with no observed certificate needs looking at, but colouring it the same as
# an expired certificate would put scan failures and genuine outages in the
# same visual bucket.
_ALERT_FILLS = {
    ExpiryAlert.EXPIRED.value: FILL_RED,
    ExpiryAlert.CRITICAL.value: FILL_RED,
    ExpiryAlert.WARNING.value: FILL_AMBER,
    ExpiryAlert.NOTICE.value: FILL_AMBER,
    ExpiryAlert.OK.value: FILL_GREEN,
    ExpiryAlert.UNKNOWN.value: FILL_AMBER,
}


class SSLExcelExporter:
    """Multi-sheet Excel workbook (item 51)."""

    @staticmethod
    def export_results(
        results: Sequence[SSLResult],
        analyzer: SSLAnalyzer,
        output_path: str,
        threshold_results: Optional[Dict[str, List[ThresholdResult]]] = None,
        provenance: Optional[Dict[str, Any]] = None,
        include_charts: bool = True,
    ) -> None:
        workbook = Workbook()
        default = workbook.active
        if default is not None:
            workbook.remove(default)

        temp_dir: Optional[str] = None
        chart_paths: List[str] = []

        try:
            SSLExcelExporter._add_summary_sheet(workbook, analyzer)
            SSLExcelExporter._add_expiry_timeline_sheet(workbook, results)
            SSLExcelExporter._add_certificate_sheet(workbook, results)
            SSLExcelExporter._add_raw_sheet(workbook, results)
            if threshold_results:
                SSLExcelExporter._add_threshold_sheet(workbook, threshold_results)
            if include_charts:
                temp_dir = tempfile.mkdtemp()
                chart_paths = SSLExcelExporter._add_charts_sheet(
                    workbook, analyzer, temp_dir
                )
            SSLExcelExporter._add_provenance_sheet(
                workbook, provenance or build_provenance()
            )

            # openpyxl reads embedded image files lazily, at save() time rather
            # than when add_image() is called. Deleting the chart PNGs before
            # this line raises FileNotFoundError from deep inside the writer,
            # which is why cleanup is in the finally block below and not at the
            # end of _add_charts_sheet.
            workbook.save(output_path)
        finally:
            for path in chart_paths:
                try:
                    if os.path.exists(path):
                        os.remove(path)
                except OSError:
                    pass
            if temp_dir and os.path.exists(temp_dir):
                try:
                    os.rmdir(temp_dir)
                except OSError:
                    pass

    @staticmethod
    def _add_summary_sheet(workbook: Workbook, analyzer: SSLAnalyzer) -> None:
        rows: List[Dict[str, Any]] = []
        for stats in analyzer.get_target_statistics():
            rows.append(
                {
                    "Target": stats.target,
                    "Checks": stats.total_checks,
                    "Measured": stats.measured_checks,
                    "Compliant": stats.successful_checks,
                    "Success %": round(stats.success_rate, 2),
                    "Handshake avg ms": round(stats.avg_latency, 2),
                    # Blank, not 0.00, when percentiles were withheld for too
                    # few samples (item 57). A 0.00 in a spreadsheet is read as
                    # a measurement and no reader would know it was withheld.
                    "Handshake p95 ms": (
                        None
                        if stats.percentiles_refused
                        else round(stats.p95_latency, 2)
                    ),
                    "TLS 1.3 %": round(stats.tls13_rate, 1),
                    "Deprecated TLS %": round(stats.deprecated_tls_rate, 1),
                    "Forward secrecy %": round(stats.forward_secrecy_rate, 1),
                    "Hostname match %": round(stats.hostname_match_rate, 1),
                    "Days remaining": stats.cert_expiry_days_min,
                    "Expiry alert": stats.worst_expiry_alert,
                    "Handshake bytes": round(stats.avg_handshake_bytes),
                    "Chain bytes": stats.avg_chain_bytes,
                }
            )
        add_simple_table_sheet(workbook, "Summary", pd.DataFrame(rows))

    @staticmethod
    def _add_expiry_timeline_sheet(
        workbook: Workbook, results: Sequence[SSLResult]
    ) -> None:
        headers = ["Target", "Days remaining", "Alert", "Not after", "Issuer"]
        rows: List[List[Any]] = []
        for result in sorted(
            results,
            key=lambda r: (r.days_remaining if r.days_remaining is not None else 10**6),
        ):
            lifetime = (
                result.certificate.lifetime if result.certificate is not None else None
            )
            rows.append(
                [
                    result.target,
                    result.days_remaining,
                    result.expiry_alert.value,
                    lifetime.not_after.date().isoformat() if lifetime else None,
                    (
                        result.certificate.issuer_cn
                        if result.certificate is not None
                        else None
                    ),
                ]
            )

        add_coloured_table_sheet(
            workbook,
            "Expiry Timeline",
            headers,
            rows,
            lambda values: _ALERT_FILLS.get(str(values[2]), FILL_AMBER),
        )

    @staticmethod
    def _add_certificate_sheet(
        workbook: Workbook, results: Sequence[SSLResult]
    ) -> None:
        rows: List[Dict[str, Any]] = []
        for result in results:
            certificate = result.certificate
            if certificate is None:
                continue
            lifetime = certificate.lifetime
            rows.append(
                {
                    "Target": result.target,
                    "Subject CN": certificate.subject_cn,
                    "Issuer": certificate.issuer_cn,
                    "Serial": certificate.serial_number,
                    "Key": (
                        f"{certificate.public_key.key_type.value} "
                        f"{certificate.public_key.key_size or ''}".strip()
                    ),
                    "Weak key": certificate.public_key.weak,
                    "Sig hash": certificate.signature_hash,
                    "Weak sig": certificate.signature_weak,
                    "Lifetime days": lifetime.lifetime_days if lifetime else None,
                    "Lifetime verdict": lifetime.verdict.value if lifetime else None,
                    "Short-lived": lifetime.short_lived if lifetime else None,
                    "SANs": len(certificate.san_dns),
                    "Wildcard": certificate.wildcard.present,
                    "Must-staple": certificate.revocation.must_staple,
                    "OCSP": len(certificate.revocation.ocsp_urls),
                    "CRL": len(certificate.revocation.crl_urls),
                    "SHA-256": (
                        certificate.fingerprints.cert_sha256
                        if certificate.fingerprints
                        else None
                    ),
                }
            )
        add_simple_table_sheet(workbook, "Certificates", pd.DataFrame(rows))

    @staticmethod
    def _add_raw_sheet(workbook: Workbook, results: Sequence[SSLResult]) -> None:
        add_simple_table_sheet(
            workbook, "Raw Results", pd.DataFrame(_raw_rows(results))
        )

    @staticmethod
    def _add_threshold_sheet(
        workbook: Workbook, threshold_results: Dict[str, List[ThresholdResult]]
    ) -> None:
        headers = [
            "Target",
            "Threshold",
            "Metric",
            "Limit",
            "Actual",
            "Passed",
            "Error",
        ]
        rows: List[List[Any]] = [
            [
                target,
                str(entry.threshold),
                entry.threshold.metric,
                entry.threshold.value,
                entry.actual,
                entry.passed,
                entry.error,
            ]
            for target, entries in threshold_results.items()
            for entry in entries
        ]
        add_coloured_table_sheet(
            workbook,
            "Thresholds",
            headers,
            rows,
            lambda values: FILL_GREEN if values[5] else FILL_RED,
        )

    @staticmethod
    def _add_charts_sheet(
        workbook: Workbook, analyzer: SSLAnalyzer, temp_dir: str
    ) -> List[str]:
        """Build chart PNGs and embed them. Returns paths for the caller to clean up."""
        stats_list = analyzer.get_target_statistics()
        if not stats_list:
            return []

        entries: List[Any] = []
        paths: List[str] = []

        with_certs = [s for s in stats_list if s.cert_expiry_days_min is not None]
        if with_certs:
            path = os.path.join(temp_dir, "ssl_expiry.png")
            # Thresholds are inverted relative to latency: MORE days remaining
            # is better, so green is the high end. generate_bar_chart takes
            # invert_colours precisely for this, and its docstring names
            # days_remaining as the case.
            generate_bar_chart(
                [s.target for s in with_certs],
                [float(s.cert_expiry_days_min or 0) for s in with_certs],
                "Days remaining",
                "Days until certificate expiry",
                path,
                thresholds=(14.0, 30.0),
                value_fmt="{:.0f}",
                invert_colours=True,
            )
            entries.append(("A3", "A4", path))
            paths.append(path)

        measured = [s for s in stats_list if s.measured_checks > 0]
        if measured:
            path = os.path.join(temp_dir, "ssl_handshake.png")
            generate_bar_chart(
                [s.target for s in measured],
                [s.avg_latency for s in measured],
                "Milliseconds",
                "Mean TLS handshake time",
                path,
            )
            entries.append(("A23", "A24", path))
            paths.append(path)

        if entries:
            embed_charts_sheet(workbook, "Charts", entries, "SSL/TLS Charts")
        return paths

    @staticmethod
    def _add_provenance_sheet(workbook: Workbook, provenance: Dict[str, Any]) -> None:
        sheet = workbook.create_sheet("Provenance")
        sheet["A1"] = "Key"
        sheet["B1"] = "Value"
        sheet["A1"].font = Font(bold=True)
        sheet["B1"].font = Font(bold=True)
        for index, (key, value) in enumerate(sorted(provenance.items()), start=2):
            sheet.cell(row=index, column=1, value=key)
            sheet.cell(row=index, column=2, value=str(value))
        autosize_columns(sheet)


# ---------------------------------------------------------------------------
# JSON bundle
# ---------------------------------------------------------------------------


@dataclass
class SSLExportBundle:
    """JSON export of an entire run (item 51)."""

    @staticmethod
    def export_json(
        results: Sequence[SSLResult],
        analyzer: SSLAnalyzer,
        output_path: str,
        threshold_results: Optional[Dict[str, List[ThresholdResult]]] = None,
        provenance: Optional[Dict[str, Any]] = None,
    ) -> None:
        payload: Dict[str, Any] = {
            "schema_version": 1,
            "module": "ssl",
            "generated_at": datetime.now(tz=timezone.utc).isoformat(),
            "provenance": provenance or build_provenance(),
            "overall": analyzer.get_overall_statistics(),
            "targets": [s.to_dict() for s in analyzer.get_target_statistics()],
            "expiry_timeline": expiry_timeline(results),
            "results": [r.to_dict() for r in results],
            "failed_targets": [
                {"target": t, "status": s, "error": e}
                for t, s, e in analyzer.get_failed_targets()
            ],
        }
        if threshold_results:
            # Flat list with an explicit target field per entry, not a dict
            # keyed by target — every other collection in this payload
            # ("results", "targets") is a flat list, and a reader iterating
            # this payload with a generic JSON tool should not need a special
            # case for one key being shaped differently from the rest.
            payload["thresholds"] = [
                {**entry.to_dict(), "target": target}
                for target, entries in threshold_results.items()
                for entry in entries
            ]
        with open(output_path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, default=str)

    @staticmethod
    def export_threshold_results(
        results_by_target: Dict[str, List[ThresholdResult]],
        output_path: str,
        filename_prefix: str,
    ) -> str:
        """Write threshold outcomes to CSV, one row per (target, threshold).

        Mirrors HTTPExportBundle.export_threshold_results exactly, same
        signature shape and same reasoning: a failed CI run needs a
        structured record of WHICH target and WHICH criterion failed, once
        the console output that showed it is gone. Accepts the mapping from
        SSLAnalyzer.get_thresholds_report().
        """
        path = os.path.join(output_path, f"{filename_prefix}_thresholds.csv")
        fieldnames = [
            "target",
            "threshold",
            "metric",
            "op",
            "limit",
            "actual",
            "passed",
            "error",
        ]
        with open(path, "w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(
                handle, fieldnames=fieldnames, extrasaction="ignore"
            )
            writer.writeheader()
            for target, results in results_by_target.items():
                for result in results:
                    row = dict(result.to_dict())
                    row["target"] = target
                    writer.writerow(row)
        return path


# ---------------------------------------------------------------------------
# PDF
# ---------------------------------------------------------------------------


class SSLPDFExporter:
    """PDF report via WeasyPrint, available through the `[pdf]` extra (item 52)."""

    @staticmethod
    def export_results(
        results: Sequence[SSLResult],
        analyzer: SSLAnalyzer,
        output_path: str,
        provenance: Optional[Dict[str, Any]] = None,
    ) -> None:
        try:
            from weasyprint import HTML
        except ImportError as exc:
            raise RuntimeError(
                "PDF export requires the [pdf] extra: pip install "
                "'net-benchmark[pdf]'"
            ) from exc

        html = SSLPDFExporter._generate_html(
            results, analyzer, provenance or build_provenance()
        )
        HTML(string=html).write_pdf(output_path)

    @staticmethod
    def _generate_html(
        results: Sequence[SSLResult],
        analyzer: SSLAnalyzer,
        provenance: Dict[str, Any],
    ) -> str:
        overall = analyzer.get_overall_statistics()
        stats_list = analyzer.get_target_statistics()

        rows = "".join(
            "<tr>"
            f"<td>{s.target}</td>"
            f"<td>{s.measured_checks}/{s.total_checks}</td>"
            f"<td>{s.avg_latency:.1f}</td>"
            f"<td>{'' if s.percentiles_refused else f'{s.p95_latency:.1f}'}</td>"
            f"<td>{s.cert_expiry_days_min if s.cert_expiry_days_min is not None else '—'}</td>"
            f"<td class='{s.worst_expiry_alert}'>{s.worst_expiry_alert}</td>"
            f"<td>{s.tls13_rate:.0f}%</td>"
            "</tr>"
            for s in stats_list
        )

        failed = "".join(
            f"<tr><td>{t}</td><td>{s}</td><td>{e or ''}</td></tr>"
            for t, s, e in analyzer.get_failed_targets()
        )

        return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>SSL/TLS Report</title>
<style>
body {{ font-family: sans-serif; font-size: 11px; }}
h1 {{ font-size: 20px; }}
table {{ border-collapse: collapse; width: 100%; margin-bottom: 18px; }}
th, td {{ border: 1px solid #ccc; padding: 4px 6px; text-align: left; }}
th {{ background: #e0e0e0; }}
.expired, .critical {{ background: #ffc7ce; }}
.warning, .notice, .unknown {{ background: #ffeb9c; }}
.ok {{ background: #c6efce; }}
.meta {{ color: #666; font-size: 10px; }}
</style></head><body>
<h1>SSL/TLS Report</h1>
<p class="meta">Generated {provenance.get('retrieved_at')} &middot;
trust store {provenance.get('trust_store')}
{provenance.get('trust_store_version') or 'version unknown'} &middot;
{provenance.get('openssl_version')}</p>
<p>{overall['measured_checks']} of {overall['total_checks']} targets measured
across {overall['hosts']} hosts.
Certificates observed: {overall['certificates_observed']}.
Soonest expiry: {overall['cert_expiry_days_min'] if overall['cert_expiry_days_min'] is not None else '—'} days.</p>
<h2>Targets</h2>
<table><tr><th>Target</th><th>Measured</th><th>Mean ms</th><th>P95 ms</th>
<th>Days left</th><th>Alert</th><th>TLS 1.3</th></tr>{rows}</table>
{'<h2>Unreachable</h2><table><tr><th>Target</th><th>Status</th><th>Error</th></tr>' + failed + '</table>' if failed else ''}
</body></html>"""
