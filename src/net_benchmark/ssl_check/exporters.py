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
from dataclasses import dataclass, field
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
from net_benchmark.ssl_check.enumeration import (
    DEFAULT_VERSION_CANDIDATES,
    EnumerationResult,
)
from net_benchmark.ssl_check.topology import MultiCertGroup

__all__ = [
    "ReportBranding",
    "SSLCSVExporter",
    "SSLExcelExporter",
    "SSLExportBundle",
    "SSLPDFExporter",
    "build_provenance",
]


# ---------------------------------------------------------------------------
# Report branding — SaaS-side only
# ---------------------------------------------------------------------------
# Deliberately not exposed through any CLI flag. The capability lives here,
# in the shared engine, so a SaaS layer imports and tests the exact same
# PDF/Excel generation code the OSS CLI uses rather than re-implementing or
# post-processing the output separately -- the same "build once" principle
# every other engine addition in this project follows. Whether a caller is
# allowed to set it (a paid-tier gate) is a decision for whatever imports
# this, not for the exporter itself: `None` here means exactly today's
# default output, and every CLI call site passes `None`.


@dataclass
class ReportBranding:
    """Optional PDF/Excel report customization. `None` at any call site
    (every one the CLI itself uses) means unchanged default output.

    `logo_bytes` is raw image bytes, not a file path — a SaaS caller has
    an uploaded logo in memory, not a filesystem location, and embedding
    by path would mean resolving and trusting a path from user input.
    """

    report_title: str = "SSL/TLS Report"
    organization_name: Optional[str] = None
    logo_bytes: Optional[bytes] = None
    logo_mime_type: str = "image/png"


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

# Oldest-to-newest rank, reusing enumeration.py's own ordering rather than a
# second one that could silently drift from it. Lexicographic string
# comparison on version names ("TLSv1.3" > "TLSv1.2") happens to agree with
# this for the current five version strings, which is exactly the kind of
# accidental correctness not worth relying on — an explicit rank is used
# instead of `max()` on the strings themselves.
_VERSION_RANK = {
    version: i for i, (version, _) in enumerate(DEFAULT_VERSION_CANDIDATES)
}


def _highest_supported_version(enumeration: EnumerationResult) -> Optional[str]:
    supported = [v for v in enumeration.versions if v.supported]
    if not supported:
        return None
    highest = max(supported, key=lambda v: _VERSION_RANK.get(v.version, -1))
    return highest.version.value


# ---------------------------------------------------------------------------
# Per-host grade (0.6.1 items 19-20)
# ---------------------------------------------------------------------------
#
# Deliberately not routed through SSLAnalyzer/HostStats: that pipeline
# aggregates *rates across samples* (e.g. "70% of handshake samples
# negotiated TLS 1.3"), which fits facts that can genuinely vary attempt to
# attempt. chain_audit/revocation_audit/ct_audit/lint_audit/enumeration each
# run once per SSLResult, not once per handshake sample -- there is no
# meaningful "rate" for "was the chain valid" the way there is for latency.
# Computed straight from the SSLResult list instead, one grade per target,
# worst-case across results when a target produced more than one (same
# pattern HostStats.worst_expiry_alert already uses for the same reason:
# a single bad result is the finding, not something an average should
# smooth over).

# Worst-first, so a target with any FATAL/ERROR-severity lint finding across
# its results reports that, not a WARNING from a different result.
_LINT_SEVERITY_PRIORITY = ["fatal", "error", "warning", "notice", "info", "debug"]
_CIPHER_STRENGTH_PRIORITY = ["F", "C", "B", "A"]
# Best to worst, matching grading.Grade's own ordering (that list is
# private to grading.py; duplicated here rather than imported, since this
# is purely a display-priority concern for the summary sheet, not a
# grading decision). M and T are placed after F: neither is "worse than F"
# in the guide's own sense (they mean the A-F scale doesn't apply at all),
# but for a single worst-case summary column, treating a trust/name
# problem as the most severe finding is the more useful simplification.
_SSL_LABS_GRADE_PRIORITY = ["F", "E", "D", "C", "B", "A-", "A", "A+", "T", "M"]


@dataclass
class HostGrade:
    """Per-target summary of the 0.6.1 opt-in checks, for the Excel grade
    sheet and the PDF findings section. Every field is `None`/empty when the
    corresponding check never ran for this target, not a false negative.
    """

    target: str
    validation_level: Optional[str] = None
    chain_verified: Optional[bool] = None
    chain_error: Optional[str] = None
    revoked: Optional[bool] = None
    ct_all_trusted: Optional[bool] = None
    weakest_cipher_strength: Optional[str] = None
    lint_worst_severity: Optional[str] = None
    lint_finding_count: int = 0
    # 0.6.2 items 20-21 — worst (lowest) SSL Labs-style grade seen across
    # this target's results, string-compared via the same letter ordering
    # grading.py itself uses (see grading._GRADE_ORDER); not folded into
    # `overall_ok` below, since a B or C grade is informative, not a
    # pass/fail verdict the way the other fields here are.
    ssl_labs_grade: Optional[str] = None
    policy_failures: List[str] = field(default_factory=list)

    @property
    def overall_ok(self) -> Optional[bool]:
        """False if any attempted check found a problem; True if every
        attempted check passed cleanly; None if nothing here was attempted
        at all (every field still at its default).
        """
        attempted = False
        problems = bool(self.policy_failures)
        if self.chain_verified is not None:
            attempted = True
            problems = problems or not self.chain_verified
        if self.revoked is not None:
            attempted = True
            problems = problems or self.revoked
        if self.ct_all_trusted is not None:
            attempted = True
            problems = problems or not self.ct_all_trusted
        if self.lint_worst_severity in ("fatal", "error"):
            attempted = True
            problems = True
        elif self.lint_worst_severity is not None:
            attempted = True
        if not attempted and not self.policy_failures:
            return None
        return not problems


def _compute_host_grades(results: Sequence[SSLResult]) -> List[HostGrade]:
    grades: Dict[str, HostGrade] = {}
    for result in results:
        grade = grades.setdefault(result.target, HostGrade(target=result.target))

        if result.certificate is not None:
            grade.validation_level = result.certificate.validation_level.value

        if result.chain_audit is not None and result.chain_audit.attempted:
            if grade.chain_verified is not False:
                grade.chain_verified = result.chain_audit.verified
                grade.chain_error = result.chain_audit.verification_error

        if result.revocation_audit is not None and result.revocation_audit.attempted:
            if result.revocation_audit.revoked is not None:
                grade.revoked = bool(grade.revoked) or result.revocation_audit.revoked

        if result.ct_audit is not None and result.ct_audit.attempted:
            if result.ct_audit.all_trusted is not None:
                grade.ct_all_trusted = (
                    grade.ct_all_trusted is not False
                ) and result.ct_audit.all_trusted

        if result.enumeration is not None:
            weakest = result.enumeration.weakest_supported_cipher_strength
            if weakest is not None:
                candidates = [
                    c for c in (grade.weakest_cipher_strength, weakest.value) if c
                ]
                if candidates:
                    grade.weakest_cipher_strength = min(
                        candidates, key=_CIPHER_STRENGTH_PRIORITY.index
                    )

        if result.grade is not None and result.grade.grade is not None:
            new_value = result.grade.grade.value
            candidates = [g for g in (grade.ssl_labs_grade, new_value) if g]
            if candidates:
                grade.ssl_labs_grade = min(
                    candidates, key=_SSL_LABS_GRADE_PRIORITY.index
                )

        if result.lint_audit is not None and result.lint_audit.attempted:
            grade.lint_finding_count += len(result.lint_audit.findings)
            severities = [f.severity.value for f in result.lint_audit.findings]
            if grade.lint_worst_severity is not None:
                severities.append(grade.lint_worst_severity)
            for level in _LINT_SEVERITY_PRIORITY:
                if level in severities:
                    grade.lint_worst_severity = level
                    break

        for failure in result.policy_failures:
            if failure not in grade.policy_failures:
                grade.policy_failures.append(failure)

    return list(grades.values())


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
                # --- validation level (0.6.1 item 14) and SCTs (item 11) ------
                "cert_validation_level": (
                    certificate.validation_level.value
                    if certificate is not None
                    else None
                ),
                "cert_sct_count": (
                    len(certificate.scts) if certificate is not None else None
                ),
                # --- validated chain (roadmap discussion #45, items 11-16) --
                # None throughout when the scan did not run with
                # --verify-chain, same convention as the rest of this row: a
                # check that did not run reports as "not evaluated", not as
                # a failure.
                "chain_verified": (
                    result.chain_audit.verified
                    if result.chain_audit is not None
                    else None
                ),
                "chain_depth": (
                    result.chain_audit.depth if result.chain_audit is not None else None
                ),
                "chain_missing_intermediate": (
                    result.chain_audit.missing_intermediate
                    if result.chain_audit is not None
                    else None
                ),
                "chain_weak_hash": (
                    result.chain_audit.weak_hash_in_chain
                    if result.chain_audit is not None
                    else None
                ),
                "chain_cross_signed": (
                    result.chain_audit.cross_signed
                    if result.chain_audit is not None
                    else None
                ),
                "chain_root_cn": (
                    result.chain_audit.root.subject_cn
                    if result.chain_audit is not None and result.chain_audit.root
                    else None
                ),
                "chain_verification_error": (
                    result.chain_audit.verification_error
                    if result.chain_audit is not None
                    else None
                ),
                # --- live revocation (roadmap discussion #45, items 17-18) --
                "revocation_checked": (
                    result.revocation_audit.attempted
                    if result.revocation_audit is not None
                    else None
                ),
                "revoked": (
                    result.revocation_audit.revoked
                    if result.revocation_audit is not None
                    else None
                ),
                "ocsp_status": (
                    result.revocation_audit.ocsp_status.value
                    if result.revocation_audit is not None
                    else None
                ),
                "crl_status": (
                    result.revocation_audit.crl_status.value
                    if result.revocation_audit is not None
                    else None
                ),
                # --- protocol & cipher enumeration (0.6.1 items 1-3) ---------
                "max_supported_tls_version": (
                    _highest_supported_version(result.enumeration)
                    if result.enumeration is not None
                    else None
                ),
                "weakest_supported_cipher_strength": (
                    result.enumeration.weakest_supported_cipher_strength.value
                    if result.enumeration is not None
                    and result.enumeration.weakest_supported_cipher_strength is not None
                    else None
                ),
                "server_enforces_cipher_order": (
                    result.cipher_preference.server_enforces_order
                    if result.cipher_preference is not None
                    else None
                ),
                # --- IPv4/IPv6 certificate consistency (0.6.1 item 17) --------
                "dual_stack_consistent": (
                    result.dual_stack_audit.consistent
                    if result.dual_stack_audit is not None
                    else None
                ),
                # --- TLS deep introspection via CryptoLyzer (0.6.2 items 1-9) --
                "deep_introspection_availability": (
                    result.deep_introspection.availability.value
                    if result.deep_introspection is not None
                    else None
                ),
                "negotiable_tls13_cipher_count": (
                    len(result.deep_introspection.tls13_ciphers.suites)
                    if result.deep_introspection is not None
                    and result.deep_introspection.tls13_ciphers is not None
                    else None
                ),
                "dhe_key_reuse": (
                    result.deep_introspection.dh_params.key_reuse
                    if result.deep_introspection is not None
                    and result.deep_introspection.dh_params is not None
                    else None
                ),
                "post_quantum_group_negotiable": (
                    bool(result.deep_introspection.named_groups.post_quantum_groups)
                    if result.deep_introspection is not None
                    and result.deep_introspection.named_groups is not None
                    else None
                ),
                "vulnerability_flags_set": (
                    ",".join(
                        name
                        for name in (
                            "sweet32",
                            "anonymous_dh",
                            "rc4",
                            "non_forward_secret",
                            "null_encryption",
                            "lucky13",
                            "freak",
                            "logjam",
                            "export_grade",
                            "weak_dh",
                            "dheat",
                            "drown",
                            "insecure_ssl_version",
                            "inappropriate_version_fallback",
                            "poodle",
                            "beast",
                        )
                        if getattr(
                            result.deep_introspection.vulnerabilities, name, None
                        )
                        is True
                    )
                    if result.deep_introspection is not None
                    and result.deep_introspection.vulnerabilities is not None
                    else None
                ),
                # --- SSL Labs-style grade (0.6.2 items 20-21) ------------------
                "ssl_labs_grade": (
                    result.grade.grade.value
                    if result.grade is not None and result.grade.grade is not None
                    else None
                ),
                "ssl_labs_numerical_score": (
                    result.grade.numerical_score if result.grade is not None else None
                ),
                # --- Server Side TLS profile compliance (0.6.2 item 21) --------
                "mozilla_profile_compliance": (
                    ",".join(
                        f"{name}={r.compliant}"
                        for name, r in result.mozilla_profile_audit.results.items()
                    )
                    if result.mozilla_profile_audit is not None
                    else None
                ),
                # --- JARM server fingerprinting (0.6.2 item 24) -----------------
                "jarm_fingerprint": (
                    result.jarm.fingerprint if result.jarm is not None else None
                ),
                # --- Full multi-store trust validation (0.6.2 item 22) ----------
                "multi_store_consistent": (
                    result.multi_store_audit.consistent
                    if result.multi_store_audit is not None
                    else None
                ),
                # --- Multi-SAN audit against active subdomains (0.6.2 item 27) --
                "san_inactive_count": (
                    len(result.san_audit.inactive_sans)
                    if result.san_audit is not None
                    else None
                ),
                "san_inconsistent_count": (
                    len(result.san_audit.inconsistent_sans)
                    if result.san_audit is not None
                    else None
                ),
                # --- TLS 1.3 0-RTT timing (0.6.2 item 11) ------------------------
                "zero_rtt_status": (
                    result.zero_rtt_timing.early_data_status
                    if result.zero_rtt_timing is not None
                    else None
                ),
                "zero_rtt_savings_ms": (
                    result.zero_rtt_timing.early_data_savings_ms
                    if result.zero_rtt_timing is not None
                    else None
                ),
                # --- CT log trust status (0.6.1 items 10, 12) -----------------
                "ct_all_scts_trusted": (
                    result.ct_audit.all_trusted if result.ct_audit is not None else None
                ),
                # --- CA/B Baseline Requirements linting (0.6.1 item 37) --------
                "lint_availability": (
                    result.lint_audit.availability.value
                    if result.lint_audit is not None
                    else None
                ),
                "lint_finding_count": (
                    len(result.lint_audit.findings)
                    if result.lint_audit is not None
                    else None
                ),
                "lint_has_errors_or_worse": (
                    result.lint_audit.has_errors_or_worse
                    if result.lint_audit is not None
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
        branding: Optional[ReportBranding] = None,
    ) -> None:
        workbook = Workbook()
        default = workbook.active
        if default is not None:
            workbook.remove(default)

        if branding:
            workbook.properties.title = branding.report_title
            if branding.organization_name:
                workbook.properties.creator = branding.organization_name

        temp_dir: Optional[str] = None
        chart_paths: List[str] = []

        try:
            SSLExcelExporter._add_summary_sheet(workbook, analyzer, branding)
            SSLExcelExporter._add_grade_sheet(workbook, results)
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
    def _add_summary_sheet(
        workbook: Workbook,
        analyzer: SSLAnalyzer,
        branding: Optional[ReportBranding] = None,
    ) -> None:
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

        if branding:
            sheet = workbook["Summary"]
            sheet.insert_rows(1, amount=2)
            sheet["A1"] = branding.report_title
            sheet["A1"].font = Font(bold=True, size=14)
            if branding.organization_name:
                sheet["A2"] = branding.organization_name
            if branding.logo_bytes:
                import io as _io

                from openpyxl.drawing.image import Image as XLImage

                logo = XLImage(_io.BytesIO(branding.logo_bytes))
                logo.height = 40
                logo.width = 120
                sheet.add_image(logo, "D1")

    @staticmethod
    def _add_grade_sheet(workbook: Workbook, results: Sequence[SSLResult]) -> None:
        """Per-host grade sheet (item 20): one row per target summarising
        the 0.6.1 opt-in checks (chain validation, revocation, CT log
        trust, weakest negotiable cipher, CA/B lint findings). Blank, not a
        false "pass", for any check that never ran on that target -- see
        `HostGrade`.
        """
        rows: List[Dict[str, Any]] = []
        for grade in sorted(_compute_host_grades(results), key=lambda g: g.target):
            rows.append(
                {
                    "Target": grade.target,
                    "Overall": (
                        "—"
                        if grade.overall_ok is None
                        else ("OK" if grade.overall_ok else "FAIL")
                    ),
                    "Validation level": grade.validation_level,
                    "Chain verified": grade.chain_verified,
                    "Chain error": grade.chain_error,
                    "Revoked": grade.revoked,
                    "CT logs trusted": grade.ct_all_trusted,
                    "Weakest cipher": grade.weakest_cipher_strength,
                    "Lint worst severity": grade.lint_worst_severity,
                    "Lint findings": grade.lint_finding_count,
                    "SSL Labs grade": grade.ssl_labs_grade,
                    "Policy failures": (
                        "; ".join(grade.policy_failures)
                        if grade.policy_failures
                        else None
                    ),
                }
            )
        add_simple_table_sheet(workbook, "Per-Host Grade", pd.DataFrame(rows))

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
        virtual_hosting: Optional[Sequence[MultiCertGroup]] = None,
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
        if virtual_hosting:
            # Item 16 — separate top-level key, not folded into "results":
            # it's a property of a *group* of results (one IP, several
            # hostnames), not of any single one.
            payload["virtual_hosting"] = [g.to_dict() for g in virtual_hosting]
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
        branding: Optional[ReportBranding] = None,
    ) -> None:
        try:
            from weasyprint import HTML
        except ImportError as exc:
            raise RuntimeError(
                "PDF export requires the [pdf] extra: pip install "
                "'net-benchmark[pdf]'"
            ) from exc

        html = SSLPDFExporter._generate_html(
            results, analyzer, provenance or build_provenance(), branding
        )
        HTML(string=html).write_pdf(output_path)

    @staticmethod
    def _generate_html(
        results: Sequence[SSLResult],
        analyzer: SSLAnalyzer,
        provenance: Dict[str, Any],
        branding: Optional[ReportBranding] = None,
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

        grades = sorted(_compute_host_grades(results), key=lambda g: g.target)
        # Gated on whether any *new* 0.6.1 check ran, not on `overall_ok`
        # generally — `overall_ok` also folds in ordinary policy failures
        # (expiry, deprecated TLS, ...), which already have their own
        # column in the Targets table above. This section exists to add
        # what isn't already visible there, so a host whose only problem is
        # an existing policy failure doesn't pull the whole section in.
        attempted_grades = [
            g
            for g in grades
            if g.chain_verified is not None
            or g.revoked is not None
            or g.ct_all_trusted is not None
            or g.weakest_cipher_strength is not None
            or g.lint_finding_count
        ]

        def _grade_cell(value: Optional[bool], true_word: str, false_word: str) -> str:
            if value is None:
                return "<td>—</td>"
            css = "ok" if not value else "critical"
            # revoked=True and chain_verified=False both mean "bad" — the
            # caller passes true_word/false_word already oriented so "bad"
            # always lands on the value that should be highlighted red.
            return f"<td class='{css}'>{true_word if value else false_word}</td>"

        grade_rows_parts: List[str] = []
        for g in attempted_grades:
            overall_css = (
                "ok" if g.overall_ok else ("critical" if g.overall_ok is False else "")
            )
            overall_text = (
                "—" if g.overall_ok is None else ("OK" if g.overall_ok else "FAIL")
            )
            grade_rows_parts.append(
                "<tr>"
                f"<td>{g.target}</td>"
                f"<td class='{overall_css}'>{overall_text}</td>"
                f"<td>{g.validation_level or '—'}</td>"
                + _grade_cell(
                    None if g.chain_verified is None else not g.chain_verified,
                    "invalid",
                    "verified",
                )
                + _grade_cell(g.revoked, "revoked", "not revoked")
                + _grade_cell(
                    None if g.ct_all_trusted is None else not g.ct_all_trusted,
                    "untrusted log",
                    "trusted",
                )
                + f"<td>{g.weakest_cipher_strength or '—'}</td>"
                + f"<td>{g.lint_finding_count or '—'}</td>"
                + "</tr>"
            )
        grade_rows = "".join(grade_rows_parts)

        findings_section = (
            f"""<h2>Findings summary</h2>
<table><tr><th>Target</th><th>Overall</th><th>Validation</th><th>Chain</th>
<th>Revocation</th><th>CT logs</th><th>Weakest cipher</th><th>Lint findings</th></tr>
{grade_rows}</table>"""
            if attempted_grades
            else ""
        )

        title = branding.report_title if branding else "SSL/TLS Report"
        byline = (
            f'<p class="meta">{branding.organization_name}</p>'
            if branding and branding.organization_name
            else ""
        )
        logo_html = ""
        if branding and branding.logo_bytes:
            import base64

            encoded = base64.b64encode(branding.logo_bytes).decode("ascii")
            logo_html = (
                f'<img src="data:{branding.logo_mime_type};base64,{encoded}" '
                'style="max-height:48px;max-width:220px;" alt="logo">'
            )

        return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>{title}</title>
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
{logo_html}
<h1>{title}</h1>
{byline}
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
{findings_section}
{'<h2>Unreachable</h2><table><tr><th>Target</th><th>Status</th><th>Error</th></tr>' + failed + '</table>' if failed else ''}
</body></html>"""
