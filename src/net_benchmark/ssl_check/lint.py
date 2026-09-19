"""Certificate profile linting against the CA/Browser Forum Baseline
Requirements, via pkilint (0.6.1 item 37).

Optional `[lint]` extra
-------------------------
pkilint is MIT-licensed (DigiCert) and its own dependency tree is entirely
permitted -- verified against the dependency policy before adding this:
`pyasn1`/`pyasn1-alt-modules` (BSD), `iso3166`/`validators` (MIT),
`publicsuffixlist` (MPL-2.0), `python-dateutil`/`python-iso639`
(Apache/BSD), `iso4217` (public domain) -- except for one: `pyasn1-fasder`
is a second compiled (Rust) dependency. The dependency policy allows that
inside an optional extra but not in the base install (item 3: "exactly one
compiled dependency in the base install"), so pkilint lives behind
`net-benchmark[lint]`, imported lazily here rather than at module import
time -- the base install has no dependency on it at all, and a caller
without the extra installed gets a clear, actionable error instead of an
ImportError surfacing from deep inside this module.

Confirmed by installing it and checking the resolved dependency tree before
writing this: bare `pkilint` pulls none of `pkilint[rest]`'s FastAPI /
Starlette / Pydantic (a second Rust extension, `pydantic-core`, for a REST
API this tool never runs) -- `pyproject.toml`'s `[lint]` extra pins bare
`pkilint` for exactly that reason. `pyasn1-fasder` installed cleanly from a
wheel on this platform/Python version; the roadmap's "verify it builds on
3.13 and 3.14" is separate, forward-looking work this doesn't attempt to
close out.

Every finding is labelled with its source and pkilint's own version, per
dependency policy item 4 -- a finding this module reports is pkilint's
verdict, not net-benchmark's own.

Certificate type and validity-period-start
---------------------------------------------
The certificate type (DV/OV/EV/IV final certificate, or a CA type) is
auto-detected from the CA/B Forum policy OID, EKU, name constraints and
basic constraints -- pkilint's own default behaviour
(`lint_cabf_serverauth_cert lint -d`), not forced, since forcing the wrong
type onto a certificate would produce findings about the wrong profile
entirely. `validity_period_start` is left at pkilint's own default (the
certificate's own `notBefore`) rather than wired to this tool's `--as-of` --
the two answer different questions. `--as-of` asks "is this chain valid as
of a given instant"; linting asks "which version of the Baseline
Requirements applied when this certificate was *issued*", which is a fact
about the certificate itself, not about when the scan happens to run.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class LintAvailability(str, Enum):
    AVAILABLE = "available"
    NOT_INSTALLED = "not_installed"


class FindingSeverity(str, Enum):
    FATAL = "fatal"
    ERROR = "error"
    WARNING = "warning"
    NOTICE = "notice"
    INFO = "info"
    DEBUG = "debug"


_SEVERITY_FROM_PKILINT = {
    "FATAL": FindingSeverity.FATAL,
    "ERROR": FindingSeverity.ERROR,
    "WARNING": FindingSeverity.WARNING,
    "NOTICE": FindingSeverity.NOTICE,
    "INFO": FindingSeverity.INFO,
    "DEBUG": FindingSeverity.DEBUG,
}


@dataclass
class LintFinding:
    severity: FindingSeverity
    code: str
    message: Optional[str]
    node_path: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "severity": self.severity.value,
            "code": self.code,
            "message": self.message,
            "node_path": self.node_path,
        }


@dataclass
class LintAudit:
    attempted: bool = False
    availability: LintAvailability = LintAvailability.NOT_INSTALLED
    pkilint_version: Optional[str] = None
    detected_certificate_type: Optional[str] = None
    findings: List[LintFinding] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def has_errors_or_worse(self) -> Optional[bool]:
        """True if any FATAL- or ERROR-severity finding was reported.
        WARNING/NOTICE/INFO/DEBUG findings are informational, not blocking.
        None when linting wasn't attempted or wasn't available -- distinct
        from False, which means it ran and found nothing at that severity.
        """
        if not self.attempted or self.availability is not LintAvailability.AVAILABLE:
            return None
        return any(
            f.severity in (FindingSeverity.FATAL, FindingSeverity.ERROR)
            for f in self.findings
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "attempted": self.attempted,
            "availability": self.availability.value,
            "pkilint_version": self.pkilint_version,
            "detected_certificate_type": self.detected_certificate_type,
            "findings": [f.to_dict() for f in self.findings],
            "has_errors_or_worse": self.has_errors_or_worse,
            "error": self.error,
        }


def lint_availability() -> LintAvailability:
    try:
        import pkilint  # noqa: F401
    except ImportError:
        return LintAvailability.NOT_INSTALLED
    return LintAvailability.AVAILABLE


def lint_certificate(
    der: bytes,
    *,
    severity_threshold: FindingSeverity = FindingSeverity.INFO,
    report_all: bool = False,
) -> LintAudit:
    """Lint one certificate against the CA/Browser Forum TLS Baseline
    Requirements.

    Synchronous -- pkilint does no I/O, this is pure computation on bytes
    already in hand -- so this is called directly from the engine, not
    through the async probe pipeline, same reasoning as `certificate.py`'s
    `parse_certificate`.

    `report_all=False` (the default) filters out PKIX-level findings that
    are superseded by a more specific CA/Browser Forum requirement, matching
    the linter's own CLI default -- reporting both would double-count the
    same underlying issue under two different findings.
    """
    audit = LintAudit(attempted=True)

    try:
        import pkilint  # noqa: F401 — presence check; version read via importlib.metadata below
        from pkilint import finding_filter, loader, report
        from pkilint.cabf import serverauth
        from pkilint.pkix import certificate as pkix_certificate
    except ImportError:
        audit.availability = LintAvailability.NOT_INSTALLED
        audit.error = (
            "pkilint is not installed. Certificate profile linting requires "
            "the [lint] extra: pip install 'net-benchmark[lint]'"
        )
        return audit

    audit.availability = LintAvailability.AVAILABLE
    try:
        import importlib.metadata

        audit.pkilint_version = importlib.metadata.version("pkilint")
    except importlib.metadata.PackageNotFoundError:  # pragma: no cover — defensive
        audit.pkilint_version = None

    try:
        doc = loader.RFC5280CertificateDocumentLoader().load_der_document(der)
    except ValueError as exc:
        audit.error = f"certificate could not be loaded for linting: {exc}"
        return audit

    try:
        certificate_type = serverauth.determine_certificate_type(doc)
        audit.detected_certificate_type = certificate_type.to_option_str

        doc_validator = pkix_certificate.create_pkix_certificate_validator_container(
            serverauth.create_decoding_validators(),
            serverauth.create_validators(certificate_type),
        )
        results = doc_validator.validate(doc.root)
        if not report_all:
            results, _ = finding_filter.filter_results(
                serverauth.create_serverauth_finding_filters(certificate_type),
                results,
            )

        pkilint_severity = getattr(
            report.ValidationFindingSeverity, severity_threshold.name
        )
        generator = report.ReportGeneratorJson(results, pkilint_severity)
        parsed = json.loads(generator.generate())
        for entry in parsed["results"]:
            for finding_description in entry["finding_descriptions"]:
                audit.findings.append(
                    LintFinding(
                        severity=_SEVERITY_FROM_PKILINT.get(
                            finding_description["severity"], FindingSeverity.INFO
                        ),
                        code=finding_description["code"],
                        message=finding_description["message"],
                        node_path=entry["node_path"],
                    )
                )
    except Exception as exc:  # noqa: BLE001
        # pkilint's own validators run against arbitrary, possibly-unusual
        # certificate data from whatever target was scanned -- this tool's
        # own certificate.py draws the same "not everything is predictable"
        # line and records rather than raises. The exception type and
        # message are disclosed in `audit.error`, not swallowed silently;
        # what's avoided is a scan-ending crash over one target's malformed
        # or edge-case certificate triggering an internal pkilint error.
        audit.error = f"pkilint linting failed: {type(exc).__name__}: {exc}"

    return audit


__all__ = [
    "LintAvailability",
    "FindingSeverity",
    "LintFinding",
    "LintAudit",
    "lint_availability",
    "lint_certificate",
]
