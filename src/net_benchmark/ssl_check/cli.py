"""SSL/TLS checking CLI.

Mirrors `http_bench.cli` and `dns_benchmark.cli`: a `click.Group`, shared
`--targets`/`--use-defaults` target selection, the `--threshold` CI-gate
pattern with typo detection against a known metric set, and exports evaluated
before the threshold gate so a failing run still leaves its artifacts behind.

Deliberately one command, `ssl check`, with each 0.6.1 capability (chain
validation, revocation, version/cipher enumeration, CT log trust, CA/B
linting, dual-stack and virtual-hosting checks) as its own opt-in flag on
that command rather than a separate subcommand — each adds fields to the
same per-target result and the same export formats, not a differently-shaped
output that would need its own command and its own exporters.
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
from net_benchmark.ssl_check.topology import (
    detect_virtual_hosting as compute_virtual_hosting_groups,
)
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
# ── policy thresholds (0.6.2 item 26) ──
@click.option(
    "--expected-cipher",
    default=None,
    help="Flag a target whose primary handshake did not negotiate exactly "
    "this cipher (OpenSSL name, case-insensitive).",
)
@click.option(
    "--expected-group",
    default=None,
    help="Flag a target that does not negotiate this named group at all. "
    "Checks negotiability via --deep-introspection's data (that flag must "
    "also be passed), not necessarily what the primary handshake itself "
    "picked — stdlib ssl has no public API for that before Python 3.13.",
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
# ── chain of trust (roadmap discussion #45, SSL items 11-16) ──
@click.option(
    "--verify-chain",
    is_flag=True,
    help="Fetch missing intermediates via AIA and validate the chain "
    "against a trust store. Adds network calls beyond the target itself; "
    "off by default.",
)
@click.option(
    "--trust-anchor-file",
    "trust_anchor_files",
    multiple=True,
    type=click.Path(exists=True, dir_okay=False, path_type=str),
    help="Extra PEM file of trust anchors, added to the certifi bundle. "
    "Repeatable. Only used with --verify-chain.",
)
@click.option(
    "--chain-timeout",
    default=10.0,
    show_default=True,
    help="Timeout in seconds for each AIA certificate fetch.",
)
@click.option(
    "--max-chain-depth",
    default=8,
    show_default=True,
    help="Maximum number of AIA hops to follow while completing a chain.",
)
@click.option(
    "--check-cross-sign",
    is_flag=True,
    help="With --verify-chain, also build an independent AIA-only path and "
    "flag when it trusts a different root than the peer-supplied chain "
    "does. Costs an extra AIA fetch even when the peer's own chain already "
    "validates; see the chain.py module docstring for what this heuristic "
    "does and does not catch.",
)
@click.option(
    "--require-valid-chain",
    is_flag=True,
    help="Flag a certificate whose chain did not validate against the "
    "trust store. Only meaningful with --verify-chain; ignored otherwise.",
)
# ── revocation (roadmap discussion #45, SSL items 17-18) ──
@click.option(
    "--check-revocation",
    is_flag=True,
    help="Query OCSP and CRL for each certificate's own revocation status. "
    "Independent of --verify-chain (only needs the immediate issuer, fetched "
    "via AIA if not already available from --verify-chain); adds network "
    "calls beyond the target itself, off by default.",
)
@click.option(
    "--ocsp-timeout",
    default=10.0,
    show_default=True,
    help="Timeout in seconds for each OCSP responder query.",
)
@click.option(
    "--crl-timeout",
    default=10.0,
    show_default=True,
    help="Timeout in seconds for each CRL fetch.",
)
@click.option(
    "--allow-revoked",
    is_flag=True,
    help="Do not flag a certificate that OCSP or CRL reports as revoked.",
)
# ── protocol & cipher enumeration (0.6.1 items 1-3) ──
@click.option(
    "--enumerate-protocol",
    is_flag=True,
    help="Enumerate supported TLS versions and (unless --no-enumerate-ciphers) "
    "TLS 1.2-and-below cipher suites, with an A-F strength rating per suite. "
    "5-70 extra handshakes against the target per scan; off by default.",
)
@click.option(
    "--enumerate-ciphers/--no-enumerate-ciphers",
    default=True,
    help="With --enumerate-protocol, whether to also probe TLS 1.2-and-below "
    "cipher suites (5-70 handshakes) or only enumerate versions (5 "
    "handshakes). Ciphers on by default.",
)
# ── CT log identification & trust status (0.6.1 items 10, 12) ──
@click.option(
    "--check-ct-logs",
    is_flag=True,
    help="Resolve each certificate's embedded SCTs against the CT log "
    "registry and report whether the issuing logs are currently trusted. "
    "Fetches Chrome's published log list (cached on disk) once per scan.",
)
# ── CA/B Baseline Requirements linting (0.6.1 item 37) ──
@click.option(
    "--lint",
    is_flag=True,
    help="Lint each certificate against the CA/Browser Forum TLS Baseline "
    "Requirements via pkilint. Requires the [lint] extra "
    "(pip install 'net-benchmark[lint]'); reports as unavailable, not an "
    "error, when not installed. No network cost — CPU only.",
)
# ── IPv4/IPv6 certificate consistency (0.6.1 item 17) ──
@click.option(
    "--check-dual-stack",
    is_flag=True,
    help="For dual-stack targets, compare the certificate served over IPv4 "
    "against IPv6 for the same hostname. Skipped for --resolve-pinned "
    "targets, which have no families left to compare.",
)
# ── virtual host / multi-cert detection (0.6.1 item 16) ──
@click.option(
    "--detect-virtual-hosting",
    is_flag=True,
    help="Report, for any IP scanned under more than one hostname in this "
    "run, how many distinct certificates it served. Descriptive, not a "
    "pass/fail check — shared virtual hosting is normal. No network cost, "
    "computed from results already collected.",
)
# ── TLS deep introspection via CryptoLyzer (0.6.2 items 1-9) ──
@click.option(
    "--deep-introspection",
    is_flag=True,
    help="Named groups, DH parameters and ephemeral key reuse, "
    "renegotiation/extension audit, signature algorithm probing, TLS 1.3 "
    "cipher enumeration, and version/draft detection via CryptoLyzer — "
    "reaches past what OpenSSL-bound stdlib ssl can ever observe. "
    "Requires the [crypto] extra; implicit TLS targets only in this "
    "release (skipped for --starttls targets). Reports as unavailable, "
    "not an error, when not installed.",
)
@click.option(
    "--crypto-executor-workers",
    default=10,
    show_default=True,
    help="Thread pool size for --deep-introspection (CryptoLyzer is "
    "synchronous; this bounds how many of its probes run concurrently).",
)
# ── SSL Labs-style grade (0.6.2 items 20-21) ──
@click.option(
    "--grade",
    "compute_grade",
    is_flag=True,
    help="Score each target against the published SSL Labs Server Rating "
    "Guide (rubric version recorded in the output). No network cost of "
    "its own — scores whatever --enumerate-protocol/--deep-introspection "
    "already collected; without those, the grade is best-effort with data "
    "gaps named explicitly rather than guessed.",
)
# ── Server Side TLS profile compliance (0.6.2 item 21) ──
@click.option(
    "--check-mozilla-profiles",
    is_flag=True,
    help="Check compliance against the published Server Side TLS "
    "guidelines (formerly hosted by Mozilla, now published by TLSRef at "
    "data.tlsref.org — same guidelines lineage and authors). Checks every "
    "profile the current guidelines document contains (Modern and "
    "Intermediate as of the current guideline version; 'Old' was removed "
    "upstream). Fetches once per scan, not once per target.",
)
@click.option(
    "--mozilla-profile",
    "mozilla_profiles",
    multiple=True,
    help="Limit --check-mozilla-profiles to specific profile names (e.g. "
    "--mozilla-profile modern). Repeatable. Defaults to every profile the "
    "guidelines document contains.",
)
# ── SPKI pin set generation (0.6.2 item 25) ──
@click.option(
    "--generate-pin-set",
    "generate_pin_set_flag",
    is_flag=True,
    help="Generate an SPKI pin set (leaf + backup pins from the validated "
    "chain) for certificate pinning. Requires --verify-chain for backup "
    "pins; without it, only a single (fragile) leaf pin is produced.",
)
@click.option(
    "--pin-set-no-root",
    is_flag=True,
    help="Exclude the trust-anchor root from --generate-pin-set's output.",
)
# ── client simulation (0.6.2 item 23) ──
@click.option(
    "--simulate-clients",
    is_flag=True,
    help="Check which real browser/library versions can complete a "
    "handshake with this target, via CryptoLyzer's per-client TLS "
    "capability data. Expensive: roughly 70 real handshake attempts per "
    "target. Requires the [crypto] extra; implicit TLS targets only.",
)
# ── JARM server fingerprinting (0.6.2 item 24) ──
@click.option(
    "--jarm",
    "compute_jarm",
    is_flag=True,
    help="Compute a JARM fingerprint (Salesforce's active TLS server "
    "fingerprinting scheme) for each target. JA4S is not included — see "
    "the docs for why. Requires the [crypto] extra; implicit TLS targets "
    "only.",
)
@click.option(
    "--jarm-timeout",
    default=20.0,
    show_default=True,
    help="Per-target timeout in seconds for --jarm.",
)
# ── full multi-store trust validation (0.6.2 item 22) ──
@click.option(
    "--check-multi-store",
    is_flag=True,
    help="Validate the certificate chain against Apple's, Google's "
    "(Chrome), and Microsoft's own root programs, in addition to the "
    "Mozilla+system default --verify-chain already uses. Reports whether "
    "the stores agree. Requires --verify-chain; Microsoft's check needs "
    "the [crypto] extra.",
)
# ── multi-SAN audit against active subdomains (0.6.2 item 27) ──
@click.option(
    "--audit-san",
    is_flag=True,
    help="For each literal (non-wildcard) DNS SAN entry on the "
    "certificate, check whether it resolves and serves this same "
    "certificate — surfaces unused SAN coverage and SAN/DNS "
    "inconsistencies. Capped at 25 entries per certificate by default "
    "(--san-audit-max-entries).",
)
@click.option(
    "--san-audit-max-entries",
    default=25,
    show_default=True,
    help="Cap on SAN entries probed per certificate for --audit-san.",
)
# ── TLS 1.3 0-RTT timing (0.6.2 item 11) ──
@click.option(
    "--measure-0rtt",
    is_flag=True,
    help="Measure the actual latency of a full handshake vs. session-"
    "resumed vs. session-resumed-with-early-data (0-RTT), and report "
    "whether the target accepted the early data. Requires the system "
    "openssl CLI — no Python library exposes early-data support. "
    "Implicit TLS targets only.",
)
@click.option(
    "--zero-rtt-timeout",
    default=10.0,
    show_default=True,
    help="Per-connection timeout in seconds for --measure-0rtt.",
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
    expected_cipher: Optional[str],
    expected_group: Optional[str],
    allow_hostname_mismatch: bool,
    require_forward_secrecy: bool,
    allow_weak_key: bool,
    allow_weak_signature: bool,
    allow_deprecated_tls: bool,
    require_revocation_source: bool,
    verify_chain: bool,
    trust_anchor_files: Tuple[str, ...],
    chain_timeout: float,
    max_chain_depth: int,
    check_cross_sign: bool,
    require_valid_chain: bool,
    check_revocation: bool,
    ocsp_timeout: float,
    crl_timeout: float,
    allow_revoked: bool,
    enumerate_protocol: bool,
    enumerate_ciphers: bool,
    check_ct_logs: bool,
    lint: bool,
    check_dual_stack: bool,
    detect_virtual_hosting: bool,
    deep_introspection: bool,
    crypto_executor_workers: int,
    compute_grade: bool,
    check_mozilla_profiles: bool,
    mozilla_profiles: Tuple[str, ...],
    generate_pin_set_flag: bool,
    pin_set_no_root: bool,
    simulate_clients: bool,
    compute_jarm: bool,
    jarm_timeout: float,
    check_multi_store: bool,
    audit_san: bool,
    san_audit_max_entries: int,
    measure_0rtt: bool,
    zero_rtt_timeout: float,
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
            verify_chain=verify_chain,
            chain_timeout=chain_timeout,
            max_chain_depth=max_chain_depth,
            trust_anchor_paths=[Path(p) for p in trust_anchor_files] or None,
            check_cross_sign=check_cross_sign,
            check_revocation=check_revocation,
            ocsp_timeout=ocsp_timeout,
            crl_timeout=crl_timeout,
            enumerate_protocol=enumerate_protocol,
            enumerate_ciphers=enumerate_ciphers,
            check_ct_logs=check_ct_logs,
            lint=lint,
            check_dual_stack=check_dual_stack,
            deep_introspection=deep_introspection,
            crypto_executor_workers=crypto_executor_workers,
            grade=compute_grade,
            check_mozilla_profiles=check_mozilla_profiles,
            mozilla_profiles=list(mozilla_profiles) or None,
            generate_pin_set_output=generate_pin_set_flag,
            pin_set_include_root=not pin_set_no_root,
            simulate_clients=simulate_clients,
            jarm=compute_jarm,
            jarm_timeout=jarm_timeout,
            check_multi_store=check_multi_store,
            audit_san=audit_san,
            san_audit_max_entries=san_audit_max_entries,
            measure_zero_rtt=measure_0rtt,
            zero_rtt_timeout=zero_rtt_timeout,
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
            try:
                return await engine.check_targets(target_list)
            finally:
                # No-op when --verify-chain was never passed — aclose() only
                # tears down a client that _ensure_async_primitives() only
                # ever creates when verify_chain is True.
                await engine.aclose()

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
            expected_cipher=expected_cipher,
            expected_group=expected_group,
            require_hostname_match=not allow_hostname_mismatch,
            require_forward_secrecy=require_forward_secrecy,
            reject_weak_key=not allow_weak_key,
            reject_weak_signature=not allow_weak_signature,
            reject_deprecated_tls=not allow_deprecated_tls,
            require_revocation_source=require_revocation_source,
            require_valid_chain=require_valid_chain,
            reject_revoked=not allow_revoked,
        )
        for result in results:
            evaluate_policy(result, policy)

        # ── analysis ─────────────────────────────────────────────────────
        analyzer = SSLAnalyzer(results)
        overall = analyzer.get_overall_statistics()

        # ── virtual host / multi-cert detection (0.6.1 item 16) ───────────
        virtual_hosting_groups = (
            compute_virtual_hosting_groups(results) if detect_virtual_hosting else []
        )
        if virtual_hosting_groups and not quiet:
            click.echo(warning("Virtual hosting detected:"))
            for group in virtual_hosting_groups:
                click.echo(
                    f"  {group.ip}: {len(group.hosts)} hostnames, "
                    f"{group.distinct_certificate_count} distinct certificate(s) "
                    f"({', '.join(group.hosts)})"
                )

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
                    virtual_hosting=virtual_hosting_groups or None,
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
