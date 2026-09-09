# SSL Check

TLS handshake, certificate, and policy audit — from a single CLI.

## Why check TLS?

A certificate expiring unnoticed, a deprecated TLS version left enabled, a
mail server's STARTTLS quietly stopped working — these become outages, not
warnings, because nothing was watching between renewals.

`net-benchmark ssl check` audits the negotiated handshake (version, cipher
suite with IANA code, ALPN, session resumption), the certificate (expiry,
key strength, signature algorithm, hostname match, CA/Browser Forum
lifetime-policy compliance), and STARTTLS explicitly for SMTP, IMAP, POP3,
FTP, and LDAP — with a threshold gate for CI.

## Quick start

```bash
# Check a single endpoint
net-benchmark ssl check --targets api.example.com

# Check several, exporting CSV and Excel
net-benchmark ssl check \
  --targets "api.example.com,www.example.com" \
  --formats csv,excel

# CI gate: fail the build if any target's certificate expires within 30 days
net-benchmark ssl check --targets ./targets.txt \
  --threshold 'cert_expiry_days>30'
```

Results are saved to `./benchmark_results/` by default. A `--threshold`
failure exits with code 1 — see "Thresholds and CI gating" below.

## Target selection

| Flag | What it does |
|---|---|
| `--targets` / `-t` | Comma-separated hosts (`host`, `host:port`, or a URL) or a file, one target per line |
| `--use-defaults` | Use a small set of built-in default targets |
| `--ports` | Ports applied to targets with no explicit port. Default: `443` |
| `--all-ports` | Scan the common TLS/STARTTLS port set: 443, 8443, 465, 993, 995, 587, 636 |
| `--resolve host:port:ip` | Pin a target to an IP without a DNS lookup (repeatable, IPv6 supported) |
| `--starttls` | Force the STARTTLS protocol (`smtp`, `imap`, `pop3`, `ldap`, `ftp`, or `none`) instead of guessing from the port |

An explicit port on a target (`mail.example.com:587`) always wins over
`--ports` — it isn't expanded across the rest of the scan.

### STARTTLS on non-standard ports

The port-based STARTTLS guess only covers well-known ports. A mail server
running SMTP STARTTLS on a non-standard port needs an explicit override, or
the handshake is sent nothing but ciphertext where SMTP expects a plaintext
greeting, and the result is a confusing `tls_error`:

```bash
net-benchmark ssl check --targets mail.example.com:2525 --starttls smtp
```

## Transport and sampling

| Flag | What it does |
|---|---|
| `--connect-timeout` / `--handshake-timeout` / `--starttls-timeout` | Per-phase timeouts (seconds) |
| `--max-concurrent` | Maximum concurrent checks (bounds the host × port product, not just the host count) |
| `--retries` | Retries for timeout-class failures only — a refused connection or a rejected TLS version is not retried, since retrying repeats a deterministic answer |
| `--per-host-serial` | Check all ports of one host before moving to the next, instead of fanning out across ports too. Use this when scanning infrastructure you don't own |
| `--handshake-samples` / `--min-samples` | Handshakes per target for timing percentiles. Percentiles are **withheld**, not reported unreliably, below `--min-samples` |
| `--warmup-handshakes` | Discarded handshakes before timing samples begin |
| `--check-resumption` | Run a dedicated pair of handshakes to test TLS session resumption, separate from the timing samples |

## TLS negotiation

| Flag | What it does |
|---|---|
| `--alpn` | Comma-separated ALPN protocols to offer, e.g. `h2,http/1.1` |
| `--ciphers` | OpenSSL cipher string restricting TLS 1.2-and-below suites. Does not affect TLS 1.3 |
| `--sni-hostname` | Override the SNI value sent (and the name checked against the certificate) |
| `--no-sni` | Send no SNI value at all |

## Policy

Every policy flag controls what makes a target **non-compliant** — an
unreachable target is never counted as non-compliant, since it was never
assessed.

| Flag | What it does |
|---|---|
| `--min-days-remaining N` | Flag a certificate with fewer than N days remaining |
| `--max-lifetime-days N` | Flag a certificate whose total validity period exceeds N days |
| `--min-tls-version` | Flag a negotiated version below this floor, e.g. `TLSv1.2` |
| `--expected-issuer` | Flag a certificate whose issuer doesn't contain this substring |
| `--expected-fingerprint` | Flag a certificate that doesn't match this SHA-256 fingerprint (certificate or SPKI) |
| `--allow-hostname-mismatch` | Do **not** flag a certificate that doesn't cover the target hostname (off by default — mismatches are flagged) |
| `--require-forward-secrecy` | Flag a negotiated cipher suite without forward secrecy |
| `--allow-weak-key` / `--allow-weak-signature` | Do **not** flag an under-strength key or a broken signature hash (both flagged by default) |
| `--allow-deprecated-tls` | Do **not** flag TLS 1.0/1.1/SSLv3 (flagged by default) |
| `--require-revocation-source` | Flag a certificate with no OCSP or CRL URL. A certificate within the CA/B short-lived exemption is never flagged by this |

```bash
# Multi-port scan with a strict policy
net-benchmark ssl check --targets mail.example.com --all-ports \
  --min-tls-version TLSv1.2 --require-forward-secrecy
```

## `--as-of`: check a future date

Evaluate every certificate as of a fixed date instead of now — useful for
checking what a renewal deadline will look like, or what expires by the end
of the quarter:

```bash
net-benchmark ssl check --targets api.example.com --as-of 2026-09-01
```

Accepts an ISO 8601 date (`2026-09-01`) or datetime
(`2026-09-01T00:00:00Z`). The date is fixed once for the whole run, so every
target in a multi-target scan is judged against the same instant.

## Thresholds and CI gating

```bash
net-benchmark ssl check --targets ./targets.txt \
  --threshold 'cert_expiry_days>30' \
  --threshold 'deprecated_tls_rate==0' \
  --quiet
```

Each `--threshold` is evaluated **per target**, not as a fleet-wide average —
`cert_expiry_days>30` means every target's own certificate must clear 30
days, not the average across all of them. Any failure on any target exits
with code 1, and the run's exports (CSV, Excel, JSON) are still written
first, so a failed CI run still leaves its artifacts for inspection.

An unreachable target fails a `cert_expiry_days` threshold with a specific
reason (the metric was never measured) rather than silently passing — a scan
that can't reach a target should never look identical to a healthy one.

Run `net-benchmark ssl check --help` for the full metric list a threshold
can reference; an unrecognized metric name is rejected immediately, before
the scan runs, with a suggestion for the likely typo.

## Output

```bash
net-benchmark ssl check --targets api.example.com \
  --formats csv,excel,pdf --json --include-charts
```

- **CSV** — raw per-check results, per-target summary, and an expiry
  timeline bucketed by days remaining
- **Excel** — Summary, Expiry Timeline (colour-coded by urgency), Certificates,
  Raw Results, Thresholds, and Charts sheets, plus a Provenance sheet
  recording the trust store and OpenSSL version used
- **JSON** (`--json`) — the full structured payload
- **PDF** (`--formats pdf`, requires `pip install net-benchmark[pdf]`) — a
  summary report

## A note on certificate chains

Full chain-of-trust reporting — which CA issued it, whether the chain the
server sent is complete, revocation status — needs
`SSLObject.get_unverified_chain()`, which is **Python 3.13+**. On 3.11/3.12,
every check here still runs and reports fully on the leaf certificate the
target presents: expiry, key strength, signature, hostname match. Chain
fields report as not observed on those versions, not as a guess. Chain
observability depends on the Python interpreter running net-benchmark, not
on the target being checked.

Chain-of-trust reporting, revocation checking (OCSP/CRL), and baseline
monitoring are planned for a follow-up release.

## Example: check TLS on a mail server's implicit and STARTTLS ports

```bash
net-benchmark ssl check --targets mail.example.com \
  --ports 465,587,993,995 \
  --starttls auto \
  --min-tls-version TLSv1.2
```

`--starttls auto` (the default) applies the well-known-port guess per port —
465/993/995 checked as implicit TLS, 587 checked with the SMTP STARTTLS
negotiation — in a single scan.
