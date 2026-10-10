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

Everything above runs by default. Opt-in, deeper checks add: chain-of-trust
validation and OCSP/CRL revocation, protocol and cipher enumeration with
A-F rating, Certificate Transparency and CA/Browser Forum linting, DV/OV/EV
detection, deep handshake introspection past what OpenSSL exposes
(including post-quantum named groups), grading against the published SSL
Labs and Server Side TLS rubrics, JARM fingerprinting, client simulation,
full multi-store trust validation, certificate pinning, multi-SAN
liveness auditing, and TLS 1.3 0-RTT timing. See the sections below.

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
| `--expected-cipher` | Flag a target whose primary handshake didn't negotiate exactly this cipher |
| `--expected-group` | Flag a target that doesn't negotiate this named group at all (needs `--deep-introspection`'s data) |
| `--allow-hostname-mismatch` | Do **not** flag a certificate that doesn't cover the target hostname (off by default — mismatches are flagged) |
| `--require-forward-secrecy` | Flag a negotiated cipher suite without forward secrecy |
| `--allow-weak-key` / `--allow-weak-signature` | Do **not** flag an under-strength key or a broken signature hash (both flagged by default) |
| `--allow-deprecated-tls` | Do **not** flag TLS 1.0/1.1/SSLv3 (flagged by default) |
| `--require-revocation-source` | Flag a certificate with no OCSP or CRL URL. A certificate within the CA/B short-lived exemption is never flagged by this |
| `--require-valid-chain` | Flag a certificate whose chain didn't validate. Only meaningful with `--verify-chain`; ignored otherwise |
| `--allow-revoked` | Do **not** flag a certificate OCSP/CRL reports as revoked (flagged by default; needs `--check-revocation`) |

```bash
# Multi-port scan with a strict policy
net-benchmark ssl check --targets mail.example.com --all-ports \
  --min-tls-version TLSv1.2 --require-forward-secrecy
```

## Chain of trust and revocation

Both are opt-in — they add network calls beyond the target itself, and
neither is needed for anything covered by the Policy section above (which
work entirely from the leaf certificate the target presents).

```bash
net-benchmark ssl check --targets api.example.com \
  --verify-chain --check-revocation --require-valid-chain
```

| Flag | What it does |
|---|---|
| `--verify-chain` | Fetch missing intermediates via AIA and validate the chain against Mozilla + system trust roots |
| `--trust-anchor-file FILE` | Extra PEM file of trust anchors, added to the certifi bundle. Repeatable |
| `--chain-timeout` / `--max-chain-depth` | Per-AIA-fetch timeout and the maximum number of AIA hops to follow |
| `--check-cross-sign` | Also build an independent AIA-only path and flag when it trusts a different root than the peer-supplied chain does |
| `--check-multi-store` | Also validate against Apple's, Google's (Chrome), and Microsoft's own root programs, reporting whether the stores agree. Microsoft's check needs the `[crypto]` extra (`mscerts`); Apple's and Google's are fetched from a third-party aggregator ([tls-inspector/rootca](https://github.com/tls-inspector/rootca)), since neither vendor publishes a directly-consumable bundle itself |
| `--check-revocation` | Query OCSP and CRL for each certificate's own revocation status (CRL is authoritative; OCSP is secondary, per current CA/Browser Forum policy) |
| `--ocsp-timeout` / `--crl-timeout` | Per-query timeouts |

A certificate's own `not_evaluated`/`unavailable_reason` fields are always
present where a check genuinely couldn't run (a fetch failed, a store
wasn't reachable) — never silently treated as a pass.

## Protocol, cipher, and deep introspection

Two tiers. `--enumerate-protocol` uses stdlib `ssl` — no extra dependency,
works everywhere. `--deep-introspection` reaches past what OpenSSL-bound
stdlib `ssl` can ever observe (post-quantum named groups, DH parameters,
TLS 1.3 cipher suites, signature algorithms, configuration-surface
vulnerability flags) via [CryptoLyzer](https://pypi.org/project/CryptoLyzer/),
an independent TLS protocol implementation — install with
`pip install net-benchmark[crypto]`.

```bash
net-benchmark ssl check --targets api.example.com \
  --enumerate-protocol --deep-introspection
```

| Flag | What it does |
|---|---|
| `--enumerate-protocol` | Enumerate supported TLS versions and (unless `--no-enumerate-ciphers`) TLS 1.2-and-below cipher suites, A-F rated. 5-70 extra handshakes |
| `--enumerate-ciphers` / `--no-enumerate-ciphers` | Whether protocol enumeration also probes ciphers (on by default) |
| `--deep-introspection` | Named groups (incl. post-quantum hybrids like `X25519MLKEM768`), DH parameters and ephemeral-key-reuse detection, renegotiation/extension audit, signature algorithm probing, TLS 1.3 cipher enumeration, version/draft detection, and configuration-surface vulnerability flags (FREAK, Logjam, Sweet32, DROWN, POODLE/BEAST preconditions, and more). Implicit TLS targets only |
| `--crypto-executor-workers` | Thread pool size for `--deep-introspection` (CryptoLyzer is synchronous) |
| `--simulate-clients` | Which real browser/library versions can complete a handshake with this target, via CryptoLyzer's per-client capability data. Expensive: ~70 handshakes per target |
| `--jarm` / `--jarm-timeout` | Compute a JARM server fingerprint. JA4S is not included — no maintained connection-based Python implementation exists with a clearly compatible licence |
| `--measure-0rtt` / `--zero-rtt-timeout` | Time a full handshake vs. session-resumed vs. session-resumed-with-early-data (0-RTT), and report whether the target accepted it. Requires the system `openssl` CLI — no Python TLS library (stdlib, CryptoLyzer, pyOpenSSL) exposes early-data support |

Every `--deep-introspection`/`--jarm`/`--simulate-clients`/`--measure-0rtt`
check reports its own availability explicitly (`"not_installed"` for a
missing extra, `"available": false` for a missing `openssl` binary) rather
than silently omitting the field.

## Certificate Transparency and linting

```bash
net-benchmark ssl check --targets api.example.com --check-ct-logs --lint
```

| Flag | What it does |
|---|---|
| `--check-ct-logs` | Resolve each certificate's embedded SCTs against the CT log registry (Chrome's published log list, cached on disk) and report whether the issuing logs are currently trusted |
| `--lint` | Lint each certificate against the CA/Browser Forum TLS Baseline Requirements via [pkilint](https://pypi.org/project/pkilint/). Install with `pip install net-benchmark[lint]`; no network cost, CPU only |

## Grading and compliance

Both score whatever the checks above already collected — running them
alone, without `--enumerate-protocol`/`--deep-introspection`, still
produces a grade, but a best-effort one with explicit data gaps rather
than a guess.

```bash
net-benchmark ssl check --targets api.example.com \
  --enumerate-protocol --deep-introspection --grade --check-mozilla-profiles
```

| Flag | What it does |
|---|---|
| `--grade` | Score against the actual published [SSL Labs Server Rating Guide](https://github.com/ssllabs/research/wiki/SSL-Server-Rating-Guide) — the rubric version is recorded in every result, and every cap/fail rule applied is listed in `applied_rules` |
| `--check-mozilla-profiles` | Check compliance against the published Server Side TLS guidelines — formerly hosted by Mozilla, now published by [TLSRef](https://data.tlsref.org) (same authors, same lineage). Checks every profile the current guidelines contain (currently Modern and Intermediate — "Old" was removed upstream) |
| `--mozilla-profile` | Limit `--check-mozilla-profiles` to specific profile names. Repeatable |

## Topology and certificate coverage

```bash
net-benchmark ssl check --targets api.example.com,cdn.example.com \
  --resolve cdn.example.com:443:203.0.113.10 \
  --detect-virtual-hosting --check-dual-stack --audit-san
```

| Flag | What it does |
|---|---|
| `--check-dual-stack` | For dual-stack targets, compare the certificate served over IPv4 against IPv6 for the same hostname |
| `--detect-virtual-hosting` | Report, for any IP scanned under more than one hostname in this run, how many distinct certificates it served. Descriptive, not pass/fail — shared virtual hosting is normal |
| `--audit-san` / `--san-audit-max-entries` | For each literal (non-wildcard) DNS SAN entry, check whether it resolves and serves this same certificate — surfaces unused SAN coverage and SAN/DNS inconsistencies. Capped at 25 entries per certificate by default |

## Certificate pinning

```bash
net-benchmark ssl check --targets api.example.com --verify-chain --generate-pin-set
```

| Flag | What it does |
|---|---|
| `--generate-pin-set` | Generate an SPKI pin set (leaf + backup pins from the validated chain). Requires `--verify-chain` for backup pins; without it, only a single, fragile leaf pin is produced |
| `--pin-set-no-root` | Exclude the trust-anchor root from the pin set |

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

- **CSV** — raw per-check results (every field every opt-in check
  produces, when it ran), per-target summary, and an expiry timeline
  bucketed by days remaining
- **Excel** — Summary, **Per-Host Grade** (one row per target, summarising
  chain/revocation/CT/lint/enumeration/SSL Labs grade), Expiry Timeline
  (colour-coded by urgency), Certificates, Raw Results, Thresholds, and
  Charts sheets, plus a Provenance sheet recording the trust store and
  OpenSSL version used
- **JSON** (`--json`) — the full structured payload, including every
  opt-in check's own result object
- **PDF** (`--formats pdf`, requires `pip install net-benchmark[pdf]`) — a
  summary report with a **Findings summary** section (chain/revocation/CT/
  cipher/lint status per host) when any of those checks ran

## A note on certificate chains

Full chain-of-trust reporting — which CA issued it, whether the chain the
server sent is complete, revocation status — is available via
`--verify-chain` and `--check-revocation` on every supported Python
version. What's still version-gated is narrower: observing the **raw
bytes the peer itself sent** for its own intermediate chain needs
`SSLObject.get_unverified_chain()`, which is **Python 3.13+**. On
3.11/3.12, `--verify-chain` still validates correctly — it just can't use
the peer's own chain as a shortcut, and always fetches intermediates via
AIA instead, which costs a few extra round trips per target but produces
the same verified result.

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
