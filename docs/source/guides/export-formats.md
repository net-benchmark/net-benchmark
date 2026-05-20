# Export Formats

## Format summary

| Format | Flag | Notes |
|---|---|---|
| CSV | `--formats csv` | Raw results + summary + optional domain/record-type/error stats |
| Excel | `--formats excel` | Formatted workbook with charts and conditional formatting |
| PDF | `--formats pdf` | Requires `pip install net-benchmark[pdf]` |
| JSON | `--json` | Full structured payload — separate flag, combinable with `--formats` |

Multiple formats can be combined:

```bash
net-benchmark dns benchmark --use-defaults --formats csv,excel,pdf --json
net-benchmark http benchmark --use-defaults --formats csv,excel,pdf --json
```

---

## DNS CSV outputs

| File | Content |
|---|---|
| `summary_*.csv` | Aggregated metrics per resolver (mean, median, P95, P99, jitter, success rate) |
| `raw_*.csv` | Every individual query result with timestamp and metadata |
| `domain_stats_*.csv` | Per-domain performance (requires `--domain-stats`) |
| `record_type_stats_*.csv` | Per-record-type performance (requires `--record-type-stats`) |
| `error_breakdown_*.csv` | Error counts by type (requires `--error-breakdown`) |

## DNS Excel report

- Raw data sheet — all query results with colour-coded latency bands
- Resolver summary — statistics with conditional formatting (green = fast)
- Domain stats — per-domain performance (optional, `--domain-stats`)
- Record type stats — per-record-type (optional, `--record-type-stats`)
- Error breakdown — aggregated error counts (optional, `--error-breakdown`)
- Performance analysis — embedded charts (requires `--include-charts`)

## HTTP CSV outputs

| File | Content |
|---|---|
| `*_raw.csv` | Individual request results with timing breakdown |
| `*_summary.csv` | Per-target aggregated statistics |
| `*_security.csv` | Security headers presence matrix |
| `*_ttfb.csv` | Time-to-first-byte analysis |
| `*_protocols.csv` | HTTP/1.1 vs HTTP/2 distribution |

## HTTP Excel report

- Raw Data sheet — all requests with timing, security headers, cert details
- Target Summary sheet — comprehensive per-target statistics
- TTFB Analysis sheet — TTFB percentiles per target
- Security Headers sheet — colour-coded presence matrix
- Charts sheet — latency comparison, TTFB, success rates (requires `--include-charts`)

---

## PDF report

DNS PDF includes:

- Executive summary — key findings and recommendations
- Performance charts — latency comparison; optional success rate chart
- Resolver rankings — ordered by average latency
- Detailed analysis — technical deep-dive with percentile breakdown

HTTP PDF includes:

- Executive summary
- Performance charts — latency and TTFB comparison
- Target rankings — ordered by average latency
- Security header coverage — pass/fail matrix
- TLS certificate status — expiry countdown per target

### PDF setup

```bash
pip install net-benchmark[pdf]
net-benchmark dns benchmark --use-defaults --formats pdf --output ./results
```

If WeasyPrint is not installed:

```
[-] Error during benchmark: PDF export requires 'weasyprint'. Install with: pip install net-benchmark[pdf]
```

See [Installation](installation.md) for WeasyPrint system dependency instructions.

---

## JSON bundle

```bash
net-benchmark dns benchmark --use-defaults --json --output ./results
net-benchmark http benchmark --use-defaults --json --output ./results
```

DNS JSON includes: overall stats, per-resolver stats, raw query results,
domain stats, record-type stats, error breakdown.

HTTP JSON includes: all request results, timing breakdowns, security findings,
cert details.

---

## Include charts

```bash
net-benchmark dns benchmark \
  --use-defaults \
  --formats pdf,excel \
  --include-charts

net-benchmark http benchmark \
  --use-defaults \
  --formats pdf,excel \
  --include-charts
```

---

## Generate sample config

```bash
net-benchmark dns generate-config \
  --category privacy \
  --output my-config.yaml
```
