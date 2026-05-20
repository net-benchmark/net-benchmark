# HTTP Export Formats

## CSV files

| File | Contents |
|---|---|
| `*_raw.csv` | Individual request results with full timing breakdown |
| `*_summary.csv` | Per-target aggregated statistics |
| `*_security.csv` | Security headers presence matrix |
| `*_ttfb.csv` | Time-to-first-byte analysis |
| `*_protocols.csv` | HTTP/1.1 vs HTTP/2 distribution |

## Excel report

- **Raw Data** sheet — all requests with timing, security headers, cert details
- **Target Summary** sheet — comprehensive per-target statistics
- **TTFB Analysis** sheet — TTFB percentiles per target
- **Security Headers** sheet — colour-coded presence matrix (green = present, red = missing)
- **Charts** sheet — latency comparison, TTFB comparison, success rates (requires `--include-charts`)

## PDF report

- Executive summary — key findings and recommendations
- Performance charts — latency and TTFB comparison
- Target rankings — ordered by average latency
- Security header coverage — pass/fail matrix
- TLS certificate status — expiry countdown per target

## JSON bundle

The `--json` flag writes a machine-readable file containing all request results,
timing breakdowns, security findings, and cert details.

## Generate all formats

```bash
net-benchmark http benchmark \
  --use-defaults \
  --formats csv,excel,pdf \
  --include-charts \
  --json \
  --output ./full_report
```
