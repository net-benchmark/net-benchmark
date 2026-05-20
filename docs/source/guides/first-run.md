# First Run

## Step 1 — Explore defaults

```bash
net-benchmark dns list-defaults
```

Prints the built-in resolvers and curated domain list that `--use-defaults` uses.

## Step 2 — Run DNS benchmark

```bash
net-benchmark dns benchmark --use-defaults --formats csv,excel
```

## Step 3 — Run HTTP benchmark

```bash
net-benchmark http benchmark --use-defaults --formats csv,excel
```

## Step 4 — Read the DNS summary

```text
=== BENCHMARK SUMMARY ===
Total queries:      150
Successful:         140 (93.33%)
Average latency:    212.45 ms
Median latency:     198.12 ms
Fastest resolver:   Cloudflare
Slowest resolver:   Quad9
Iterations:         3
Cache hits:         40 (26.7%)
```

## Step 5 — Read the HTTP summary

```text
============================================
| Total requests:   5                      |
| Successful:       4 (80.00%)             |
| Avg latency:      1047.25 ms             |
| Avg TTFB:         772.20 ms              |
| HTTP/2 rate:      100.0%                 |
| HSTS coverage:    60.0%                  |
| Assertion pass:   100.0%                 |
| Fastest target:   https://www.apple.com  |
| Slowest target:   https://www.github.com |
============================================
```

## Step 6 — Output files

```
benchmark_results/
├── summary_YYYYMMDD_HHMMSS.csv       ← aggregated stats per resolver/target
├── raw_YYYYMMDD_HHMMSS.csv           ← every individual query result
└── report_YYYYMMDD_HHMMSS.xlsx       ← formatted Excel workbook
```

## Getting help

```bash
net-benchmark dns --help
net-benchmark dns benchmark --help
net-benchmark http --help
net-benchmark http benchmark --help
```
