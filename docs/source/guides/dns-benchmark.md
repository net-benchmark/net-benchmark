# DNS Benchmark

Test DNS resolver performance, DNSSEC, DoH/DoT from a single CLI.

## Why benchmark DNS?

DNS resolution is often the hidden bottleneck in network performance.
A slow resolver can add **300 ms+** to every request.

**The problem:**
- ⏱️ DNS can add 300 ms+ to every request
- 🤷 Most developers never test their DNS
- 🌍 "Fastest" resolver depends on where **you** are
- 🔒 DNSSEC, DoH, DoT support differs wildly

**net-benchmark helps you:**
- Find the fastest DNS resolver for **your** location
- Get real data — P95, P99, jitter, consistency scores
- Validate security — DNSSEC verification built-in
- Test at scale — 100+ concurrent queries in seconds

**Perfect for:** Developers · DevOps/SRE · Self-hosters · Network admins

---

## Commands at a glance

| Command | What it does | Quick example |
|---|---|---|
| `benchmark` | Full DNS benchmark with exports | `net-benchmark dns benchmark --use-defaults` |
| `top` | Rank all resolvers by speed | `net-benchmark dns top --limit 5` |
| `compare` | Side-by-side resolver comparison | `net-benchmark dns compare Cloudflare Google Quad9` |
| `monitoring` | Continuous monitoring with alerts | `net-benchmark dns monitoring --use-defaults` |

---

## benchmark

```bash
# Test default resolvers against popular domains
net-benchmark dns benchmark --use-defaults --formats csv,excel

# Basic test with progress bars
net-benchmark dns benchmark --use-defaults --formats csv,excel

# Basic test without progress bars
net-benchmark dns benchmark --use-defaults --formats csv,excel --quiet

# Test with custom resolvers and domains
net-benchmark dns benchmark --resolvers data/resolvers.json --domains data/domains.txt

# Quick test with only CSV output
net-benchmark dns benchmark --use-defaults --formats csv

# Export a machine-readable bundle
net-benchmark dns benchmark --use-defaults --json --output ./results

# Test specific record types
net-benchmark dns benchmark --use-defaults --formats csv,excel --record-types A,AAAA,MX

# Custom output location and formats
net-benchmark dns benchmark \
  --use-defaults \
  --output ./my-results \
  --formats csv,excel

# Include detailed statistics
net-benchmark dns benchmark \
  --use-defaults \
  --formats csv,excel \
  --record-type-stats \
  --error-breakdown

# High concurrency with retries
net-benchmark dns benchmark \
  --use-defaults \
  --formats csv,excel \
  --max-concurrent 200 \
  --timeout 3.0 \
  --retries 3

# Website migration planning
net-benchmark dns benchmark \
  --resolvers data/global_resolvers.json \
  --domains data/migration_domains.txt \
  --formats excel,pdf \
  --output ./migration_analysis

# DNS provider selection
net-benchmark dns benchmark \
  --resolvers data/provider_candidates.json \
  --domains data/business_domains.txt \
  --formats csv,excel \
  --output ./provider_selection

# Network troubleshooting
net-benchmark dns benchmark \
  --resolvers "192.168.1.1,1.1.1.1,8.8.8.8" \
  --domains "problematic-domain.com,working-domain.com" \
  --timeout 10 \
  --retries 3 \
  --formats csv \
  --output ./troubleshooting

# Security assessment
net-benchmark dns benchmark \
  --resolvers data/security_resolvers.json \
  --domains data/security_test_domains.txt \
  --formats pdf \
  --output ./security_assessment

# Performance monitoring
net-benchmark dns benchmark \
  --use-defaults \
  --formats csv \
  --quiet \
  --output /var/log/net_benchmark/$(date +%Y%m%d_%H%M%S)
```

### New CLI options

| Option | Description | Example |
|---|---|---|
| `--iterations, -i` | Run the full benchmark loop **N times** | `net-benchmark dns benchmark --use-defaults -i 3` |
| `--use-cache` | Allow cached results to be reused across iterations | `net-benchmark dns benchmark --use-defaults -i 3 --use-cache` |
| `--warmup` | Run a **full warmup** (all resolvers × domains × record types) | `net-benchmark dns benchmark --use-defaults --warmup` |
| `--warmup-fast` | Run a **lightweight warmup** (one probe per resolver) | `net-benchmark dns benchmark --use-defaults --warmup-fast` |
| `--include-charts` | Embed charts and graphs in PDF/Excel reports | `net-benchmark dns benchmark --use-defaults --formats pdf,excel --include-charts` |

### Include domain and record-type analytics

```bash
net-benchmark dns benchmark --use-defaults \
  --domain-stats --record-type-stats --error-breakdown
```

---

## top

Quickly rank resolvers by speed and reliability.

```bash
# Rank resolvers quickly
net-benchmark dns top

# Use custom domain list
net-benchmark dns top -d domains.txt

# Export results to JSON
net-benchmark dns top -o results.json

# DoH top 5
net-benchmark dns top --doh --limit 5

# DoT top 5 by reliability
net-benchmark dns top --dot --metric reliability --limit 5
```

---

## compare

Benchmark resolvers side-by-side with detailed statistics.

```bash
# Compare Cloudflare, Google, and Quad9
net-benchmark dns compare Cloudflare Google Quad9

# Compare by IP addresses
net-benchmark dns compare 1.1.1.1 8.8.8.8 9.9.9.9

# Show detailed per-domain breakdown
net-benchmark dns compare Cloudflare Google --show-details

# Export results to CSV
net-benchmark dns compare Cloudflare Google -o results.csv

# Compare DoH resolvers
net-benchmark dns compare Cloudflare Google --doh --iterations 3
```

---

## monitoring

Continuously monitor resolver performance with alerts.

```bash
# Monitor default resolvers continuously (every 60 s)
net-benchmark dns monitoring --use-defaults

# Monitor with custom resolvers and domains
net-benchmark dns monitoring -r resolvers.json -d domains.txt

# Run monitoring for 1 hour with alerts
net-benchmark dns monitoring --use-defaults --interval 30 --duration 3600 \
  --alert-latency 150 --alert-failure-rate 5 --output monitor.log

# Monitor with DoT
net-benchmark dns monitoring --use-defaults --dot \
  --interval 60 --alert-latency 300
```

---

## Inline vs file inputs

Both `--resolvers` and `--domains` accept inline comma-separated values or file paths.
File paths take priority if the value matches an existing file.

```bash
# Inline resolvers — IPs
--resolvers "1.1.1.1,8.8.8.8,9.9.9.9"

# Inline resolvers — named
--resolvers "Cloudflare,Google,Quad9"

# Mixed
--resolvers "1.1.1.1,Cloudflare,8.8.8.8"

# Single value
--resolvers "1.1.1.1"

# File (JSON)
--resolvers data/resolvers.json

# Inline domains
--domains "google.com,github.com"

# File (plain text)
--domains data/domains.txt
```

All existing file-based configurations continue to work — no breaking changes.

---

## Analysis enhancements

- **Iteration count** — displayed when more than one iteration is run
- **Cache hits** — shows queries served from cache (when `--use-cache` is enabled)
- **Failure tracking** — resolvers with repeated errors counted; inspect via `get_failed_resolvers()`
- **Cache statistics** — via `get_cache_stats()`, shows cached entry count and whether cache is enabled
- **Warmup results** — tagged `iteration=0` in raw data, easy to filter out

Example summary output:

```text
=== BENCHMARK SUMMARY ===
Total queries: 150
Successful: 140 (93.33%)
Average latency: 212.45 ms
Median latency: 198.12 ms
Fastest resolver: Cloudflare
Slowest resolver: Quad9
Iterations: 3
Cache hits: 40 (26.7%)
```

---

## Key features

**Performance**
- Async queries — test 100+ resolvers simultaneously
- Multi-iteration — run benchmarks multiple times for accuracy
- Statistical analysis — mean, median, P95, P99, jitter, consistency
- Cache control — test with/without DNS caching

**Security & Privacy**
- DNSSEC validation — verify cryptographic trust chains
- DNS-over-HTTPS (DoH) — encrypted DNS benchmarking
- DNS-over-TLS (DoT) — secure transport testing
- DNS-over-QUIC (DoQ) — experimental QUIC support

**Analysis & Export**
- Multiple formats — CSV, Excel, PDF, JSON
- Visual reports — charts and graphs
- Domain statistics — per-domain performance analysis
- Error breakdown — identify problematic resolvers

**Enterprise features**
- TSIG authentication — secure enterprise queries *(coming soon)*
- Zone transfers — AXFR/IXFR validation *(coming soon)*
- Dynamic updates — test DNS write operations *(coming soon)*
- Compliance reports — audit-ready documentation

**Cross-platform**
- Linux, macOS, Windows
- CI/CD friendly — JSON output, exit codes
- IDNA support — internationalized domain names *(coming soon)*
- Auto-detection — Windows WMI DNS discovery

---

## Getting help

```bash
net-benchmark dns --help
net-benchmark dns benchmark --help
net-benchmark dns list-resolvers --help
net-benchmark dns list-domains --help
net-benchmark dns list-categories --help
net-benchmark dns generate-config --help
```

Common scenarios:

```bash
# I'm new — where to start?
net-benchmark dns list-defaults
net-benchmark dns benchmark --use-defaults

# Test specific resolvers
net-benchmark dns list-resolvers --category security
net-benchmark dns benchmark --resolvers data/security_resolvers.json --use-defaults

# Generate a management report
net-benchmark dns benchmark --use-defaults --formats excel,pdf \
  --domain-stats --record-type-stats --error-breakdown --json \
  --output ./management_report
```
