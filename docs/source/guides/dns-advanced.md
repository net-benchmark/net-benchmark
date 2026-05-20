# DNS Advanced Capabilities

## Performance & concurrency

```bash
net-benchmark dns benchmark \
  --max-concurrent 200 \
  --iterations 5 \
  --timeout 3.0 \
  --warmup
```

- Async I/O with dnspython — test 100+ resolvers simultaneously
- Trio framework support — high-concurrency async operations
- Configurable concurrency — `--max-concurrent`
- Retry logic — exponential backoff for failed queries
- Cache simulation — `--use-cache`
- Multi-iteration benchmarks — `--iterations N`
- Warmup phase — `--warmup` / `--warmup-fast`
- Statistical analysis — mean, median, P95, P99, jitter, consistency scores

## Best practices

| Mode | Recommended flags | Purpose |
|---|---|---|
| **Quick Run** | `--iterations 1 --timeout 1 --retries 0 --warmup-fast` | Fast feedback, minimal retries, lightweight warmup |
| **Thorough Run** | `--iterations 3 --use-cache --warmup --timeout 5 --retries 2` | Multiple passes, cache enabled, full warmup |
| **Debug Mode** | `--iterations 1 --timeout 10 --retries 0 --quiet` | Long timeout, no retries, minimal output |
| **Balanced Run** | `--iterations 2 --use-cache --warmup-fast --timeout 2 --retries 1` | Middle ground |

## Security & privacy features

```bash
# Test DoH resolvers
net-benchmark dns benchmark \
  --doh \
  --resolvers doh-providers.json \
  --dnssec-validate
```

- DNSSEC validation — verify cryptographic trust chains
- DNS-over-HTTPS (DoH)
- DNS-over-TLS (DoT)
- DNS-over-QUIC (DoQ) — experimental
- TSIG authentication *(coming soon)*
- EDNS0 support

## Enterprise & migration features

```bash
# Validate DNS migration
net-benchmark dns benchmark \
  --resolvers old-provider.json,new-provider.json \
  --output migration-report/ \
  --formats pdf,excel
```

- Zone transfers (AXFR/IXFR) *(coming soon)*
- Dynamic DNS updates *(coming soon)*
- EDNS0 support — extended DNS options, client subnet, larger payloads
- Windows WMI integration — auto-detect active system DNS settings
- Compliance reporting — generate audit-ready PDF/Excel reports
- SLA validation — track uptime and performance thresholds

## Analysis & reporting features

```bash
# Detailed analysis
net-benchmark dns benchmark \
  --use-defaults \
  --domain-stats \
  --record-type-stats \
  --error-breakdown \
  --formats csv,excel,pdf
```

- Per-domain statistics
- Per-record-type stats — compare A, AAAA, MX, TXT, etc.
- Error breakdown — categorize and count error types
- Comparison matrices — side-by-side resolver comparisons
- Trend analysis — performance over time (with multiple runs)
- Best-by-criteria — find best resolver by latency/reliability/consistency

## Internationalization & compatibility

```bash
# Test internationalized domains
net-benchmark dns benchmark \
  --domains international-domains.txt \
  --record-types A,AAAA,MX \
  --resolvers custom-resolvers.json
```

- IDNA support *(coming soon)*
- Multiple record types — A, AAAA, MX, TXT, CNAME, NS, SOA, PTR, SRV, CAA
- Cross-platform — Linux, macOS, Windows
- CI/CD integration — JSON output, proper exit codes, quiet mode

## Performance optimization

```bash
# Large-scale testing (1000+ queries)
net-benchmark dns benchmark \
  --resolvers data/many_resolvers.json \
  --domains data/many_domains.txt \
  --max-concurrent 50 \
  --timeout 3 \
  --quiet \
  --formats csv

# Unstable networks
net-benchmark dns benchmark \
  --resolvers data/backup_resolvers.json \
  --domains data/critical_domains.txt \
  --timeout 10 \
  --retries 3 \
  --max-concurrent 10

# Quick diagnostics
net-benchmark dns benchmark \
  --resolvers "1.1.1.1,8.8.8.8" \
  --domains "google.com,cloudflare.com" \
  --formats csv \
  --quiet \
  --timeout 2
```

## Troubleshooting

```bash
# Command not found
pip install -e .
python -m net_benchmark.dns_benchmark.cli --help

# PDF generation fails (Ubuntu/Debian)
sudo apt-get install libcairo2 libpango-1.0-0 libpangocairo-1.0-0 \
  libgdk-pixbuf2.0-0 libffi-dev shared-mime-info
# Or skip PDF
net-benchmark dns benchmark --use-defaults --formats csv,excel

# Network timeouts
net-benchmark dns benchmark --use-defaults --timeout 10 --retries 3
net-benchmark dns benchmark --use-defaults --max-concurrent 25
```

Debug mode:

```bash
# Verbose run
python -m net_benchmark.dns_benchmark.cli benchmark --use-defaults --formats csv

# Minimal configuration
net-benchmark dns benchmark --resolvers "1.1.1.1" --domains "google.com" --formats csv
```

## Upcoming features

| Flag | Description |
|---|---|
| `--zone-transfer` | AXFR/IXFR zone transfer testing |
| `--tsig` | TSIG-authenticated queries |
| `--idna` | Internationalized domain name support |
