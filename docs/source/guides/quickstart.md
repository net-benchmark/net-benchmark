# Quick Start

## First run — DNS

```bash
# Test with defaults (recommended for first time)
net-benchmark dns benchmark --use-defaults --formats csv,excel
```

## First run — HTTP

```bash
# HTTP test with defaults
net-benchmark http benchmark --use-defaults --formats csv,excel
```

Results land in `./benchmark_results/` — summary CSV, raw CSV, and Excel workbook.

---

## Common one-liners

```bash
# Find your fastest DNS resolver right now
net-benchmark dns top --limit 5

# Compare the big three DNS resolvers
net-benchmark dns compare Cloudflare Google Quad9 --show-details

# Monitor DNS with DoT and alerts for 1 hour
net-benchmark dns monitoring --use-defaults --dot \
  --interval 30 --duration 3600 \
  --alert-latency 150 --output monitor.log

# Find your fastest HTTP endpoint right now
net-benchmark http top --limit 5

# Compare two APIs side-by-side
net-benchmark http compare api.example.com api2.example.com --iterations 3 --show-details

# Monitor HTTP with alerts for 1 hour
net-benchmark http monitoring --use-defaults \
  --interval 30 --duration 3600 \
  --alert-latency 500 --alert-failure-rate 5
```

---

## Next steps

- [DNS Benchmark](dns-benchmark.md) — full DNS guide
- [HTTP Benchmark](http-benchmark.md) — full HTTP guide
- [Export Formats](../guides/export-formats.md)
