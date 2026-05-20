# Automation & CI

## GitHub Actions — DNS

```yaml
# .github/workflows/dns-check.yml
name: DNS Performance Check

on:
  push:
    branches: [main]
  schedule:
    - cron: "0 6 * * *"   # Daily at 06:00 UTC

jobs:
  dns-benchmark:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install net-benchmark
        run: pip install net-benchmark

      - name: Run DNS benchmark
        run: |
          net-benchmark dns benchmark \
            --resolvers "1.1.1.1,8.8.8.8" \
            --domains "api.service.com,database.service.com" \
            --formats csv \
            --quiet

      - name: Upload results
        uses: actions/upload-artifact@v4
        with:
          name: dns-benchmark-results
          path: benchmark_results/
```

## GitHub Actions — HTTP

```yaml
# .github/workflows/http-check.yml
name: HTTP Endpoint Health Check

on:
  push:
    branches: [main]

jobs:
  http-benchmark:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install net-benchmark
        run: pip install net-benchmark

      - name: HTTP endpoint health check
        run: |
          net-benchmark http benchmark \
            --targets "https://api.prod.example.com/health,https://web.prod.example.com" \
            --assert status=200 \
            --assert max_latency=1000 \
            --formats csv \
            --quiet

      - name: Upload results
        uses: actions/upload-artifact@v4
        with:
          name: http-benchmark-results
          path: benchmark_results/
```

---

## Cron jobs — DNS

```bash
# Daily at 02:00
0 2 * * * /usr/local/bin/net-benchmark dns benchmark \
  --use-defaults \
  --formats csv \
  --quiet \
  --output /var/log/net_benchmark/daily_$(date +\%Y\%m\%d)

# Every 6 hours
0 */6 * * * /usr/local/bin/net-benchmark dns benchmark \
  --use-defaults \
  --formats csv \
  --quiet \
  --output /var/log/net_benchmark/$(date +\%Y\%m\%d_\%H)

# Monthly management report (1st of the month)
0 0 1 * * /usr/local/bin/net-benchmark dns benchmark \
  --use-defaults \
  --formats excel,pdf \
  --domain-stats \
  --error-breakdown \
  --output /var/reports/dns/$(date +\%Y\%m)
```

## Cron jobs — HTTP

```bash
# Hourly HTTP health check
0 * * * * /usr/local/bin/net-benchmark http benchmark \
  --targets targets.txt \
  --assert status=200 --assert max_latency=1000 \
  --formats csv --quiet \
  --output /var/reports/http/$(date +\%Y\%m\%d_\%H)
```

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | Runtime error (check stderr) |
| `2` | Invalid arguments |

Use exit codes in CI pipelines to gate deployments:

```bash
net-benchmark http benchmark \
  --targets "https://api.myapp.com/health" \
  --assert status=200 \
  --quiet \
  --formats csv || exit 1
```
