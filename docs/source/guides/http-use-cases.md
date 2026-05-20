# HTTP Use Cases

## For developers: optimize API performance

```bash
# Find fastest endpoint and break down timing
net-benchmark http benchmark \
  --targets https://api.myapp.com/v1/users,https://api.myapp.com/v2/users \
  --method GET \
  --headers "Authorization:Bearer token" \
  --iterations 5
```

**Result:** Pinpoint whether DNS, TCP, TLS, or server logic is the bottleneck.

---

## For DevOps/SRE: validate CDN migration

```bash
# Compare old origin vs new CDN
net-benchmark http compare \
  https://origin.example.com \
  https://cdn.example.com \
  --iterations 5 --show-details
```

**Result:** Data-driven proof your CDN is (or isn't) faster.

---

## For security engineers: audit public endpoints

```bash
# Full security audit with assertions
net-benchmark http benchmark \
  --targets https://www.example.com,https://api.example.com \
  --assert status=200 \
  --assert header_exists=strict-transport-security \
  --assert header_value=X-Content-Type-Options=nosniff \
  --formats excel,pdf \
  --output ./security_audit
```

**Result:** Instant report card of security header coverage and TLS certificate health.

---

## For enterprise: automated health checks

```bash
# Add to crontab for hourly reports
0 * * * * net-benchmark http benchmark \
  --targets targets.txt \
  --assert status=200 --assert max_latency=1000 \
  --formats csv --quiet \
  --output /var/reports/http/$(date +\%Y\%m\%d_\%H)
```

**Result:** Automated SLA compliance and performance trending.

---

## CI/CD integration

```yaml
- name: HTTP Endpoint Health Check
  run: |
    pip install net-benchmark
    net-benchmark http benchmark \
      --targets "https://api.prod.example.com/health,https://web.prod.example.com" \
      --assert status=200 \
      --assert max_latency=1000 \
      --formats csv \
      --quiet
```

---

## API testing with payloads

```bash
# POST with JSON body
net-benchmark http benchmark \
  --targets https://api.example.com/echo \
  --method POST \
  --body '{"action":"test"}'

# POST with body from file
echo '{"name":"test","value":42}' > payload.json
net-benchmark http benchmark \
  --targets https://api.example.com/echo \
  --method POST \
  --body-file payload.json

# With query parameters
net-benchmark http benchmark \
  --targets https://api.example.com/search \
  --params "page=1,limit=50,q=test"
```

---

## Command showcase

| Command | Purpose | Typical use case | Key options | Output |
|---|---|---|---|---|
| **top** | Quick ranking of targets by speed/reliability | Fast check to see which endpoint is best right now | `--limit`, `--metric`, `--iterations` | Sorted list with latency & success rate |
| **compare** | Side-by-side comparison of specific targets | Detailed benchmarking across chosen endpoints | `--iterations`, `--show-details`, `--output` | Table with latency, TTFB, success rate, per-iteration breakdown |
| **monitoring** | Continuous monitoring with alerts | Real-time tracking of endpoint health over time | `--interval`, `--duration`, `--alert-latency`, `--alert-failure-rate`, `--output` | Live status, alerts, per-interval JSON snapshots |
