# HTTP Benchmark

Latency, TTFB, security headers, CDN fingerprinting, TLS certs — from a single CLI.

## Why benchmark HTTP?

Every HTTP request hides a dozen performance and security signals — DNS, TCP, TLS,
redirects, compression, caching, CDN routing, and server software.
Most tools measure only total latency. net-benchmark gives you the full picture.

**The problem:**
- ⏱️ Hidden bottlenecks — is the delay DNS, TCP, TLS, or the server itself?
- 🔗 Silent redirects — each hop adds latency you can't see without per-hop timing
- 🔒 Missing security headers — CSP, HSTS, X-Frame-Options often absent
- 🕵️ Unknown CDN — what CDN is actually serving your traffic?
- 📜 Expired certificates — hard to catch before they break production

**net-benchmark helps you:**
- Break down every request — DNS → TCP → TLS → TTFB → TTLB, all in milliseconds
- Get real stats — P95, P99, jitter, consistency scores
- Audit security — HSTS, CSP, X-Frame-Options, CDN fingerprinting, server header leaks
- Capture TLS certs — expiry days, CN, issuer, SANs, wildcard detection
- Test at scale — 50+ concurrent requests in seconds

**Perfect for:** Developers · DevOps/SRE · Security engineers · API providers

---

## Commands at a glance

| Command | What it does | Quick example |
|---|---|---|
| `benchmark` | Full HTTP benchmark with exports | `net-benchmark http benchmark --use-defaults` |
| `top` | Rank all targets by speed | `net-benchmark http top --limit 5` |
| `compare` | Side-by-side target comparison | `net-benchmark http compare api.example.com api2.example.com` |
| `monitoring` | Continuous monitoring with alerts | `net-benchmark http monitoring --use-defaults` |

---

## benchmark

```bash
# Test 5 built-in targets with a single iteration
net-benchmark http benchmark --use-defaults

# First-run recommendations
net-benchmark http benchmark --use-defaults --formats csv,excel
net-benchmark http benchmark --use-defaults --iterations 5   # meaningful jitter/consistency

# Custom targets from file
net-benchmark http benchmark --targets ./targets.txt

# Inline targets (comma-separated)
net-benchmark http benchmark --targets "https://example.com,https://httpbin.org/get"

# Quick test with only CSV output
net-benchmark http benchmark --use-defaults --formats csv --quiet

# Multiple iterations for statistical accuracy
net-benchmark http benchmark --use-defaults --iterations 5

# Custom HTTP method with body
net-benchmark http benchmark \
  --targets https://api.example.com/echo \
  --method POST \
  --body '{"action":"test"}'

# Body from file
net-benchmark http benchmark \
  --targets https://api.example.com/echo \
  --method POST \
  --body-file payload.json
```

### Advanced usage

```bash
# Export all formats with charts
net-benchmark http benchmark \
  --use-defaults \
  --formats csv,excel,pdf \
  --include-charts \
  --json \
  --output ./full_report

# Separate timeout control
net-benchmark http benchmark \
  --targets https://slow-api.example.com \
  --connect-timeout 5 --read-timeout 30 --write-timeout 10

# Query parameters without hacking the URL
net-benchmark http benchmark \
  --targets https://api.example.com/search \
  --params "page=1,limit=50,q=test"

# High concurrency with warmup
net-benchmark http benchmark \
  --use-defaults \
  --max-concurrent 100 \
  --warmup-fast \
  --iterations 3

# Full assertion suite
net-benchmark http benchmark \
  --targets https://api.example.com/health \
  --assert status=200 \
  --assert body_contains=ok \
  --assert max_latency=500 \
  --assert content_type=application/json \
  --assert response_size_min=10
```

### Force HTTP/1.1 to compare performance

```bash
# Force HTTP/1.1
net-benchmark http benchmark --use-defaults --no-http2

# Watch redirect chains
net-benchmark http benchmark --targets https://github.com --iterations 1

# Detect HTTP/2 downgrades (useful behind corporate proxies)
net-benchmark http benchmark --use-defaults --iterations 3
```

---

## top

Quickly rank targets by speed or reliability.

```bash
# Rank default targets by latency
net-benchmark http top --use-defaults --limit 5

# Rank by TTFB
net-benchmark http top --use-defaults --limit 5 --metric ttfb

# Rank by success rate
net-benchmark http top --targets targets.txt --limit 10 --metric success
```

---

## compare

Benchmark specific targets side-by-side with detailed statistics.

```bash
# Compare two targets
net-benchmark http compare https://example.com https://httpbin.org/get

# Auto-scheme (https:// added if missing)
net-benchmark http compare api.example.com api2.example.com

# With auth and iterations
net-benchmark http compare api.example.com api2.example.com \
  --auth "bearer:token" --iterations 5

# Show per-iteration breakdown
net-benchmark http compare api.example.com api2.example.com \
  --iterations 3 --show-details

# Export comparison
net-benchmark http compare api.example.com api2.example.com \
  --output comparison.csv
```

---

## monitoring

Continuously monitor targets with configurable alerts.

```bash
# Monitor defaults every 60 seconds
net-benchmark http monitoring --use-defaults

# Monitor with custom targets and alerts
net-benchmark http monitoring \
  --targets targets.txt \
  --interval 30 \
  --duration 3600 \
  --alert-latency 500 \
  --alert-failure-rate 5 \
  --output ./monitoring_logs

# Monitor behind a proxy
net-benchmark http monitoring \
  --targets https://internal-api.example.com \
  --proxy http://proxy:8080 \
  --interval 60
```

---

## Key features

**Performance**
- Async engine — httpx with HTTP/2, connection pooling, semaphore concurrency
- Timing breakdown — DNS resolve, TCP connect, TLS handshake, TTFB, TTLB, total latency
- Multi-iteration — run benchmarks multiple times for statistical accuracy
- Statistical analysis — mean, median, P95, P99, jitter, consistency score
- Retry with backoff — exponential backoff on failures
- Configurable concurrency — `--max-concurrent`
- Warmup phase — optional HEAD or full warmup before measurement

**Security & TLS**
- Security headers audit — HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
- CDN fingerprinting — detects Cloudflare, CloudFront, Fastly, Akamai, Google, Azure CDN
- Server header leak detection — flags software/version disclosure
- Inline TLS cert capture — expiry days, CN, issuer, SANs, wildcard detection
- Downgrade detection — HTTPS→HTTP redirect chains and HTTP/2→HTTP/1.1 fallback
- IPv4 vs IPv6 — dual-stack detection per request
- Alt-Svc detection — server advertising HTTP/3

**HTTP/2, redirects, and downgrade detection**

| Feature | What it captures |
|---|---|
| HTTP/2 negotiation | ALPN result (`h2` or `http/1.1`) per request |
| HTTP/2 downgrade detection | Flags when HTTP/2 was expected but HTTP/1.1 was negotiated |
| Redirect chain | Full hop list with per-hop URL, status code, and duration |
| Downgrade detection | Flags any HTTPS→HTTP redirect in the chain |
| Compressed size | Content-Length header captured for bandwidth analysis |

**Assertions & validation**
- `--assert status=200`
- `--assert body_contains=success`
- `--assert header_exists=X-Cache`
- `--assert header_value=X-Cache=HIT`
- `--assert max_latency=500`
- `--assert content_type=application/json`
- `--assert response_size_min=100`
- `--assert response_size_max=10000`

---

## Best practices

| Mode | Recommended flags | Purpose |
|---|---|---|
| **Quick Run** | `--iterations 1 --warmup-fast` | Fast feedback, lightweight warmup |
| **Thorough Run** | `--iterations 5 --warmup --timeout 10 --retries 2` | Multiple passes, full warmup |
| **Debug Mode** | `--iterations 1 --timeout 30 --retries 0` | Long timeout, no retries |
| **API Testing** | `--method POST --body '{}' --headers "Auth:token" --assert status=200` | Send payloads and validate responses |

---

## What the summary shows

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

---

## Troubleshooting

```bash
# Command not found
pip install -e .
python -m net_benchmark.http_bench.cli --help

# PDF generation fails (Ubuntu/Debian)
sudo apt-get install libcairo2 libpango-1.0-0 libpangocairo-1.0-0 \
  libgdk-pixbuf2.0-0 libffi-dev shared-mime-info
# Or skip PDF
net-benchmark http benchmark --use-defaults --formats csv,excel

# Network timeouts
net-benchmark http benchmark --use-defaults --timeout 30 --retries 3
net-benchmark http benchmark --use-defaults --max-concurrent 10

# SSL errors on internal servers
net-benchmark http benchmark --targets https://internal.local --no-verify-ssl
```

---

## Getting help

```bash
net-benchmark http --help
net-benchmark http benchmark --help
net-benchmark http top --help
net-benchmark http compare --help
net-benchmark http monitoring --help
```

Common scenarios:

```bash
# I'm new — where to start?
net-benchmark http benchmark --use-defaults

# Test a specific API with auth
net-benchmark http benchmark \
  --targets https://api.example.com/echo \
  --method POST \
  --headers "x-api-key:sk-abc123" \
  --body '{"test":true}'

# Generate a security audit report
net-benchmark http benchmark \
  --targets https://www.example.com \
  --assert status=200 \
  --assert header_exists=strict-transport-security \
  --formats excel,pdf \
  --output ./security_audit
```
