# FAQ

## DNS

**Why is my ISP's DNS not the fastest?**

Local ISP DNS often has caching advantages but may lack a global anycast network,
DNSSEC validation, privacy features (DoH/DoT), and reliability guarantees.
Test both with `net-benchmark dns compare` and decide based on your priorities.

**How often should I benchmark DNS?**

When choosing a provider (one-time, 3+ iterations), monthly for network health
checks, before and after migrating providers, and on-demand when troubleshooting
slow requests.

**Can I test my own DNS server?**

Yes. Add it to a custom JSON file:

```json
{ "resolvers": [{ "name": "My DNS", "ip": "192.168.1.1" }] }
```

Then: `net-benchmark dns benchmark --resolvers my-resolvers.json --use-defaults`

**What does `DNSSEC_FAILED` mean?**

The resolver did not return a valid DNSSEC signature (AD flag) for the queried
domain. This is expected for unsigned domains — only ~33% of commonly tested
domains are DNSSEC-signed.

**Why do results vary between runs?**

Network congestion, DNS caching at the resolver and intermediate hops, server
load fluctuations, and geographic anycast routing decisions all contribute.
Run `--iterations 5` and compare median latency for stable results.

---

## HTTP

**Why is my API slower than expected?**

The timing breakdown (DNS → TCP → TLS → TTFB → TTLB) tells you exactly where
the time goes. If DNS is slow, check your resolver. If TLS is slow, check
certificate chain size or OCSP stapling. If TTFB is slow, the server logic
or database is the bottleneck.

**Can I test endpoints behind authentication?**

Yes — `--auth basic:user:pass`, `--auth bearer:token`, or
`--headers x-api-key:key` all work. mTLS is also supported via
`--cert` and `--cert-key`.

**How often should I benchmark HTTP endpoints?**

One-time when choosing a CDN or API provider, daily for critical production
endpoints, before deployment to catch performance regressions, and after
incidents to validate fixes.

---

## General

**PDF export fails — what should I do?**

Install WeasyPrint and its system-level C dependencies.
See [Installation](../guides/installation.md) for WeasyPrint setup.
Or skip PDF: `--formats csv,excel`.

**Command not found after install?**

```bash
pip install -e .
python -m net_benchmark.dns_benchmark.cli --help   # DNS fallback
python -m net_benchmark.http_bench.cli --help      # HTTP fallback
```

Make sure the Python `bin` / `Scripts` directory is in your `PATH`.

**Is this tool safe to use in production?**

Yes. It only performs standard DNS lookups and HTTP read requests. It does not
modify DNS records, modify data on servers, perform attacks, or send data to
external servers beyond the queries themselves.
