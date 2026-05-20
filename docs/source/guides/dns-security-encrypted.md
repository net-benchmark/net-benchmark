# DNS Security & Encrypted DNS

Three protocols are fully supported — each adds privacy at a latency cost.

| Protocol | Flag | Typical overhead | When to use |
|---|---|---|---|
| Plain UDP | *(default)* | baseline | Latency benchmarking |
| DNS-over-HTTPS | `--doh` | +50–200 ms | Privacy, firewall bypass |
| DNS-over-TLS | `--dot` | +200–500 ms cold, ~50 ms warm | Encrypted transport |
| DNSSEC | `--dnssec-validate` | +30–100 ms | Validating resolver integrity |

```{warning}
**Tradeoffs**

- DoH and DoT add TLS handshake overhead on first query per resolver.
  Use `--warmup-fast` to absorb this before measuring.
- `--dnssec-validate` requests RRSIG records and enforces the AD flag.
  Only ~33% of common domains are DNSSEC-signed — expect `DNSSEC_FAILED`
  results on unsigned domains. Latency numbers with and without this flag
  are **not directly comparable**.
- Results on mobile/hotspot will show 2–5× higher variance than wired Ethernet.
  Use `--iterations 5` and compare median latency, not average.
```

---

## DoH — DNS-over-HTTPS

```bash
# DoH benchmark
net-benchmark dns benchmark \
  --resolvers "Cloudflare,Google" \
  --domains "cloudflare.com,google.com" \
  --doh --warmup-fast

# Custom resolvers — must supply URLs 1:1, order matters, or it fails early
net-benchmark dns benchmark \
  --resolvers "Cloudflare,Google" \
  --domains "bing.com,google.com" \
  --doh \
  --doh-url "https://cloudflare-dns.com/dns-query,https://dns.google/dns-query" \
  --iterations 1 \
  --formats csv \
  --output ./doh_results_explicit_urls

# DoH + DNSSEC enforced + export
net-benchmark dns benchmark --use-defaults --doh --dnssec-validate --formats csv,excel

# DoH + custom URLs + monitoring
net-benchmark dns monitoring \
  --resolvers "Cloudflare,Google" \
  --doh \
  --doh-url "https://cloudflare-dns.com/dns-query,https://dns.google/dns-query" \
  --interval 30 --duration 7200

# Rank top DoH resolvers
net-benchmark dns top --doh --limit 5

# Compare DoH resolvers
net-benchmark dns compare Cloudflare Google --doh --iterations 3
```

---

## DoT — DNS-over-TLS

```bash
# DoT with DNSSEC on signed domains
net-benchmark dns benchmark \
  --resolvers "Cloudflare,Quad9" \
  --domains "cloudflare.com,quad9.net" \
  --dot \
  --dnssec-validate

# DoT + DNSSEC + multiple iterations
net-benchmark dns benchmark \
  --resolvers "Cloudflare,Quad9,Google" \
  --domains "cloudflare.com,quad9.net,google.com" \
  --dot \
  --dnssec-validate \
  --iterations 5 \
  --formats excel

# Rank top DoT resolvers by reliability
net-benchmark dns top --dot --metric reliability --limit 5

# Monitor with DoT
net-benchmark dns monitoring --use-defaults --dot \
  --interval 60 --alert-latency 300
```

---

## DNSSEC validation

```bash
# DNSSEC validate
net-benchmark dns benchmark \
  --resolvers "Cloudflare,Quad9" \
  --domains "cloudflare.com,quad9.net" \
  --dnssec-validate
```

```{note}
Only ~33% of common domains are DNSSEC-signed. Expect `DNSSEC_FAILED` on
unsigned domains — this is expected, not a tool bug.
```

---

## Early failure examples

These commands fail immediately before any query runs:

```bash
# --doh and --dot are mutually exclusive
net-benchmark dns benchmark --use-defaults --doh --dot
# ERROR: --doh and --dot are mutually exclusive.

# --doh-url count must match --resolvers count
net-benchmark dns benchmark --resolvers "Cloudflare,Google" --doh \
  --doh-url "https://cloudflare-dns.com/dns-query"
# ERROR: --doh-url has 1 URL(s) but --resolvers has 2 resolver(s). Counts must match.

# Custom IP with --doh requires --doh-url
net-benchmark dns benchmark --resolvers "192.168.1.1" --doh
# ERROR: --doh requires a DoH URL for: 192.168.1.1. Use --doh-url to supply them explicitly.
```
