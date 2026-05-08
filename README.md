# net-benchmark

fast, extensible network benchmarking — dns, http, and ssl from a single cli.

[![PyPI version](https://badge.fury.io/py/net-benchmark.svg)](https://pypi.org/project/net-benchmark)
[![Python](https://img.shields.io/pypi/pyversions/net-benchmark.svg)](https://pypi.org/project/net-benchmark)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI](https://github.com/net-benchmark/net-benchmark/actions/workflows/ci.yml/badge.svg)](https://github.com/net-benchmark/net-benchmark/actions)
[![Downloads](https://pepy.tech/badge/net-benchmark)](https://pepy.tech/project/net-benchmark)

```bash
pip install net-benchmark
pip install net-benchmark[pdf]   # with pdf export
```

> successor to [dns-benchmark-tool](https://github.com/net-benchmark/dns-benchmark-tool) — fully backward compatible.
> `dns-benchmark` command still works as an alias.

---

## Table of contents

- [Installation](#installation)
- [Tools](#tools)
  - [DNS benchmark](#dns-benchmark)
  - [HTTP benchmark](#http-benchmark)
  - [SSL check](#ssl-check)
- [Export formats](#export-formats)
- [Release workflow](#release-workflow)
- [Links & Support](#links--support)
- [Contributing](#contributing)
- [License](#license)

---

## Installation

```bash
pip install net-benchmark          # core
pip install net-benchmark[pdf]     # with pdf export
```

### Requirements

- Python 3.9+
- pip package manager

### Install from Source

```bash
git clone https://github.com/net-benchmark/net-benchmark.git
cd net-benchmark
pip install -e .
```

### Verify Installation

```bash
net-benchmark --version
net-benchmark dns --help
```

### First Run

```bash
# Test with defaults (recommended for first time)
net-benchmark dns benchmark --use-defaults --formats csv,excel
```

---

## Tools

### DNS benchmark

<details>
<summary><strong>DNS benchmark</strong> — test dns resolver performance, dnssec, doh/dot</summary>

#### 🎯 Why This Tool?

DNS resolution is often the hidden bottleneck in network performance. A slow resolver can add hundreds of milliseconds to every request.

##### The Problem

- ⏱️ **Hidden Bottleneck**: DNS can add 300ms+ to every request
- 🤷 **Unknown Performance**: Most developers never test their DNS
- 🌍 **Location Matters**: "Fastest" resolver depends on where YOU are
- 🔒 **Security Varies**: DNSSEC, DoH, DoT support differs wildly

##### The Solution

net-benchmark helps you:

- 🔍 **Find the fastest** DNS resolver for YOUR location
- 📊 **Get real data** - P95, P99, jitter, consistency scores
- 🛡️ **Validate security** - DNSSEC verification built-in
- 🚀 **Test at scale** - 100+ concurrent queries in seconds

##### Perfect For

- ✅ **Developers** optimizing API performance
- ✅ **DevOps/SRE** validating resolver SLAs
- ✅ **Self-hosters** comparing Pi-hole/Unbound vs public DNS
- ✅ **Network admins** running compliance checks

---

#### Quick start

```bash
# Test default resolvers against popular domains
net-benchmark dns benchmark --use-defaults --formats csv,excel
```

Results are automatically saved to `./benchmark_results/` with summary CSV, detailed raw data, and optional PDF/Excel reports.

> For installation details, see [Installation](#installation).  
> For PDF export, see [PDF dependencies](#pdf-dependencies) under [Export formats](#export-formats).

---

#### ⚡ Commands at a Glance

| Command | What it does | Quick example |
|---|---|---|
| `benchmark` | Full DNS benchmark with exports | `net-benchmark dns benchmark --use-defaults` |
| `top` | Rank all resolvers by speed | `net-benchmark dns top --limit 5` |
| `compare` | Side-by-side resolver comparison | `net-benchmark dns compare Cloudflare Google Quad9` |
| `monitoring` | Continuous monitoring with alerts | `net-benchmark dns monitoring --use-defaults` |

```bash
# Find your fastest resolver right now
net-benchmark dns top --limit 5

# Compare the big three
net-benchmark dns compare Cloudflare Google Quad9 --show-details

# Monitor with DoT and alerts for 1 hour
net-benchmark dns monitoring --use-defaults --dot \
  --interval 30 --duration 3600 \
  --alert-latency 150 --output monitor.log
```

---

#### ✨ Key Features

##### 🚀 Performance

- **Async queries** - Test 100+ resolvers simultaneously
- **Multi-iteration** - Run benchmarks multiple times for accuracy
- **Statistical analysis** - Mean, median, P95, P99, jitter, consistency
- **Cache control** - Test with/without DNS caching

##### 🔒 Security & Privacy

- **DNSSEC validation** - Verify cryptographic trust chains
- **DNS-over-HTTPS (DoH)** - Encrypted DNS benchmarking
- **DNS-over-TLS (DoT)** - Secure transport testing
- **DNS-over-QUIC (DoQ)** - Experimental QUIC support

##### 📊 Analysis & Export

- **Multiple formats** - CSV, Excel, PDF, JSON (see [Export formats](#export-formats) for details)
- **Visual reports** - Charts and graphs
- **Domain statistics** - Per-domain performance analysis
- **Error breakdown** - Identify problematic resolvers

##### 🏢 Enterprise Features

- **TSIG authentication** - Secure enterprise queries
- **Zone transfers** - AXFR/IXFR validation
- **Dynamic updates** - Test DNS write operations
- **Compliance reports** - Audit-ready documentation

##### 🌐 Cross-Platform

- **Linux, macOS, Windows** - Works everywhere
- **CI/CD friendly** - JSON output, exit codes
- **IDNA support** - Internationalized domain names
- **Auto-detection** - Windows WMI DNS discovery

---

#### 🔒 Security & Encrypted DNS

Three protocols are fully supported — each adds privacy at a latency cost.

| Protocol | Flag | Typical overhead | When to use |
|---|---|---|---|
| Plain UDP | *(default)* | baseline | Latency benchmarking |
| DNS-over-HTTPS | `--doh` | +50–200ms | Privacy, firewall bypass |
| DNS-over-TLS | `--dot` | +200–500ms cold, ~50ms warm | Encrypted transport |
| DNSSEC | `--dnssec-validate` | +30–100ms | Validating resolver integrity |

> ⚠️ **Tradeoffs**
> - DoH and DoT add TLS handshake overhead on first query per resolver. Use `--warmup-fast` to absorb this before measuring.
> - `--dnssec-validate` requests RRSIG records and enforces the AD flag. Only ~33% of common domains are DNSSEC-signed — expect `DNSSEC_FAILED` results on unsigned domains. Latency numbers with and without this flag are **not directly comparable**.
> - Results on mobile/hotspot will show 2–5× higher variance than wired ethernet. Use `--iterations 5` and compare median latency, not average.

```bash
# DoH benchmark
net-benchmark dns benchmark \
  --resolvers "Cloudflare,Google" \
  --domains "cloudflare.com,google.com" \
  --doh --warmup-fast

# custom resolvers — must supply urls 1:1, order matters, or it fails early
net-benchmark dns benchmark \
  --resolvers "Cloudflare,Google" \
  --domains "bing.com,google.com" \
  --doh \
  --doh-url "https://cloudflare-dns.com/dns-query,https://dns.google/dns-query" \
  --iterations 1 \
  --formats csv \
  --output ./doh_results_explicit_urls

# DoT with DNSSEC on signed domains
net-benchmark dns benchmark \
  --resolvers "Cloudflare,Quad9" \
  --domains "cloudflare.com,quad9.net" \
  --dot \
  --dnssec-validate

# DOH rank top resolvers
net-benchmark dns top --doh --limit 5

# DOT rank top resolvers
net-benchmark dns top --dot --metric reliability --limit 5

# Compare DoH resolvers
net-benchmark dns compare Cloudflare Google --doh --iterations 3

# Monitor with DoT
net-benchmark dns monitoring --use-defaults --dot \
  --interval 60 --alert-latency 300

# DoH + DNSSEC enforced + export
net-benchmark dns benchmark --use-defaults --doh --dnssec-validate --formats csv,excel

# DoT + DNSSEC enforced + multiple iterations
net-benchmark dns benchmark \
  --resolvers "Cloudflare,Quad9,Google" \
  --domains "cloudflare.com,quad9.net,google.com" \
  --dot \
  --dnssec-validate \
  --iterations 5 \
  --formats excel

# DoH + custom urls + monitoring
net-benchmark dns monitoring \
  --resolvers "Cloudflare,Google" \
  --doh \
  --doh-url "https://cloudflare-dns.com/dns-query,https://dns.google/dns-query" \
  --interval 30 --duration 7200
```

**Early failure examples** — these fail immediately before any query runs:

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

---

#### 🔧 Advanced Capabilities

> ⚠️ These flags are **documented for visibility** but not yet implemented.  
> They represent upcoming advanced features.

- `--zone-transfer` → AXFR/IXFR zone transfer testing *(coming soon)*
- `--tsig` → TSIG-authenticated queries *(coming soon)*
- `--idna` → Internationalized domain name support *(coming soon)*

<details>
<summary><b>🚀 Performance & Concurrency Features</b></summary>

<br>

- **Async I/O with dnspython** - Test 100+ resolvers simultaneously
- **Trio framework support** - High-concurrency async operations
- **Configurable concurrency** - Control max concurrent queries
- **Retry logic** - Exponential backoff for failed queries
- **Cache simulation** - Test with/without DNS caching
- **Multi-iteration benchmarks** - Run tests multiple times for accuracy
- **Warmup phase** - Pre-warm DNS caches before testing
- **Statistical analysis** - Mean, median, P95, P99, jitter, consistency scores

**Example:**

```bash
net-benchmark dns benchmark \
  --max-concurrent 200 \
  --iterations 5 \
  --timeout 3.0 \
  --warmup
```

</details>

<details>
<summary><b>🔒 Security & Privacy Features</b></summary>

<br>

- **DNSSEC validation** - Verify cryptographic trust chains
- **DNS-over-HTTPS (DoH)** - Encrypted DNS benchmarking via HTTPS
- **DNS-over-TLS (DoT)** - Secure transport layer testing
- **DNS-over-QUIC (DoQ)** - Experimental QUIC protocol support
- **TSIG authentication** - Transaction signatures for enterprise DNS
- **EDNS0 support** - Extended DNS features and larger payloads

**Example:**

```bash
# Test DoH resolvers
net-benchmark dns benchmark \
  --doh \
  --resolvers doh-providers.json \
  --dnssec-validate
```

</details>

<details>
<summary><b>🏢 Enterprise & Migration Features</b></summary>

<br>

- **Zone transfers (AXFR/IXFR)** - Full and incremental zone transfer validation
- **Dynamic DNS updates** - Test DNS write operations and updates
- **EDNS0 support** - Extended DNS options, client subnet, larger payloads
- **Windows WMI integration** - Auto-detect active system DNS settings
- **Compliance reporting** - Generate audit-ready PDF/Excel reports
- **SLA validation** - Track uptime and performance thresholds

**Example:**

```bash
# Validate DNS migration
net-benchmark dns benchmark \
  --resolvers old-provider.json,new-provider.json \
  --zone-transfer \ # coming soon
  --output migration-report/ \
  --formats pdf,excel
```

</details>

<details>
<summary><b>📊 Analysis & Reporting Features</b></summary>

<br>

- **Per-domain statistics** - Analyze performance by domain
- **Per-record-type stats** - Compare A, AAAA, MX, TXT, etc.
- **Error breakdown** - Categorize and count error types
- **Comparison matrices** - Side-by-side resolver comparisons
- **Trend analysis** - Performance over time (with multiple runs)
- **Best-by-criteria** - Find best resolver by latency/reliability/consistency

**Example:**

```bash
# Detailed analysis
net-benchmark dns benchmark \
  --use-defaults \
  --formats csv,excel \
  --domain-stats \
  --record-type-stats \
  --error-breakdown \
  --formats csv,excel,pdf
```

</details>

<details>
<summary><b>🌐 Internationalization & Compatibility</b></summary>

<br>

- **IDNA support** - Internationalized domain names (IDN)
- **Multiple record types** - A, AAAA, MX, TXT, CNAME, NS, SOA, PTR, SRV, CAA
- **Cross-platform** - Linux, macOS, Windows (native support)
- **CI/CD integration** - JSON output, proper exit codes, quiet mode
- **Custom resolvers** - Load from JSON, test your own DNS servers
- **Custom domains** - Test against your specific domain list

**Example:**

```bash
# Test internationalized domains
net-benchmark dns benchmark \
  --domains international-domains.txt \
  --record-types A,AAAA,MX \
  --resolvers custom-resolvers.json
```

</details>

> 💡 **Most users only need basic features.** These advanced capabilities are available when you need them.

---

#### 💼 Use Cases

##### 🔧 For Developers: Optimize API Performance

```bash
# Find fastest DNS for your API endpoints
net-benchmark dns benchmark \
  --domains api.myapp.com,cdn.myapp.com \
  --record-types A,AAAA \
  --resolvers production.json \
  --iterations 10
```

**Result:** Reduce API latency by 100-300ms

---

##### 🛡️ For DevOps/SRE: Validate Before Migration

```bash
# Test new DNS provider before switching
net-benchmark dns benchmark \
  --resolvers current-dns.json,new-dns.json \
  --use-defaults \
  --dnssec-validate \
  --output migration-report/ \
  --formats csv,excel
```

**Result:** Verify performance and security before migration

---

##### 🏠 For Self-Hosters: Prove Pi-hole Performance

```bash
# Compare Pi-hole against public resolvers
net-benchmark dns compare \
  --resolvers pihole.local,1.1.1.1,8.8.8.8,9.9.9.9 \
  --domains common-sites.txt \
  --rounds 10
```

**Result:** Data-driven proof your self-hosted DNS is faster (or not!)

---

##### 📊 For Network Admins: Automated Health Checks

```bash
# Add to crontab for monthly reports
0 0 1 * * net-benchmark dns benchmark \
  --use-defaults \
  --output /var/reports/dns/ \
  --formats excel,csv \
  --domain-stats \
  --error-breakdown
```

**Result:** Automated compliance and SLA reporting

---

##### 🔐 For Privacy Advocates: Test Encrypted DNS

```bash
# Benchmark privacy-focused DoH/DoT resolvers
net-benchmark dns benchmark \
  --doh \
  --resolvers privacy-resolvers.json \
  --domains sensitive-sites.txt \
  --dnssec-validate
```

**Result:** Find fastest encrypted DNS without sacrificing privacy

---

#### 📖 Usage Examples

##### Basic Usage

```bash
# Basic test with progress bars
net-benchmark dns benchmark --use-defaults --formats csv,excel

# Basic test without progress bars
net-benchmark dns benchmark --use-defaults --formats csv,excel --quiet

# Test with custom resolvers and domains
net-benchmark dns benchmark --resolvers data/resolvers.json --domains data/domains.txt

# Quick test with only CSV output
net-benchmark dns benchmark --use-defaults --formats csv
```

##### Advanced Usage

```bash
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

#### Inline input support for resolvers and domains

This feature introduces full support for comma‑separated inline values for the
`--resolvers` and `--domains` flags.

##### New capabilities

1. **inline resolvers**: `--resolvers "1.1.1.1,8.8.8.8,9.9.9.9"`
2. **inline domains**: `--domains "google.com,github.com"`
3. **single values**: `--resolvers "1.1.1.1"` or `--domains "google.com"`
4. **named resolvers**: `--resolvers "cloudflare,google,quad9"`
5. **mixed input**: `--resolvers "1.1.1.1,cloudflare,8.8.8.8"`

##### Backward compatibility

- all existing file‑based configurations continue to work
- no breaking changes to the cli
- file detection takes priority over inline parsing

##### Usage Examples

###### Before (Only files worked)

```bash
net-benchmark dns benchmark \
    --resolvers data/resolvers.json \
    --domains data/domains.txt
```

###### After (Both work)

```bash
# Inline (New)
net-benchmark dns benchmark \
    --resolvers "1.1.1.1,8.8.8.8,9.9.9.9" \
    --domains "google.com,github.com" \
    --timeout 10 \
    --retries 3 \
    --formats csv \
    --output ./troubleshooting

# Files (STILL WORKS)
net-benchmark dns benchmark \
    --resolvers data/resolvers.json \
    --domains data/domains.txt \
    --formats csv
```

###### Named resolvers

```bash
net-benchmark dns benchmark \
    --resolvers "Cloudflare,Google,Quad9" \
    --domains "google.com,github.com" \
    --timeout 10 \
    --retries 3 \
    --formats csv \
    --output ./troubleshooting_named
```

###### Mixed input

```bash
net-benchmark dns benchmark \
    --resolvers "1.1.1.1,Cloudflare,8.8.8.8" \
    --domains "google.com,github.com" \
    --timeout 10 \
    --retries 3 \
    --formats csv \
    --output ./troubleshooting_mixed
```

###### Single

```bash
net-benchmark dns benchmark \
    --resolvers "1.1.1.1" \
    --domains "google.com" \
    --timeout 10 \
    --retries 3 \
    --formats csv \
    --output ./troubleshooting
```

#### 🔧 Utilities

##### Resolver management

```bash
# Show default resolvers and domains
net-benchmark dns list-defaults

# Browse all available resolvers
net-benchmark dns list-resolvers

# Browse with detailed information
net-benchmark dns list-resolvers --details

# Filter by category
net-benchmark dns list-resolvers --category security
net-benchmark dns list-resolvers --category privacy
net-benchmark dns list-resolvers --category family

# Export resolvers to different formats
net-benchmark dns list-resolvers --format csv
net-benchmark dns list-resolvers --format json
```

##### Domain management

```bash
# List all test domains
net-benchmark dns list-domains

# Show domains by category
net-benchmark dns list-domains --category tech
net-benchmark dns list-domains --category ecommerce
net-benchmark dns list-domains --category social

# Limit results
net-benchmark dns list-domains --count 10
net-benchmark dns list-domains --category news --count 5

# Export domain list
net-benchmark dns list-domains --format csv
net-benchmark dns list-domains --format json
```

##### Category overview

```bash
# View all available categories
net-benchmark dns list-categories
```

##### Configuration management

```bash
# Generate sample configuration
net-benchmark dns generate-config --output sample_config.yaml

# Category-specific configurations
net-benchmark dns generate-config --category security --output security_test.yaml
net-benchmark dns generate-config --category family --output family_protection.yaml
net-benchmark dns generate-config --category performance --output performance_test.yaml

# Custom configuration for specific use case
net-benchmark dns generate-config --category privacy --output privacy_audit.yaml
```

---

#### Complete usage guide

##### Quick performance test

```bash
# Basic test with progress bars
net-benchmark dns benchmark --use-defaults

# Quick test with only CSV output
net-benchmark dns benchmark --use-defaults --formats csv --quiet

# Test specific record types
net-benchmark dns benchmark --use-defaults --record-types A,AAAA,MX
```

Add-on analytics flags:

```bash
# Include domain and record-type analytics and error breakdown
net-benchmark dns benchmark --use-defaults \
  --domain-stats --record-type-stats --error-breakdown
```

JSON export:

```bash
# Export a machine-readable bundle
net-benchmark dns benchmark --use-defaults --json --output ./results
```

##### Network administrator

```bash
# Compare internal vs external DNS
net-benchmark dns benchmark \
  --resolvers "192.168.1.1,1.1.1.1,8.8.8.8,9.9.9.9" \
  --domains "internal.company.com,google.com,github.com,api.service.com" \
  --formats excel,pdf \
  --timeout 3 \
  --max-concurrent 50 \
  --output ./network_audit

# Test DNS failover scenarios
net-benchmark dns benchmark \
  --resolvers data/primary_resolvers.json \
  --domains data/business_critical_domains.txt \
  --record-types A,AAAA \
  --retries 3 \
  --formats csv,excel \
  --output ./failover_test
```

##### ISP & network operator

```bash
# Comprehensive ISP resolver comparison
net-benchmark dns benchmark \
  --resolvers data/isp_resolvers.json \
  --domains data/popular_domains.txt \
  --timeout 5 \
  --max-concurrent 100 \
  --formats csv,excel,pdf \
  --output ./isp_performance_analysis

# Regional performance testing
net-benchmark dns benchmark \
  --resolvers data/regional_resolvers.json \
  --domains data/regional_domains.txt \
  --formats excel \
  --quiet \
  --output ./regional_analysis
```

##### Developer & DevOps

```bash
# Test application dependencies
net-benchmark dns benchmark \
  --resolvers "1.1.1.1,8.8.8.8" \
  --domains "api.github.com,registry.npmjs.org,pypi.org,docker.io,aws.amazon.com" \
  --formats csv \
  --quiet \
  --output ./app_dependencies

# CI/CD integration test
net-benchmark dns benchmark \
  --resolvers data/ci_resolvers.json \
  --domains data/ci_domains.txt \
  --timeout 2 \
  --formats csv \
  --quiet
```

##### Security auditor

```bash
# Security-focused resolver testing
net-benchmark dns benchmark \
  --resolvers data/security_resolvers.json \
  --domains data/malware_test_domains.txt \
  --formats csv,pdf \
  --output ./security_audit

# Privacy-focused testing
net-benchmark dns benchmark \
  --resolvers data/privacy_resolvers.json \
  --domains data/tracking_domains.txt \
  --formats excel \
  --output ./privacy_analysis
```

##### Enterprise IT

```bash
# Corporate network assessment
net-benchmark dns benchmark \
  --resolvers data/enterprise_resolvers.json \
  --domains data/corporate_domains.txt \
  --record-types A,AAAA,MX,TXT,SRV \
  --timeout 10 \
  --max-concurrent 25 \
  --retries 2 \
  --formats csv,excel,pdf \
  --output ./enterprise_dns_audit

# Multi-location testing
net-benchmark dns benchmark \
  --resolvers data/global_resolvers.json \
  --domains data/international_domains.txt \
  --formats excel \
  --output ./global_performance
```

#### 🔍 New CLI Options

| Option             | Description                                                                 | Example                                                                 |
|--------------------|-----------------------------------------------------------------------------|-------------------------------------------------------------------------|
| `--iterations, -i` | Run the full benchmark loop **N times**                                     | `net-benchmark dns benchmark --use-defaults -i 3`                           |
| `--use-cache`      | Allow cached results to be reused across iterations                         | `net-benchmark dns benchmark --use-defaults -i 3 --use-cache`               |
| `--warmup`         | Run a **full warmup** (all resolvers × domains × record types)              | `net-benchmark dns benchmark --use-defaults --warmup`                       |
| `--warmup-fast`    | Run a **lightweight warmup** (one probe per resolver)                       | `net-benchmark dns benchmark --use-defaults --warmup-fast`                  |
| `--include-charts` | Embed charts and graphs in PDF/Excel reports for visual performance analysis | `net-benchmark dns benchmark --use-defaults --formats pdf,excel --include-charts` |

---

#### ⚡ CLI Commands

##### 🚀 Top

Quickly rank resolvers by speed and reliability.

```bash
# Rank resolvers quickly
net-benchmark dns top

# Use custom domain list
net-benchmark dns top -d domains.txt

# Export results to JSON
net-benchmark dns top -o results.json
```

---

##### 📊 Compare

Benchmark resolvers side‑by‑side with detailed statistics.

```bash
# Compare Cloudflare, Google, and Quad9
net-benchmark dns compare Cloudflare Google Quad9

# Compare by IP addresses
net-benchmark dns compare 1.1.1.1 8.8.8.8 9.9.9.9

# Show detailed per-domain breakdown
net-benchmark dns compare Cloudflare Google --show-details

# Export results to CSV
net-benchmark dns compare Cloudflare Google -o results.csv
```

---

##### 🔄 Monitoring

Continuously monitor resolver performance with alerts.

```bash
# Monitor default resolvers continuously (every 60s)
net-benchmark dns monitoring --use-defaults

# Monitor with custom resolvers and domains
net-benchmark dns monitoring -r resolvers.json -d domains.txt

# Run monitoring for 1 hour with alerts
net-benchmark dns monitoring --use-defaults --interval 30 --duration 3600 \
  --alert-latency 150 --alert-failure-rate 5 --output monitor.log
```

---

##### 🌟 Command Showcase

| Command      | Purpose | Typical Use Case | Key Options | Output |
|--------------|---------|------------------|-------------|--------|
| **top**      | Quick ranking of resolvers by speed and reliability | Fast check to see which resolver is best right now | `--domains`, `--record-types`, `--output` | Sorted list of resolvers with latency & success rate |
| **compare**  | Side‑by‑side comparison of specific resolvers | Detailed benchmarking across chosen resolvers/domains | `--domains`, `--record-types`, `--iterations`, `--output`, `--show-details` | Table of resolvers with latency, success rate, per‑domain breakdown |
| **monitoring** | Continuous monitoring with alerts | Real‑time tracking of resolver performance over time | `--interval`, `--duration`, `--alert-latency`, `--alert-failure-rate`, `--output`, `--use-defaults` | Live status indicators, alerts, optional log file |

---

#### 📊 Analysis Enhancements

- **Iteration count**: displayed when more than one iteration is run.  
- **Cache hits**: shows how many queries were served from cache (when `--use-cache` is enabled).  
- **Failure tracking**: resolvers with repeated errors are counted and can be inspected with `get_failed_resolvers()`.  
- **Cache statistics**: available via `get_cache_stats()`, showing number of cached entries and whether cache is enabled.  
- **Warmup results**: warmup queries are marked with `iteration=0` in raw data, making them easy to filter out in analysis.  

Example summary output:

```markdown

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

#### ⚡ Best Practices

| Mode            | Recommended Flags                                                                 | Purpose                                                                 |
|-----------------|------------------------------------------------------------------------------------|-------------------------------------------------------------------------|
| **Quick Run**   | `--iterations 1 --timeout 1 --retries 0 --warmup-fast`                             | Fast feedback, minimal retries, lightweight warmup. Good for quick checks. |
| **Thorough Run**| `--iterations 3 --use-cache --warmup --timeout 5 --retries 2`                      | Multiple passes, cache enabled, full warmup. Best for detailed benchmarking. |
| **Debug Mode**  | `--iterations 1 --timeout 10 --retries 0 --quiet`                                  | Long timeout, no retries, minimal output. Useful for diagnosing resolver issues. |
| **Balanced Run**| `--iterations 2 --use-cache --warmup-fast --timeout 2 --retries 1`                 | A middle ground: moderate speed, some retries, cache enabled, quick warmup. |

#### ⚙️ Configuration Files

##### Resolvers JSON format

```json
{
  "resolvers": [
    {
      "name": "Cloudflare",
      "ip": "1.1.1.1",
      "ipv6": "2606:4700:4700::1111"
    },
    {
      "name": "Google DNS",
      "ip": "8.8.8.8",
      "ipv6": "2001:4860:4860::8888"
    }
  ]
}
```

##### Domains text file format

```txt
# Popular websites
google.com
github.com
stackoverflow.com

# Corporate domains
microsoft.com
apple.com
amazon.com

# CDN and cloud
cloudflare.com
aws.amazon.com
```

---

#### Performance optimization

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

---

#### Troubleshooting

```bash
# Command not found
pip install -e .
python -m net_benchmark.dns_benchmark.cli --help

# PDF generation fails (Ubuntu/Debian) – see [PDF dependencies](#pdf-dependencies)
sudo apt-get install libcairo2 libpango-1.0-0 libpangocairo-1.0-0 \
  libgdk-pixbuf2.0-0 libffi-dev shared-mime-info
# Or skip PDF
net-benchmark dns benchmark --use-defaults --formats csv,excel

# Network timeouts
net-benchmark dns benchmark --use-defaults --timeout 10 --retries 3
net-benchmark dns benchmark --use-defaults --max-concurrent 25
```

##### Debug mode

```bash
# Verbose run
python -m net_benchmark.dns_benchmark.cli benchmark --use-defaults --formats csv

# Minimal configuration
net-benchmark dns benchmark --resolvers "1.1.1.1" --domains "google.com" --formats csv
```

---

#### Automation & CI

##### Cron jobs

```bash
# Daily monitoring
0 2 * * * /usr/local/bin/net-benchmark dns benchmark --use-defaults --formats csv --quiet --output /var/log/net_benchmark/daily_$(date +\%Y\%m\%d)

# Time-based variability (every 6 hours)
0 */6 * * * /usr/local/bin/net-benchmark dns benchmark --use-defaults --formats csv --quiet --output /var/log/net_benchmark/$(date +\%Y\%m\%d_\%H)
```

##### GitHub Actions example

```yaml
- name: DNS Performance Test
  run: |
    pip install net-benchmark
    net-benchmark dns benchmark \
      --resolvers "1.1.1.1,8.8.8.8" \
      --domains "api.service.com,database.service.com" \
      --formats csv \
      --quiet
```

---

#### Screenshots

Place images in `src/net_benchmark/dns_benchmark/docs/screenshots/`:

- `src/net_benchmark/dns_benchmark/docs/screenshots/cli_run.png`
- `src/net_benchmark/dns_benchmark/docs/screenshots/excel_report.png`
- `src/net_benchmark/dns_benchmark/docs/screenshots/pdf_summary.png`
- `src/net_benchmark/dns_benchmark/docs/screenshots/pdf_charts.png`
- `src/net_benchmark/dns_benchmark/docs/screenshots/excel_charts.png`
- `src/net_benchmark/dns_benchmark/docs/screenshots/real_time_monitoring.png`

##### 1. CLI Benchmark Run

[![CLI Benchmark Run](src/net_benchmark/dns_benchmark/docs/screenshots/cli_run.png)](https://github.com/net-benchmark/net-benchmark)

##### 2. Excel Report Output

[![Excel Report Output](src/net_benchmark/dns_benchmark/docs/screenshots/excel_report.png)](https://github.com/net-benchmark/net-benchmark)

##### 3. PDF Executive Summary

[![PDF Executive Summary](src/net_benchmark/dns_benchmark/docs/screenshots/pdf_summary.png)](https://github.com/net-benchmark/net-benchmark)

##### 4. PDF Charts

[![PDF Charts](src/net_benchmark/dns_benchmark/docs/screenshots/pdf_charts.png)](https://github.com/net-benchmark/net-benchmark)

##### 5. Excel Charts

[![Excel Charts](src/net_benchmark/dns_benchmark/docs/screenshots/excel_charts.png)](https://github.com/net-benchmark/net-benchmark)

##### 6. Real Time Monitoring

[![Real Time Monitoring](src/net_benchmark/dns_benchmark/docs/real_time_tracking.gif)](https://github.com/net-benchmark/net-benchmark)

#### Getting help

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

---

#### ❓ FAQ

<details>
<summary><b>Why is my ISP's DNS not fastest?</b></summary>

Local ISP DNS often has caching advantages but may lack:
- Global anycast network (slower for distant domains)
- DNSSEC validation
- Privacy features (DoH/DoT)
- Reliability guarantees

Test both and decide based on YOUR priorities!

</details>

<details>
<summary><b>How often should I benchmark DNS?</b></summary>

- **One-time**: When choosing DNS provider
- **Monthly**: For network health checks
- **Before migration**: When switching providers
- **After issues**: To troubleshoot performance

</details>

<details>
<summary><b>Can I test my own DNS server?</b></summary>

Yes! Just add it to a custom resolvers JSON file:

```json
{
  "resolvers": [
    {"name": "My DNS", "ip": "192.168.1.1"}
  ]
}
```

</details>

<details>
<summary><b>Is this tool safe to use in production?</b></summary>

Yes! The tool only performs DNS lookups (read operations). It does NOT:
- Modify DNS records
- Perform attacks
- Send data to external servers

All tests are standard DNS queries that any resolver handles daily.

</details>

<details>
<summary><b>Why do results vary between runs?</b></summary>

DNS performance varies due to:
- Network conditions
- DNS caching (resolver and intermediate)
- Server load
- Geographic routing changes

Run multiple iterations (`--iterations 5`) for more consistent results.

</details>

</details>

---

### HTTP benchmark

<details>
<summary><strong>HTTP benchmark</strong> — benchmark http/https endpoints <em>(coming in 0.5.0)</em></summary>

#### Planned features

- measure TTFB, download speed, redirect chains
- support for HTTP/2 and HTTP/3
- configurable headers and authentication

> **Status:** planned for version 0.5.0 — [contributions welcome](CONTRIBUTING.md)

</details>

---

### SSL check

<details>
<summary><strong>SSL check</strong> — certificate expiry, chain validation <em>(coming in 0.6.0)</em></summary>

#### Planned features

- check certificate expiration dates
- validate certificate chains and trust stores
- monitor multiple hosts with alerts

> **Status:** planned for version 0.6.0 — [contributions welcome](CONTRIBUTING.md)

</details>

---

## Export formats

| format | flag | notes |
|--------|------|-------|
| CSV | `--formats csv` | raw results + summary + optional domain/record type/error stats |
| Excel | `--formats excel` | formatted workbook with charts and DNSSEC sheet |
| PDF | `--formats pdf` | requires `pip install net-benchmark[pdf]` (see below) |
| JSON | `--json` | full structured payload (separate flag) |

### CSV outputs

- Raw data: individual query results with timestamps and metadata
- Summary statistics: aggregated metrics per resolver
- Domain statistics: per-domain metrics (when `--domain-stats`)
- Record type statistics: per-record-type metrics (when `--record-type-stats`)
- Error breakdown: counts by error type (when `--error-breakdown`)

### Excel report

- Raw data sheet: all query results with formatting
- Resolver summary: comprehensive statistics with conditional formatting
- Domain stats: per-domain performance (optional)
- Record type stats: per-record-type performance (optional)
- Error breakdown: aggregated error counts (optional)
- Performance analysis: charts and comparative analysis

### PDF report

- Executive summary: key findings and recommendations
- Performance charts: latency comparison; optional success rate chart
- Resolver rankings: ordered by average latency
- Detailed analysis: technical deep‑dive with percentiles

### 📄 Optional PDF Export

By default, the tool supports **CSV** and **Excel** exports.  
PDF export requires the extra dependency **weasyprint**, which is not installed automatically to avoid runtime issues on some platforms.

#### Install with PDF support

```bash
pip install net-benchmark[pdf]
```

#### Usage

Once installed, you can request PDF output via the CLI:

```bash
net-benchmark dns benchmark --use-defaults --formats pdf --output ./results
```

If `weasyprint` is not installed and you request PDF output, the CLI will show:

```bash
[-] Error during benchmark: PDF export requires 'weasyprint'. Install with: pip install net-benchmark[pdf]
```

### ⚠️ WeasyPrint Setup (for PDF export) {#pdf-dependencies}

The tool uses **WeasyPrint** to generate PDF reports.  
You need extra system libraries in addition to the Python package.

#### 🛠 Linux (Debian/Ubuntu)

```bash
sudo apt install python3-pip libpango-1.0-0 libpangoft2-1.0-0 \
  libharfbuzz-subset0 libjpeg-dev libopenjp2-7-dev libffi-dev
```

#### 🛠 macOS (Homebrew)

```bash
brew install pango cairo libffi gdk-pixbuf jpeg openjpeg harfbuzz
```

#### 🛠 Windows

Install GTK+ libraries using one of these methods:

- **MSYS2**: [Download MSYS2](https://www.msys2.org/), then run:

  ```bash
  pacman -S mingw-w64-x86_64-gtk3 mingw-w64-x86_64-libffi
  ```

- **GTK+ 64‑bit Installer**: [Download GTK+ Runtime](https://github.com/tschoonj/GTK-for-Windows-Runtime-Environment-Installer/releases) and run the installer.

Restart your terminal after installation.

#### ✅ Verify Installation

After installing the system libraries, install the Python extra:

```bash
pip install net-benchmark[pdf]
```

Then run:

```bash
net-benchmark dns benchmark --use-defaults --formats pdf --output ./results
```

### JSON export

- Machine‑readable bundle including:
  - Overall statistics
  - Resolver statistics
  - Raw query results
  - Domain statistics
  - Record type statistics
  - Error breakdown

### Generate Sample Config

```bash
net-benchmark dns generate-config \
  --category privacy \
  --output my-config.yaml
```

---

## Release workflow

- **Prerequisites**
  - **GPG key configured:** run `make gpg-check` to verify.
  - **Branch protection:** main requires signed commits and passing CI.
  - **CI publish:** triggered on signed tags matching vX.Y.Z.

- **Prepare release (signed)**
  - **Patch/minor/major bump:**
  
    ```bash
    make release-patch      # or: make release-minor / make release-major
    ```

    - Updates versions.
    - Creates or reuses `release/X.Y.Z`.
    - Makes a signed commit and pushes the branch.
  - **Open PR:** from `release/X.Y.Z` into `main`, then merge once CI passes.

- **Tag and publish**
  - **Create signed tag and push:**

    ```bash
    make release-tag VERSION=X.Y.Z
    ```

    - Tags main with `vX.Y.Z` (signed).
    - CI publishes to PyPI.

- **Manual alternative**
  - **Create branch and commit signed:**
  
    ```bash
    git checkout -b release/manually-update-version-based-on-release-pattern
    git add .
    git commit -S -m "Release release/$NEXT_VERSION"
    git push origin release/$NEXT_VERSION
    ```

  - **Open PR and merge into main.**
  - **Then tag:**
  
    ```bash
    make release-tag VERSION=$NEXT_VERSION
    ```

- **Notes**
  - **Signed commits:** `git commit -S ...`
  - **Signed tags:** `git tag -s vX.Y.Z -m "Release vX.Y.Z"`
  - **Version sources:** `pyproject.toml` and `src/net_benchmark/__init__.py`

---

## Links & Support

### Official

- **GitHub**: [net-benchmark/net-benchmark](https://github.com/net-benchmark/net-benchmark)
- **PyPI**: [net-benchmark](https://pypi.org/project/net-benchmark)

### Community

- **Discussions**: [GitHub Discussions](https://github.com/net-benchmark/net-benchmark/discussions)
- **Issues**: [Bug Reports](https://github.com/net-benchmark/net-benchmark/issues)

---

## Contributing

contributions are welcome. see [CONTRIBUTING.md](CONTRIBUTING.md).
this project uses a [BDFL governance model](GOVERNANCE.md) — @frankovo
has final say on technical direction and releases.

---

## License

MIT © [frankovo](https://github.com/frankovo)

> **Looking for dns-benchmark-tool?**
> this project is its successor. the original is archived at
> [net-benchmark/dns-benchmark-tool](https://github.com/net-benchmark/dns-benchmark-tool).

---
powered by [buildtools.net](https://buildtools.net) —
web dashboard, multi-region testing, and enterprise features.
