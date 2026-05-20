# DNS CLI Reference

## Entry points

```
net-benchmark dns [OPTIONS] COMMAND [ARGS]...
dns-benchmark  [OPTIONS] COMMAND [ARGS]...   ← backward-compatible alias
```

## Commands

| Command | Description |
|---|---|
| `benchmark` | Full benchmark suite with exports |
| `top` | Rank resolvers by speed |
| `compare` | Side-by-side comparison |
| `monitoring` | Continuous monitoring with alerts |
| `list-resolvers` | Browse available built-in resolvers |
| `list-domains` | Browse available built-in domain lists |
| `list-defaults` | Show defaults used by `--use-defaults` |
| `list-categories` | Show all resolver / domain categories |
| `generate-config` | Generate a YAML configuration for a category |

---

## net-benchmark dns benchmark

| Option | Type | Default | Description |
|---|---|---|---|
| `--use-defaults` | flag | off | Use built-in resolvers and domains |
| `--resolvers, -r` | TEXT | — | Comma-sep IPs / names or JSON/YAML file path |
| `--domains, -d` | TEXT | — | Comma-sep domains or `.txt` file path |
| `--formats` | TEXT | `csv` | `csv`, `excel`, `pdf` (comma-separated) |
| `--json` | flag | off | Write structured JSON bundle |
| `--output, -o` | PATH | `./benchmark_results` | Output directory |
| `--iterations, -i` | INT | `1` | Number of benchmark passes |
| `--warmup` | flag | off | Full warmup (all resolvers × domains × record types) |
| `--warmup-fast` | flag | off | Lightweight warmup (one probe per resolver) |
| `--use-cache` | flag | off | Reuse DNS cache across iterations |
| `--max-concurrent` | INT | `50` | Max concurrent async queries |
| `--timeout` | FLOAT | `2.0` | Per-query timeout in seconds |
| `--retries` | INT | `1` | Retry count on failure |
| `--record-types` | TEXT | `A` | Record types: `A,AAAA,MX,TXT,…` |
| `--domain-stats` | flag | off | Include per-domain stats |
| `--record-type-stats` | flag | off | Include per-record-type stats |
| `--error-breakdown` | flag | off | Include error type counts |
| `--include-charts` | flag | off | Embed charts in PDF / Excel |
| `--quiet` | flag | off | Suppress progress bars |
| `--doh` | flag | off | Use DNS-over-HTTPS |
| `--dot` | flag | off | Use DNS-over-TLS |
| `--doh-url` | TEXT | — | Custom DoH URLs (comma-sep, must match `--resolvers` count) |
| `--dnssec-validate` | flag | off | Validate DNSSEC signatures |

---

## net-benchmark dns top

| Option | Type | Default | Description |
|---|---|---|---|
| `--limit, -n` | INT | `10` | Number of resolvers to display |
| `--domains, -d` | PATH | built-in | Domain file |
| `--metric` | TEXT | `latency` | `latency` or `reliability` |
| `--doh` | flag | off | Use DoH |
| `--dot` | flag | off | Use DoT |
| `--output, -o` | PATH | — | Write results to file |

---

## net-benchmark dns compare

| Argument / Option | Description |
|---|---|
| `RESOLVERS...` | Two or more resolver names or IPs |
| `--domains, -d` | Domain file |
| `--record-types` | Record types |
| `--iterations, -i` | Number of passes |
| `--show-details` | Print per-domain breakdown |
| `--doh` | Use DoH |
| `--dot` | Use DoT |
| `--output, -o` | Write results to file |

---

## net-benchmark dns monitoring

| Option | Type | Default | Description |
|---|---|---|---|
| `--use-defaults` | flag | off | Use built-in resolvers and domains |
| `--resolvers, -r` | TEXT | — | Resolvers |
| `--domains, -d` | TEXT | — | Domains |
| `--interval` | INT | `60` | Poll interval in seconds |
| `--duration` | INT | `0` | Total duration in seconds (0 = run forever) |
| `--alert-latency` | FLOAT | — | Alert if mean latency exceeds this (ms) |
| `--alert-failure-rate` | FLOAT | — | Alert if failure rate exceeds this (%) |
| `--output` | PATH | — | Log file path |
| `--doh` | flag | off | Use DoH |
| `--dot` | flag | off | Use DoT |

---

## Utility commands

```bash
net-benchmark dns list-defaults
net-benchmark dns list-resolvers
net-benchmark dns list-resolvers --details
net-benchmark dns list-resolvers --category security
net-benchmark dns list-resolvers --format csv
net-benchmark dns list-resolvers --format json

net-benchmark dns list-domains
net-benchmark dns list-domains --category tech
net-benchmark dns list-domains --count 10
net-benchmark dns list-domains --format csv
net-benchmark dns list-domains --format json

net-benchmark dns list-categories

net-benchmark dns generate-config --output sample_config.yaml
net-benchmark dns generate-config --category privacy --output privacy.yaml
net-benchmark dns generate-config --category security --output security.yaml
net-benchmark dns generate-config --category family --output family.yaml
net-benchmark dns generate-config --category performance --output performance.yaml
```
