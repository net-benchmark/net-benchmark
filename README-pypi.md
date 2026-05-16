# net-benchmark

fast, extensible network benchmarking — dns, http, and ssl from a single cli.

[![PyPI version](https://badge.fury.io/py/net-benchmark.svg)](https://pypi.org/project/net-benchmark)
[![Python](https://img.shields.io/pypi/pyversions/net-benchmark.svg)](https://pypi.org/project/net-benchmark)
![License](https://img.shields.io/badge/license-MIT-yellow.svg)

[![CI](https://github.com/net-benchmark/net-benchmark/actions/workflows/ci.yml/badge.svg)](https://github.com/net-benchmark/net-benchmark/actions)
[![Downloads](https://pepy.tech/badge/net-benchmark)](https://pepy.tech/project/net-benchmark)

```bash
pip install net-benchmark
pip install net-benchmark[pdf]   # with pdf export
```

> successor to [dns-benchmark-tool](https://github.com/net-benchmark/dns-benchmark-tool) — fully backward compatible.
> `dns-benchmark` command still works as an alias.

---

## tools

<details>
<summary><strong>dns benchmark</strong> — resolver performance, dnssec, doh/dot</summary>

```bash
net-benchmark dns benchmark --use-defaults
net-benchmark dns benchmark --use-defaults --doh
net-benchmark dns benchmark --use-defaults --dot --dnssec-validate
net-benchmark dns compare Cloudflare Google Quad9 --dnssec-validate
net-benchmark dns monitoring --use-defaults --interval 30
```

| flag | description | default |
|---|---|---|
| `--use-defaults` | built-in resolvers and sample domains | — |
| `--resolvers` | name, ip, or file | — |
| `--domains` | comma-separated or file | — |
| `--iterations` | queries per resolver | `1` |
| `--doh` | dns-over-https | `false` |
| `--doh-url` | comma-separated urls, one per resolver | — |
| `--dot` | dns-over-tls | `false` |
| `--dnssec-validate` | fail if ad flag absent | `false` |
| `--formats` | csv, excel, pdf, json | `csv,excel,pdf` |

full documentation: [github.com/net-benchmark/net-benchmark](https://github.com/net-benchmark/net-benchmark#dns-benchmark)

</details>

<details>
<summary><strong>http benchmark</strong> — latency, ttfb, security headers, tls certs</summary>

```bash
net-benchmark http benchmark --use-defaults
net-benchmark http benchmark --use-defaults --iterations 5
net-benchmark http benchmark --targets "https://api.example.com" --method POST --body '{}'
net-benchmark http compare api.example.com api2.example.com --iterations 3
net-benchmark http top --use-defaults --limit 5
net-benchmark http monitoring --use-defaults --interval 30
```

| flag | description | default |
|---|---|---|
| `--use-defaults` | built-in target urls | — |
| `--targets` | comma-separated urls or file | — |
| `--method` | http verb (get, post, etc.) | `get` |
| `--headers` | `"key:value,key2:value2"` | — |
| `--body` | inline request body (e.g. json) | — |
| `--body-file` | path to body file | — |
| `--auth` | `basic:user:pass` or `bearer:token` | — |
| `--cert` / `--cert-key` | mtls client certificate | — |
| `--proxy` | proxy url | — |
| `--assert` | repeatable: `status=200`, `body_contains=ok`, `max_latency=500`, etc. | — |
| `--iterations` | requests per target | `1` |
| `--no-http2` | force http/1.1 | `false` |
| `--no-verify-ssl` | skip tls verification | `false` |
| `--formats` | csv, excel, pdf, json | `csv,excel,pdf` |

full documentation: [github.com/net-benchmark/net-benchmark](https://github.com/net-benchmark/net-benchmark#http-benchmark)

</details>

<details>
<summary><strong>ssl check</strong> — certificate expiry and chain validation <em>(coming 0.6.0)</em></summary>

```bash
net-benchmark ssl check --hosts "example.com,api.example.com"
```

full documentation: [github.com/net-benchmark/net-benchmark](https://github.com/net-benchmark/net-benchmark#ssl-check)

</details>

---

## export formats

| format | flag | notes |
|---|---|---|
| csv | `--formats csv` | raw results + summary |
| excel | `--formats excel` | charts, dnssec sheet, colour coding |
| pdf | `--formats pdf` | requires `pip install net-benchmark[pdf]` |
| json | `--formats json` | full payload including protocol stats |

---

## links

- repository: [github.com/net-benchmark/net-benchmark](https://github.com/net-benchmark/net-benchmark)
- issues: [github.com/net-benchmark/net-benchmark/issues](https://github.com/net-benchmark/net-benchmark/issues)
- changelog: [github.com/net-benchmark/net-benchmark/blob/main/CHANGELOG.md](https://github.com/net-benchmark/net-benchmark/blob/main/CHANGELOG.md)
- powered by [buildtools.net](https://buildtools.net)

---

## license

mit © [frankovo](https://github.com/frankovo)
