# HTTP CLI Reference

## Entry point

```
net-benchmark http [OPTIONS] COMMAND [ARGS]...
```

## Commands

| Command | Description |
|---|---|
| `benchmark` | Full HTTP benchmark with exports |
| `top` | Rank all targets by speed |
| `compare` | Side-by-side target comparison |
| `monitoring` | Continuous monitoring with alerts |

---

## net-benchmark http benchmark

| Option | Type | Default | Description |
|---|---|---|---|
| `--use-defaults` | flag | off | Use built-in targets |
| `--targets` | TEXT | — | Comma-sep URLs or path to `.txt` file |
| `--method` | TEXT | `GET` | HTTP method: `GET`, `POST`, `PUT`, `DELETE`, `HEAD`, `PATCH` |
| `--body` | TEXT | — | Request body string |
| `--body-file` | PATH | — | Request body from file |
| `--params` | TEXT | — | Query parameters: `key=value,key2=value2` |
| `--headers` | TEXT | — | Custom headers: `Name:Value` (repeatable) |
| `--auth` | TEXT | — | `basic:user:pass`, `bearer:token` |
| `--cert` | PATH | — | Client certificate (mTLS) |
| `--cert-key` | PATH | — | Client certificate key (mTLS) |
| `--proxy` | TEXT | — | Proxy URL |
| `--sni` | TEXT | — | SNI override |
| `--local-address` | TEXT | — | Local interface to bind |
| `--user-agent` | TEXT | — | Custom User-Agent string |
| `--cookie` | TEXT | — | Cookie `name=value` (repeatable) |
| `--inject-request-id` | flag | off | Add `X-Request-ID` header |
| `--no-http2` | flag | off | Force HTTP/1.1 |
| `--no-verify-ssl` | flag | off | Skip TLS verification |
| `--connect-timeout` | FLOAT | — | TCP connect timeout (seconds) |
| `--read-timeout` | FLOAT | — | Read timeout (seconds) |
| `--write-timeout` | FLOAT | — | Write timeout (seconds) |
| `--timeout` | FLOAT | `10.0` | Overall timeout (seconds) |
| `--retries` | INT | `1` | Retry count on failure |
| `--max-concurrent` | INT | `50` | Max concurrent async requests |
| `--iterations, -i` | INT | `1` | Number of benchmark passes |
| `--warmup` | flag | off | Full warmup before timing |
| `--warmup-fast` | flag | off | Lightweight warmup (HEAD per target) |
| `--assert` | TEXT | — | Assertion (repeatable, see below) |
| `--formats` | TEXT | `csv` | `csv`, `excel`, `pdf` (comma-separated) |
| `--json` | flag | off | Write structured JSON bundle |
| `--include-charts` | flag | off | Embed charts in PDF / Excel |
| `--output, -o` | PATH | `./benchmark_results` | Output directory |
| `--quiet` | flag | off | Suppress progress bars |

### Assertions

| Assert | Example |
|---|---|
| Status code | `--assert status=200` |
| Body contains | `--assert body_contains=success` |
| Header exists | `--assert header_exists=X-Cache` |
| Header value | `--assert header_value=X-Cache=HIT` |
| Max latency (ms) | `--assert max_latency=500` |
| Content-Type | `--assert content_type=application/json` |
| Response size min | `--assert response_size_min=100` |
| Response size max | `--assert response_size_max=10000` |

---

## net-benchmark http top

| Option | Type | Default | Description |
|---|---|---|---|
| `--use-defaults` | flag | off | Use built-in targets |
| `--targets` | TEXT | — | Targets |
| `--limit, -n` | INT | `10` | Number of targets to display |
| `--metric` | TEXT | `latency` | `latency`, `ttfb`, or `success` |
| `--iterations, -i` | INT | `1` | Number of passes |

---

## net-benchmark http compare

| Argument / Option | Description |
|---|---|
| `TARGETS...` | Two or more URLs (auto-scheme: `https://` added if missing) |
| `--auth` | Authentication |
| `--headers` | Custom headers |
| `--iterations, -i` | Number of passes |
| `--show-details` | Print per-iteration breakdown |
| `--output, -o` | Write results to file |

---

## net-benchmark http monitoring

| Option | Type | Default | Description |
|---|---|---|---|
| `--use-defaults` | flag | off | Use built-in targets |
| `--targets` | TEXT | — | Targets |
| `--interval` | INT | `60` | Poll interval in seconds |
| `--duration` | INT | `0` | Total duration in seconds (0 = run forever) |
| `--alert-latency` | FLOAT | — | Alert if mean latency exceeds this (ms) |
| `--alert-failure-rate` | FLOAT | — | Alert if failure rate exceeds this (%) |
| `--proxy` | TEXT | — | Proxy URL |
| `--output` | PATH | — | Log file path |
