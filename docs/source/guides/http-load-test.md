# HTTP Load Testing

`net-benchmark http load-test` runs sustained traffic against one or more
HTTP targets using three load-shaping strategies. Unlike `benchmark`
(fixed iteration count), load-test runs for a duration and reports
achieved throughput, latency percentiles, and connection-level behavior.

## Modes

| Mode         | What it does                                      | Use case                          |
|--------------|----------------------------------------------------|------------------------------------|
| `throughput` | Saturates the target up to `--max-concurrency`     | Find the ceiling                   |
| `sustained`  | Holds a fixed `--rps` for `--duration`             | SLA / capacity validation          |
| `ramp-up`    | Steps concurrency up, then holds at peak           | Find the breaking point gradually  |

## Examples

**Throughput — how fast can this endpoint go?**

```bash
net-benchmark http load-test \
  -t https://api.staging.example.com/health \
  --mode throughput \
  --duration 30 \
  --max-concurrency 300 \
  --formats csv,excel \
  --include-charts
```

**Sustained — validate a fixed capacity target**

```bash
net-benchmark http load-test \
  -t https://checkout.example.com/api/cart \
  --mode sustained \
  --rps 150 \
  --duration 300 \
  --enable-connection-reuse \
  --formats csv,excel,json
```

`--rps` is required in sustained mode — the CLI fails fast with a clear
message if it's missing.

**Ramp-up — find where things start to break**

```bash
net-benchmark http load-test \
  -t https://api.example.com/search \
  --mode ramp-up \
  --start-concurrency 5 \
  --ramp-concurrency 500 \
  --ramp-duration 120 \
  --hold-duration 60 \
  --max-total-rps 1000 \
  --formats csv,excel,pdf
```

`--max-total-rps` is a *safety ceiling*, not a target rate — use
`sustained` if you want a fixed rate. It exists because against very
fast targets (localhost, mesh sidecars) nothing else bounds request
rate. It defaults to `ramp-concurrency * 50`, which is usually generous
enough to never trigger against real network-bound services.

**Comparing multiple targets (e.g. canary vs. stable)**

```bash
net-benchmark http load-test \
  -t https://api-v1.example.com,https://api-v2.example.com \
  --mode sustained --rps 100 --duration 120 \
  --formats excel --include-charts
```

Each target runs concurrently in its own connection pool. The Excel
export produces a comparison sheet plus per-target raw-request and
timeline sheets.

**Protocol/transport diagnostics under load**

```bash
net-benchmark http load-test \
  -t https://cdn.example.com/asset.js \
  --mode throughput --duration 60 --max-concurrency 200 \
  --enable-connection-reuse --enable-tls-resumption --enable-push-detection \
  --formats json
```

These detection features are opt-in — they add per-request bookkeeping,
so only turn them on when you're actually investigating connection
reuse / TLS resumption / HTTP/2 push behavior.

## Output formats

| Format  | Contents                                                     |
|---------|----------------------------------------------------------------|
| `csv`   | Raw results, summary, per-second timeline, error breakdown    |
| `excel` | Comparison sheet + per-target raw/timeline sheets, optional charts |
| `pdf`   | Report with charts (requires `pip install net-benchmark[pdf]`) |
| `json`  | Full structured bundle, all targets                            |

> **Note:** PDF export fails soft — if `weasyprint` isn't installed, the
> run still completes and other formats are still written; check the CLI
> output for `PDF export failed`.
