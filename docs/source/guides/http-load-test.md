# HTTP Load Testing

`net-benchmark http load-test` runs sustained traffic against one or more
HTTP targets using three load-shaping strategies. Unlike `benchmark`
(fixed iteration count), load-test runs for a duration and reports
achieved throughput, latency percentiles, and connection-level behavior.

Since **0.5.2** the load can also be generated from several parallel workers —
separate processes on one machine, or separate machines entirely — with a
synchronised start and a statistically correct merge.

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

## Distributed load generation (0.5.2)

A single Python process — one GIL, one event loop, one connection pool — is
often the bottleneck long before the target is. `--workers` generates the load
from N **separate processes**, started against a shared wall-clock barrier and
merged at the end.

```bash
# Baseline: one process.
net-benchmark http load-test -t https://api.example.com/health \
  --mode throughput --duration 20 --max-concurrency 50

# Four processes. --max-concurrency is PER WORKER: 200 in flight overall.
net-benchmark http load-test -t https://api.example.com/health \
  --mode throughput --duration 20 --max-concurrency 50 --workers 4
```

Expect a ~5s pause before requests begin: workers start on a shared barrier,
and the lead time is sized so every spawned interpreter has finished importing
before the run starts.

Reading the comparison — three outcomes, all valid results:

- RPS scales with worker count and `blocked` stays flat → the single process
  was the ceiling, and you removed it.
- RPS barely moves while `waiting` climbs → the target is saturated. More
  workers cannot help.
- RPS barely moves while `blocked` climbs → a machine limit (NIC, CPU,
  ephemeral ports). Separate processes escape the GIL and the single event
  loop; they do not add a second network card.

`Avg blocked` is time waiting for a connection slot (**your** side); `Avg
waiting` is time waiting for the server (**theirs**). Blocked rising while
waiting stays flat means you are measuring your own generator.

### Rate splitting

`--rps` is the **total** offered rate and is divided across workers:

```bash
# 4 workers pace 100 RPS each; the merged summary reports 400.
net-benchmark http load-test -t https://api.example.com/cart \
  --mode sustained --rps 400 --duration 30 --workers 4 --max-backlog 20
```

`--max-backlog` is per worker. Without it a slow target causes requests to pile
up, and the latency you measure includes time spent in your own queue — a
number about your tool, not the server. Dropping makes overload visible as
`dropped_rate`.

### Target topologies

With several targets, `--target-distribution` decides what `--workers`
multiplies — and changes what `--rps` means:

| Value | Behaviour | `--rps` is | Use when |
|---|---|---|---|
| `replicate` (default) | Every worker runs every target | run **total**, split | Saturating one origin |
| `shard` | Targets dealt round-robin, one worker each | **per target**, not divided | Measuring more targets in parallel |

Sharding with more workers than targets leaves surplus workers unstarted, and
the CLI says so — silently falling back to `replicate` would multiply the load
you asked to keep constant.

## Running across several machines (0.5.2)

Multi-process generation removes the GIL and the single event loop. It does not
remove the NIC, or the fact that all traffic originates from one place. For
traffic genuinely arriving from several regions, run a node per region against
a shared barrier and merge.

```bash
# 1. Pick the barrier — prints the epoch to paste onto every node.
net-benchmark http load-test -t https://example.com \
  --duration 60 --start-delay 120 --quiet
# [i]   Start barrier: 1754320000.000 (epoch seconds, UTC)

# 2. Every node: IDENTICAL --start-at, its own labels and rate share.
net-benchmark http load-test -t https://example.com \
  --mode sustained --rps 250 --duration 60 \
  --start-at 1754320000.000 --warmup 10 \
  --worker-id hel1 --region eu-north \
  --emit-summary hel1.json --formats ''

# 3. Collect and merge.
net-benchmark http merge-load-test ./nodes/*.json \
  -o ./merged --threshold 'p95_latency<500'
```

```text
| Workers merged:   2  [hel1, ash]                  |
| Total requests:   29918                           |
| Successful:       29918 (100.00%)                 |
| Achieved RPS:     498.3                           |
| P95 latency:      184.2 ms (from merged histogram)|
| Worst start skew: 85 ms                           |
```

Each node gets its own share of the rate; automatic splitting applies only to
the local `--workers` path. Percentiles are recomputed from the merged
histogram — averaging several nodes' P95 values gives the P95 of neither.

`--warmup` opens connections *before* the barrier: otherwise a synchronised
start is a synchronised cold start and the opening seconds measure TLS
handshakes. Where clock offset has been measured, the merge refuses beyond
50 ms of skew — nodes agreeing on an epoch only proves they were *told* the
same value. Workers that will be merged must also agree on
`--interval-bucket`.

## Pass/fail thresholds

Parsed *before* the run starts — including the metric name, with suggestions —
so a typo costs a second rather than a full load test. Any failure exits
non-zero.

```bash
net-benchmark http load-test \
  -t https://staging.example.com/api/health \
  --mode sustained --rps 200 --duration 60 \
  --workers 4 --max-backlog 50 --warmup 10 \
  --expected-status 200,404 \
  --threshold 'p95_latency<400' \
  --threshold 'success_rate>99.5' \
  --threshold 'dropped_rate<1'
```

Percentiles survive a merge. Dispersion and phase-timing metrics do not, and
are **rejected** rather than silently passing:

```bash
net-benchmark http load-test -t https://api.example.com \
  --duration 10 --workers 2 --threshold 'p95_waiting_ms<500'
# fails: p95_waiting_ms cannot be computed for a merged run
```

No arithmetic recovers a standard deviation or a phase percentile from
per-worker summaries, so a merged summary carries `0.0` for them — which is
also the "no samples" value. Publishing them would let that threshold pass on a
technicality and turn a CI gate green for the wrong reason. Affected:
`std_latency`, `jitter`, `consistency_score`, `p95_ttfb_ms`, `p95_duration_ms`,
`p95_blocked_ms`, `p95_waiting_ms`. They stay exact at `--workers 1` and per
worker in `*_workers.csv`.

## Limits and gotchas

- **Concurrency flags are per worker.** `--workers 4 --max-concurrency 50` is
  200 in flight; so are `--max-backlog` and `--max-total-rps`. `--rps` is the
  exception under `replicate`.
- **Raw per-request rows do not survive `--workers > 1`** or a cross-machine
  merge — `*_raw.csv` and the per-target Excel sheets are empty regardless of
  `--no-retain-results`. Every statistic, interval and histogram survives.
- **`--live` is single-worker only.** The callback cannot be sent into a
  spawned process; above one worker the CLI warns rather than silently
  printing nothing.
- **A dead worker means load that was never offered.** Failures are reported
  per target rather than folded into the merged summary.

## Output formats

| Format  | Contents                                                     |
|---------|----------------------------------------------------------------|
| `csv`   | Raw results, summary, per-worker summary, per-interval timeline, error breakdown, latency histogram |
| `excel` | Comparison sheet + per-target raw/timeline sheets, optional charts |
| `pdf`   | Report with charts (requires `pip install net-benchmark[pdf]`) |
| `json`  | Full structured bundle, all targets                            |

> **Note:** PDF export fails soft — if `weasyprint` isn't installed, the
> run still completes and other formats are still written; check the CLI
> output for `PDF export failed`.
