# Automation & CI

## GitHub Actions — DNS

```yaml
# .github/workflows/dns-check.yml
name: DNS Performance Check

on:
  push:
    branches: [main]
  schedule:
    - cron: "0 6 * * *"   # Daily at 06:00 UTC

jobs:
  dns-benchmark:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install net-benchmark
        run: pip install net-benchmark

      - name: Run DNS benchmark
        run: |
          net-benchmark dns benchmark \
            --resolvers "1.1.1.1,8.8.8.8" \
            --domains "api.service.com,database.service.com" \
            --formats csv \
            --quiet

      - name: Upload results
        uses: actions/upload-artifact@v4
        with:
          name: dns-benchmark-results
          path: benchmark_results/
```

## GitHub Actions — HTTP

```yaml
# .github/workflows/http-check.yml
name: HTTP Endpoint Health Check

on:
  push:
    branches: [main]

jobs:
  http-benchmark:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install net-benchmark
        run: pip install net-benchmark

      - name: HTTP endpoint health check
        run: |
          net-benchmark http benchmark \
            --targets "https://api.prod.example.com/health,https://web.prod.example.com" \
            --assert status=200 \
            --assert max_latency=1000 \
            --formats csv \
            --quiet

      - name: Upload results
        uses: actions/upload-artifact@v4
        with:
          name: http-benchmark-results
          path: benchmark_results/
```

---

## Cron jobs — DNS

```bash
# Daily at 02:00
0 2 * * * /usr/local/bin/net-benchmark dns benchmark \
  --use-defaults \
  --formats csv \
  --quiet \
  --output /var/log/net_benchmark/daily_$(date +\%Y\%m\%d)

# Every 6 hours
0 */6 * * * /usr/local/bin/net-benchmark dns benchmark \
  --use-defaults \
  --formats csv \
  --quiet \
  --output /var/log/net_benchmark/$(date +\%Y\%m\%d_\%H)

# Monthly management report (1st of the month)
0 0 1 * * /usr/local/bin/net-benchmark dns benchmark \
  --use-defaults \
  --formats excel,pdf \
  --domain-stats \
  --error-breakdown \
  --output /var/reports/dns/$(date +\%Y\%m)
```

## Cron jobs — HTTP

```bash
# Hourly HTTP health check
0 * * * * /usr/local/bin/net-benchmark http benchmark \
  --targets targets.txt \
  --assert status=200 --assert max_latency=1000 \
  --formats csv --quiet \
  --output /var/reports/http/$(date +\%Y\%m\%d_\%H)
```

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success — and every configured `--threshold` passed |
| `1` | Runtime error, or a `--threshold` failed |
| `2` | Invalid arguments |

**`--assert` does not affect the exit code.** It's a per-target reporting
annotation — it shows up in the output, but a failed assertion does not
make the process exit non-zero. `--threshold` is the actual CI gate:

```bash
net-benchmark http benchmark \
  --targets "https://api.myapp.com/health" \
  --threshold "success_rate>=99" \
  --threshold "p95_latency<1000" \
  --quiet \
  --formats csv
```

A run against a target that never responds still exits `0` if no
`--threshold` is set — there's nothing to fail. Always pair a CI
invocation with at least one `--threshold`; treat `--assert` as
informational only.

---

## Running in Docker

net-benchmark ships as a container image, built from the published PyPI
release (so the image always matches what `pip install net-benchmark`
gives everyone else):

```bash
docker pull joeovo/net-benchmark:latest
```

A `-pdf` variant carries weasyprint's runtime libraries for `--formats
pdf`; the default tag doesn't, to stay small for pipelines that only need
csv/excel:

```bash
docker pull joeovo/net-benchmark:latest-pdf
```

Mount a directory for target lists in and results out, and use the exit
code as the gate — this is the whole point of running it in a pipeline:

```bash
docker run --rm \
  -v "$(pwd)/ci-data:/work" \
  joeovo/net-benchmark:latest \
  http benchmark \
  --targets /work/targets.txt \
  --threshold "success_rate>=99" \
  --threshold "p95_latency<1000" \
  --formats csv \
  --output /work/results \
  --quiet
echo "exit code: $?"
```

The image runs as a non-root user by default; `/work` is world-writable
so a bind mount works regardless of which UID your CI runner uses —
you don't need `--user` unless your own security policy requires it.

### GitHub Actions

```yaml
- name: Run benchmark and gate on thresholds
  run: |
    docker run --rm \
      -v "${{ github.workspace }}/ci-data:/work" \
      joeovo/net-benchmark:latest \
      http benchmark \
      --targets /work/targets.txt \
      --threshold "success_rate>=99" \
      --threshold "p95_latency<1000" \
      --formats csv \
      --output /work/results \
      --quiet
```

The step fails the job automatically if any threshold fails — no `|| exit
1` needed, `docker run` already surfaces the container's real exit code.

### GitLab CI

```yaml
benchmark:
  image: joeovo/net-benchmark:latest
  script:
    - net-benchmark http benchmark
        --targets targets.txt
        --threshold "success_rate>=99"
        --threshold "p95_latency<1000"
        --formats csv
        --output results
        --quiet
```

No `docker run` wrapper needed here — GitLab CI runs the image directly
as the job's own container, so the job fails exactly when net-benchmark
does.

### Kubernetes

net-benchmark isn't a server — there's no Deployment or Service here, just
a `Job` for one-shot gated runs and a `CronJob` for recurring ones,
manifests at `k8s/job.yaml` and `k8s/cronjob.yaml` in the repo. Both run
as non-root (uid 10001, matching the image's default) with a read-only
root filesystem; `/tmp` and `/work` are explicit `emptyDir` mounts so that
stays true without the container needing to write anywhere else.

Use the Job as an in-cluster deploy gate:

```bash
kubectl apply -f k8s/job.yaml
kubectl wait --for=condition=complete --timeout=300s job/net-benchmark-run
```

A failed `--threshold` makes the container exit non-zero, which
Kubernetes surfaces as the Job failing — `kubectl wait` above returns
non-zero too, so it composes directly into a pipeline the same way the
Docker exit code does.

The CronJob example intentionally has no `--threshold` — it's for
ongoing monitoring, not a pass/fail gate, so unlike the Job it won't fail
loudly on a bad run by default. Add `--threshold` flags to it the same
way as the Job if you want scheduled runs to also alert on regression
rather than just log to `/work/results`, which is `emptyDir` and gone
once the pod is cleaned up — mount a PVC there instead, or add a step
that ships results externally, if you want history.

