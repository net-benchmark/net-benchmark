# Docker

net-benchmark ships as a container image, built from the published PyPI
release — the image contains exactly what `pip install net-benchmark`
gives you, at the same version.

```
docker.io/joeovo/net-benchmark
ghcr.io/net-benchmark/net-benchmark
```

## Which tag do I want?

There are two variants of every release, and picking the wrong one is the
most common source of confusion:

| Tag | Contains | Use it when |
|---|---|---|
| `0.5.4`, `latest` | csv, excel, json export | CI pipelines, gating, most uses |
| `0.5.4-pdf`, `latest-pdf` | the above **plus** PDF reports | you need `--formats pdf` |

The default tag deliberately omits PDF support. PDF export pulls in
WeasyPrint and its Pango/Cairo/HarfBuzz system libraries, which most CI
users never need and shouldn't have to pull.

**If you ask the default tag for a PDF, you get this:**

```
[-] PDF export failed: PDF export requires 'weasyprint'.
    Install with: pip install net-benchmark[pdf]
```

In Docker, the fix is not `pip install` — it's switching to the `-pdf`
tag. Note also that `http benchmark`'s `--formats` **defaults to
`csv,excel,pdf`**, so you will see this message on the default tag even
if you never asked for a PDF. Pass `--formats` explicitly to avoid it:

```bash
# on the default tag, always name your formats
docker run --rm joeovo/net-benchmark:latest \
  http benchmark -t https://example.com --formats csv
```

Every example below does this.

## Install

```bash
docker pull joeovo/net-benchmark:latest       # or :latest-pdf
```

Pin the version rather than `latest` in anything automated:

```bash
docker pull joeovo/net-benchmark:0.5.5
```

## Basic use

The image's entrypoint is `net-benchmark` itself, so pass subcommands and
flags directly — no `net-benchmark` prefix, no shell wrapper:

```bash
docker run --rm joeovo/net-benchmark:latest --version
docker run --rm joeovo/net-benchmark:latest --help
docker run --rm joeovo/net-benchmark:latest http benchmark --help
```

A one-off benchmark, results to stdout only:

```bash
docker run --rm joeovo/net-benchmark:latest \
  http benchmark -t https://example.com -i 10 --formats csv
```

## Getting files in and out

The container's working directory is `/work`. Mount a host directory
there for target lists in and results out:

```bash
mkdir -p ci-data
echo "https://example.com" > ci-data/targets.txt

docker run --rm -v "$(pwd)/ci-data:/work" \
  joeovo/net-benchmark:latest \
  http benchmark \
  --targets /work/targets.txt \
  --formats csv \
  --output /work/results
```

Results land in `./ci-data/results/` on the host.

The image runs as a non-root user (uid 10001) and `/work` is writable by
any uid, so a bind mount works regardless of which user your CI runner
uses — you don't need `--user` unless your own policy requires it. If
your results directory comes out unwritable, that's a permission on the
*host* directory, not the image.

## PDF reports

Use the `-pdf` tag, and nothing else changes:

```bash
docker run --rm -v "$(pwd)/ci-data:/work" \
  joeovo/net-benchmark:latest-pdf \
  http benchmark \
  -t https://example.com -i 10 \
  --formats pdf \
  --output /work/results
```

## Using the exit code as a CI gate

This is the main reason to run net-benchmark in a pipeline. A failed
`--threshold` exits `1`; everything passing exits `0`:

```bash
docker run --rm joeovo/net-benchmark:latest \
  http benchmark -t https://example.com -i 10 \
  --formats csv \
  --threshold "success_rate>=99" \
  --threshold "p95_latency<1000"
echo "exit: $?"
```

**`--threshold` is the gate. `--assert` is not** — it annotates output but
never changes the exit code. And a run with no `--threshold` at all exits
`0` even if every request failed, because there was nothing to fail
against. Always pass at least one `--threshold` in CI.

See [Automation & CI](automation-ci.md) for full GitHub Actions, GitLab
CI, and Kubernetes examples.

## Notes

- **Both registries carry identical images.** Docker Hub is primary;
  `ghcr.io` is a mirror. Use whichever your infrastructure prefers.
- **`--rm` is recommended** in all examples so containers don't
  accumulate; net-benchmark runs to completion and exits, it isn't a
  long-running service.
- **Distributed load tests work in-container.** `http load-test --workers N`
  (a net-benchmark flag) spawns real worker processes inside the
  container. If you raise the worker count, give the container more CPU
  with Docker's own `--cpus` flag on `docker run` — for example `docker
  run --cpus 4 ...` — not a net-benchmark option.
- **Base image CVEs** are inherited from `python:3.14-slim` (Debian).
  The image is rebuilt on each release; see the repository's Dependabot
  configuration for base-image digest updates between releases.
