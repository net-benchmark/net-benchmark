# syntax=docker/dockerfile:1
#
# net-benchmark container image.
#
# Deliberately installs from the published PyPI wheel, not repo source —
# this image is built AFTER a version is live on PyPI (see release process
# in RELEASE.md), as a smoke test of the actual public artifact, not a
# separate build path that could drift from what `pip install net-benchmark`
# gives everyone else.
#
# Two build targets from one file:
#   docker build --target final-lean -t net-benchmark:0.5.3     .
#   docker build --target final-pdf  -t net-benchmark:0.5.3-pdf .
#
# Base image pinned by digest rather than tag, for reproducible builds.
# This digest rotates whenever the upstream image is rebuilt (Debian
# security patches land often), so it will go stale — re-verify before
# any deliberate base-image bump, and update both FROM lines below:
#   docker buildx imagetools inspect python:3.14-slim
# Pinned to the multi-arch index digest, not a single-platform manifest
# digest, so both build-amd64 and build-arm64 in docker.yml resolve to
# the correct platform automatically from the one reference.
FROM python:3.14-slim@sha256:cad9a2c871761c413caa6fdd6441c783451e740a48aaeba60ae62a8b53525ef6 AS base

# ---------------------------------------------------------------------------
# Builders — one per extras profile. Both install from PyPI, not source.
# ---------------------------------------------------------------------------

FROM base AS builder-lean
# No default: the version must be supplied explicitly, so a local build can
# never silently produce an image tagged one version but containing another.
# CI passes it from the git tag; locally use `make docker-build`, which reads
# it from src/net_benchmark/__init__.py (the same source of truth commitizen
# bumps).
ARG NET_BENCHMARK_VERSION
RUN test -n "$NET_BENCHMARK_VERSION" || (echo "NET_BENCHMARK_VERSION build-arg is required" >&2; exit 1)
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --upgrade pip \
    && pip install --no-compile "net-benchmark==${NET_BENCHMARK_VERSION}"
# Strip packaging bloat that shouldn't have shipped in the wheel in the
# first place: MANIFEST.in bundles dns_benchmark's doc screenshots into
# every install, and its tests-exclude list was never extended to
# http_bench when that module landed. ~6.3MB of the ~7MB 0.5.3 wheel is
# these two things. Real fix belongs in MANIFEST.in for a future
# release — this just keeps the image honest in the meantime.
RUN find /opt/venv -type d -path "*/dns_benchmark/docs/screenshots" -exec rm -rf {} + ; \
    find /opt/venv -type d -path "*/net_benchmark/*/tests" -exec rm -rf {} + ; \
    find /opt/venv -type d -name "__pycache__" -exec rm -rf {} + ; \
    find /opt/venv -type f -name "*.pyc" -delete
# pip and setuptools aren't needed at runtime, and both carry known CVEs
# (setuptools itself, plus msgpack vendored inside pip) that show up in
# image scans despite being build-time-only tools. Nothing in net_benchmark
# imports pkg_resources or setuptools — verified with a full benchmark run
# (csv + excel export) after removing both.
RUN /opt/venv/bin/pip uninstall -y pip setuptools 2>/dev/null || true

FROM base AS builder-pdf
ARG NET_BENCHMARK_VERSION
RUN test -n "$NET_BENCHMARK_VERSION" || (echo "NET_BENCHMARK_VERSION build-arg is required" >&2; exit 1)
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --upgrade pip \
    && pip install --no-compile "net-benchmark[pdf]==${NET_BENCHMARK_VERSION}"
RUN find /opt/venv -type d -path "*/dns_benchmark/docs/screenshots" -exec rm -rf {} + ; \
    find /opt/venv -type d -path "*/net_benchmark/*/tests" -exec rm -rf {} + ; \
    find /opt/venv -type d -name "__pycache__" -exec rm -rf {} + ; \
    find /opt/venv -type f -name "*.pyc" -delete
RUN /opt/venv/bin/pip uninstall -y pip setuptools 2>/dev/null || true

# ---------------------------------------------------------------------------
# final-lean — no weasyprint, no pango/cairo/harfbuzz. This is the tag most
# CI users want: every runtime dependency has a manylinux wheel on both
# x86_64 and aarch64 as of the 0.5.3 floor-bump audit, so no compiler is
# needed anywhere in this stage.
# ---------------------------------------------------------------------------
FROM base AS final-lean

LABEL org.opencontainers.image.source="https://github.com/net-benchmark/net-benchmark" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.title="net-benchmark" \
      org.opencontainers.image.description="dns, http, and ssl network benchmarking from a single CLI"

COPY --from=builder-lean /opt/venv /opt/venv

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    MPLCONFIGDIR=/tmp \
    HOME=/tmp

# Non-root by default. /work is world-writable (not group-0 tricks) because
# the realistic failure mode is a CI runner bind-mounting a host directory
# with a UID this image has never seen (GitHub-hosted runners use uid 1001,
# not our 10001) — there's no way to know that UID at build time, so the
# directory just has to be writable by anyone. MPLCONFIGDIR/HOME=/tmp gets
# the same property for free since /tmp is 1777 in the base image already.
RUN groupadd --gid 10001 appuser \
    && useradd --uid 10001 --gid appuser --no-create-home --shell /usr/sbin/nologin appuser \
    && mkdir -p /work \
    && chmod 1777 /work

WORKDIR /work
USER 10001:10001

ENTRYPOINT ["net-benchmark"]
CMD ["--help"]

# ---------------------------------------------------------------------------
# final-pdf — adds weasyprint's runtime shared libraries. Not built from
# final-lean (that would mean copying the lean venv over just to overwrite
# it, an extra layer for nothing) — starts fresh from base with its own
# venv from builder-pdf, then layers the apt packages weasyprint needs at
# import time, not just build time.
# ---------------------------------------------------------------------------
FROM base AS final-pdf

LABEL org.opencontainers.image.source="https://github.com/net-benchmark/net-benchmark" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.title="net-benchmark" \
      org.opencontainers.image.description="dns, http, and ssl network benchmarking from a single CLI, with PDF report export"

# WeasyPrint's runtime shared libraries. This list is the one proven working
# in production rather than a minimal guess — weasyprint fails at import
# time, not build time, when any of these are missing, so erring toward
# complete is the right trade.
#
# Two notes if you ever change the base image:
#   - -dev packages are deliberately NOT used here (libjpeg-dev,
#     libffi-dev, libopenjp2-7-dev). Those ship headers for compiling
#     against; a runtime-only image needs the shared library instead.
#   - python:3.14-slim is Debian trixie. Package names below are trixie's;
#     a bookworm-era list would say `mime-support` (removed in Debian 12 —
#     it's `media-types` now) and may differ on libtiff/libjpeg soname
#     suffixes. If a build fails on an unknown package, that's why.
RUN apt-get update \
    && apt-get install --assume-yes --no-install-recommends \
        libcairo2 \
        libpango-1.0-0 \
        libpangocairo-1.0-0 \
        libpangoft2-1.0-0 \
        libgdk-pixbuf-2.0-0 \
        libharfbuzz0b \
        libharfbuzz-subset0 \
        libjpeg62-turbo \
        libopenjp2-7 \
        libtiff6 \
        libwebp7 \
        libffi8 \
        shared-mime-info \
        media-types \
        fonts-dejavu-core \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder-pdf /opt/venv /opt/venv

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    MPLCONFIGDIR=/tmp \
    HOME=/tmp

RUN groupadd --gid 10001 appuser \
    && useradd --uid 10001 --gid appuser --no-create-home --shell /usr/sbin/nologin appuser \
    && mkdir -p /work \
    && chmod 1777 /work

WORKDIR /work
USER 10001:10001

ENTRYPOINT ["net-benchmark"]
CMD ["--help"]
