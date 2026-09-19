# Roadmap

The roadmap lives in
**[GitHub Discussion #45 — Roadmap: DNS / HTTP / SSL (central thread)](https://github.com/net-benchmark/net-benchmark/discussions/45)**.

That thread is the single source of truth. It carries the release table,
per-module item lists with status, the dependency policy (banned /
permitted / implemented), and the open decisions (D1 TLS engine, D2
baseline store, D3 dependency register) — with the reasoning behind each,
not just the outcome.

---

## Why this file no longer holds the roadmap

It used to. It held a shorter version of the same tables, and it was
almost always stale: the discussion page is updated continuously as work
lands and priorities move, while this file only changed when someone
remembered to open a PR for it. Two copies of the same information, one
of which is reliably behind, is worse than one copy — a reader who lands
here first gets the outdated answer and has no way to know it.

So the detailed roadmap moved to the discussion page, where the
discussion about it already happens. This file points there.

## Where to look

| You want | Go to |
|---|---|
| What's planned, in what order, and why | [Discussion #45](https://github.com/net-benchmark/net-benchmark/discussions/45) |
| What has already shipped | [`CHANGELOG.md`](./CHANGELOG.md) |
| Why a dependency was accepted or rejected | Discussion #45, section **D3 — Dependency register** |
| Why a design decision was made | Discussion #45, section **Open decisions**, or the relevant PR |