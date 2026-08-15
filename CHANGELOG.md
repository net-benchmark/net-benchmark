## v0.5.2 (2026-08-15)

### Feat

- **http_bench_cli**: add distributed orchestration and expose it on the cli
- **http_bench_load_test**: add emit_empty_intervals and close windows on elapsed time
- **http_bench_core**: merge load test results across parallel workers

### Fix

- **dns_core**: invoke progress_callback outside the lock and isolate it

## v0.5.1 (2026-07-18)

### Feat

- **http_bench**: add load test engine with throughput/sustained/ramp-up modes
- **core**: add DoH endpoints for seven public resolvers

### Fix

- **docs**: remove jinja2 from autodoc_mock_imports

## v0.5.0 (2026-05-16)

### Feat

- **http**: release 0.5.0 — http benchmarking suite

### Fix

- **cli**: fix mypy no-redef error in ssl_group import
- **cli**: resolve mypy incompatible type error in ssl_group assignment
- **cli**: make ssl_check import conditional to avoid ci failures

## v0.4.3 (2026-05-09)

### Fix

- **exporters**: correct pdf export package name to net-benchmark[pdf]

## v0.4.2 (2026-05-08)

## v0.4.1 (2026-05-08)

### Feat

- **init**: initial release of net-benchmark 0.4.0
