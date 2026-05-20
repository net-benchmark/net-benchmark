# Best Practices

## DNS modes

| Mode | Recommended flags | Purpose |
|---|---|---|
| **Quick Run** | `--iterations 1 --timeout 1 --retries 0 --warmup-fast` | Fast feedback, spot checks |
| **Balanced Run** | `--iterations 2 --use-cache --warmup-fast --timeout 2 --retries 1` | Daily runs |
| **Thorough Run** | `--iterations 3 --use-cache --warmup --timeout 5 --retries 2` | Provider evaluation |
| **Debug Mode** | `--iterations 1 --timeout 10 --retries 0 --quiet` | Diagnosing resolver issues |

## HTTP modes

| Mode | Recommended flags | Purpose |
|---|---|---|
| **Quick Run** | `--iterations 1 --warmup-fast` | Fast feedback |
| **Thorough Run** | `--iterations 5 --warmup --timeout 10 --retries 2` | Detailed benchmarking |
| **Debug Mode** | `--iterations 1 --timeout 30 --retries 0` | Diagnosing endpoint issues |
| **API Testing** | `--method POST --body '{}' --headers "Auth:token" --assert status=200` | Validate responses |

---

## Statistical accuracy

- Run `--iterations 3` or more for stable mean/median figures.
- Use `--warmup-fast` when testing DoH or DoT to absorb the TLS handshake overhead before timing starts.
- On mobile or hotspot connections, expect 2–5× higher variance than on wired Ethernet. Compare **median** latency, not average.

---

## Comparing encrypted vs plain DNS

Do **not** compare latency numbers from a plain UDP run directly with a DoH or
DoT run — they measure different things. Run separate benchmarks and compare
the two results side-by-side.

---

## DNSSEC tips

- Only ~33% of common domains are DNSSEC-signed.
- Add `--domains` containing known DNSSEC-signed domains when testing `--dnssec-validate` (e.g. `cloudflare.com`, `quad9.net`).
- `DNSSEC_FAILED` on unsigned domains is expected, not a resolver failure.

---

## Output management

- Use `--quiet` in CI / cron jobs to suppress progress bars.
- Use `--output /path/with/datestamp` in cron jobs for automatic log rotation.
- Use `--json` alongside `--formats csv,excel` for both human-readable and machine-readable outputs from a single run.

---

## Large-scale testing

- For 1000+ DNS queries, keep `--max-concurrent` at 50 or below to avoid triggering rate-limiting on public resolvers.
- Plain UDP DNS queries are visible to network observers. Use `--doh` or `--dot` when testing from untrusted networks.
