# SSL CLI Reference

## Entry point

```
net-benchmark ssl check [OPTIONS]
```

One command. Every capability below is a flag on it, not a subcommand —
each adds fields to the same per-target result and the same export
formats, so a single scan can combine any number of them.

See the [SSL Check guide](../guides/ssl-check.md) for narrative
walkthroughs of each area; this page is the flat reference.

---

## Target selection

| Option | Type | Default | Description |
|---|---|---|---|
| `--targets, -t` | TEXT | — | Comma-separated hosts (`host`, `host:port`, or a URL) or a file, one target per line |
| `--use-defaults` | flag | off | Use built-in default targets |
| `--ports` | TEXT | `443` | Ports applied to targets with no explicit port |
| `--all-ports` | flag | off | Scan 443, 8443, 465, 993, 995, 587, 636 for targets with no explicit port. Overridden by an explicit `--ports` |
| `--resolve` | TEXT | — | Pin a target to an IP without a DNS lookup: `host:port:ip` (repeatable, IPv6 supported) |
| `--starttls` | TEXT | `auto` | Force the STARTTLS protocol for every target: `auto`, `none`, `smtp`, `imap`, `pop3`, `ldap`, `ftp` |

---

## Transport and sampling

| Option | Type | Default | Description |
|---|---|---|---|
| `--connect-timeout` | FLOAT | `10.0` | TCP connect timeout (s) |
| `--handshake-timeout` | FLOAT | `15.0` | TLS handshake timeout (s) |
| `--starttls-timeout` | FLOAT | `15.0` | Plaintext STARTTLS negotiation timeout (s) |
| `--max-concurrent` | INT | `20` | Maximum concurrent checks |
| `--retries` | INT | `1` | Retries for timeout-class failures only |
| `--per-host-serial` | flag | off | Check all ports of one host before moving to the next |
| `--no-backoff` | flag | off | Disable the delay before re-probing a host that has been timing out |
| `--handshake-samples` | INT | `1` | Handshakes per target for the timing distribution |
| `--warmup-handshakes` | INT | `1` | Discarded handshakes before timing samples begin |
| `--min-samples` | INT | `5` | Minimum samples before percentiles are reported rather than withheld |
| `--check-resumption` | flag | off | Run a dedicated pair of handshakes to test TLS session resumption |

---

## TLS negotiation

| Option | Type | Default | Description |
|---|---|---|---|
| `--alpn` | TEXT | — | Comma-separated ALPN protocols to offer, e.g. `h2,http/1.1` |
| `--ciphers` | TEXT | — | OpenSSL cipher string restricting TLS 1.2-and-below suites |
| `--sni-hostname` | TEXT | — | Override the SNI value sent and checked against the certificate |
| `--no-sni` | flag | off | Send no SNI value at all |

---

## Policy (what makes a target non-compliant)

| Option | Type | Default | Description |
|---|---|---|---|
| `--min-days-remaining` | INT | — | Flag a certificate with fewer days remaining than this |
| `--max-lifetime-days` | INT | — | Flag a certificate whose total validity period exceeds this |
| `--min-tls-version` | TEXT | — | Flag a negotiated version below this floor, e.g. `TLSv1.2` |
| `--expected-issuer` | TEXT | — | Flag a certificate whose issuer doesn't contain this substring |
| `--expected-fingerprint` | TEXT | — | Flag a certificate that doesn't match this SHA-256 fingerprint |
| `--expected-cipher` | TEXT | — | Flag a target whose primary handshake didn't negotiate exactly this cipher |
| `--expected-group` | TEXT | — | Flag a target that doesn't negotiate this named group at all (needs `--deep-introspection`) |
| `--allow-hostname-mismatch` | flag | off | Do not flag a certificate that doesn't cover the target hostname |
| `--require-forward-secrecy` | flag | off | Flag a negotiated cipher suite without forward secrecy |
| `--allow-weak-key` | flag | off | Do not flag an under-strength public key |
| `--allow-weak-signature` | flag | off | Do not flag a broken signature hash (MD5/SHA-1) |
| `--allow-deprecated-tls` | flag | off | Do not flag TLS 1.0/1.1/SSLv3 |
| `--require-revocation-source` | flag | off | Flag a certificate with no OCSP or CRL URL |
| `--require-valid-chain` | flag | off | Flag a certificate whose chain didn't validate (needs `--verify-chain`) |
| `--allow-revoked` | flag | off | Do not flag a certificate OCSP/CRL reports as revoked |

---

## Chain of trust and revocation

| Option | Type | Default | Description |
|---|---|---|---|
| `--verify-chain` | flag | off | Fetch missing intermediates via AIA, validate against Mozilla + system trust |
| `--trust-anchor-file` | FILE | — | Extra PEM file of trust anchors (repeatable) |
| `--chain-timeout` | FLOAT | `10.0` | Timeout per AIA certificate fetch |
| `--max-chain-depth` | INT | `8` | Maximum AIA hops while completing a chain |
| `--check-cross-sign` | flag | off | Flag when an independent AIA-only path trusts a different root than the peer-supplied chain |
| `--check-multi-store` | flag | off | Also validate against Apple's, Google's, and Microsoft's own root programs |
| `--check-revocation` | flag | off | Query OCSP and CRL for each certificate's own revocation status |
| `--ocsp-timeout` | FLOAT | `10.0` | Timeout per OCSP responder query |
| `--crl-timeout` | FLOAT | `10.0` | Timeout per CRL fetch |

---

## Protocol, cipher, and deep introspection

| Option | Type | Default | Description |
|---|---|---|---|
| `--enumerate-protocol` | flag | off | Enumerate TLS versions and (unless `--no-enumerate-ciphers`) TLS 1.2-and-below ciphers, A-F rated |
| `--enumerate-ciphers` / `--no-enumerate-ciphers` | flag | on | Whether protocol enumeration also probes ciphers |
| `--deep-introspection` | flag | off | Named groups, DH parameters, extensions, signature algorithms, TLS 1.3 ciphers, vulnerability flags, via CryptoLyzer (`[crypto]` extra) |
| `--crypto-executor-workers` | INT | `10` | Thread pool size for `--deep-introspection` |
| `--simulate-clients` | flag | off | Which real browsers/libraries can complete a handshake with this target (`[crypto]` extra) |
| `--jarm` | flag | off | Compute a JARM server fingerprint (`[crypto]` extra) |
| `--jarm-timeout` | FLOAT | `20.0` | Per-target timeout for `--jarm` |
| `--measure-0rtt` | flag | off | Time full vs. resumed vs. resumed-with-0-RTT handshakes (needs the system `openssl` CLI) |
| `--zero-rtt-timeout` | FLOAT | `10.0` | Per-connection timeout for `--measure-0rtt` |

---

## Certificate Transparency and linting

| Option | Type | Default | Description |
|---|---|---|---|
| `--check-ct-logs` | flag | off | Resolve embedded SCTs against the CT log registry; report log trust status |
| `--lint` | flag | off | Lint against the CA/Browser Forum TLS Baseline Requirements via pkilint (`[lint]` extra) |

---

## Grading and compliance

| Option | Type | Default | Description |
|---|---|---|---|
| `--grade` | flag | off | Score against the published SSL Labs Server Rating Guide |
| `--check-mozilla-profiles` | flag | off | Check compliance against the published Server Side TLS (TLSRef) guidelines |
| `--mozilla-profile` | TEXT | all | Limit `--check-mozilla-profiles` to specific profile names (repeatable) |

---

## Topology and certificate coverage

| Option | Type | Default | Description |
|---|---|---|---|
| `--check-dual-stack` | flag | off | Compare the certificate served over IPv4 against IPv6 for dual-stack targets |
| `--detect-virtual-hosting` | flag | off | Report distinct certificates served by any IP scanned under more than one hostname |
| `--audit-san` | flag | off | For each literal DNS SAN entry, check whether it resolves and serves this same certificate |
| `--san-audit-max-entries` | INT | `25` | Cap on SAN entries probed per certificate |

---

## Certificate pinning

| Option | Type | Default | Description |
|---|---|---|---|
| `--generate-pin-set` | flag | off | Generate an SPKI pin set (leaf + backup pins from the validated chain) |
| `--pin-set-no-root` | flag | off | Exclude the trust-anchor root from the pin set |

---

## Time travel and output

| Option | Type | Default | Description |
|---|---|---|---|
| `--as-of` | TEXT | now | Evaluate every certificate as of this date/time (ISO 8601) instead of now |
| `--output, -o` | TEXT | `./benchmark_results` | Output directory |
| `--formats, -f` | TEXT | `csv,excel,pdf` | Output formats: `csv`, `excel`, `pdf` |
| `--json` | flag | off | Export results to JSON |
| `--include-charts` | flag | off | Include charts in the Excel export |
| `--threshold` | TEXT | — | Pass/fail criterion, e.g. `cert_expiry_days>30` (repeatable) |
| `--quiet` | flag | off | Suppress progress output |

---

## Optional extras

Several checks require installing net-benchmark with an extra:

| Extra | Unlocks | Install |
|---|---|---|
| `[pdf]` | PDF export | `pip install net-benchmark[pdf]` |
| `[lint]` | `--lint` (pkilint) | `pip install net-benchmark[lint]` |
| `[crypto]` | `--deep-introspection`, `--simulate-clients`, `--jarm`, Microsoft's store in `--check-multi-store` (CryptoLyzer, pyjarm, mscerts) | `pip install net-benchmark[crypto]` |

A check that needs a missing extra reports its own availability as
`"not_installed"` in the result rather than raising — the rest of the scan
still runs and exports normally.
