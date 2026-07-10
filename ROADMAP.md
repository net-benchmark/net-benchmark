# Roadmap

> Full details, implementation notes, and contributor discussion:
> [GitHub Discussion #45](https://github.com/net-benchmark/net-benchmark/discussions/45)

---

## DNS Module

| Version | Theme | Status |
|---|---|---|
| 0.5.0 | Async engine, Plain/DoH/DoT, DNSSEC basic, resolver/domain management, CLI & export | ✅ Released |
| 0.7.0 | DNSSEC full chain validation, RCODE classification, EDNS0 extensions, force-TCP, LRU cache | 🔜 Planned |
| 0.8.0 | DoQ (experimental), TSIG, AXFR/IXFR zone transfers, DDNS (RFC 2136), IDNA full support | 🔜 Planned |
| 0.9.0 | Record-type deep inspection, DNS audit, delegation chain analysis, encrypted DNS discovery | 🔭 Future |
| 1.0.0 | Wire-level inspection, resolver health scoring, Prometheus metrics, stable Python API | 🔭 Future |

---

## HTTP Module

| Version | Theme | Status |
|---|---|---|
| 0.5.0 | Async engine, HTTP/1.1+2, all methods, timing breakdown, security headers, CDN fingerprinting, auth, assertions, export | ✅ Released |
| 0.5.1 | Load testing, RPS, ramp-up, WebSocket, TLS resumption, charts, PDF report | 🔜 Planned |

---

## SSL/TLS Module

| Version | Theme | Status |
|---|---|---|
| 0.6.0 | Async TLS engine, certificate parsing, chain validation, OCSP/CRL revocation, STARTTLS, multi-port, monitoring | 🔜 Planned |
| 0.6.1 | Cipher enumeration & grading, Certificate Transparency, CAA, DV/OV/EV detection, pin set generation | 🔜 Planned |
| 0.6.2 | Full vulnerability scan via sslyze, SSL Labs-style grade, TLS 1.3 0-RTT, OCSP stapling (full) | 🔜 Planned |
