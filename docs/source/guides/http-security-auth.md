# HTTP Security & Auth

## Auth & enterprise options

| Flag | What it does |
|---|---|
| `--auth basic:user:pass` | HTTP Basic authentication |
| `--auth bearer:token` | Bearer token (OAuth2) |
| `--headers x-api-key:key` | Custom API key header |
| `--cert client.pem --cert-key client-key.pem` | mTLS client certificate |
| `--proxy http://proxy:8080` | Proxy support |
| `--sni example.com` | SNI override |
| `--local-address 192.168.1.100` | Interface binding |
| `--inject-request-id` | Adds `X-Request-ID` header |
| `--user-agent "MyBot/1.0"` | Custom User-Agent |
| `--cookie "name=value"` | Cookie (repeatable) |
| `--no-verify-ssl` | Skip TLS verification (internal servers) |

---

## Auth examples

```bash
# Basic auth
net-benchmark http benchmark \
  --targets https://httpbin.org/basic-auth/user/pass \
  --auth "basic:user:pass"

# Bearer token (standard OAuth2)
net-benchmark http benchmark \
  --targets https://api.example.com/data \
  --auth "bearer:sk-abc123"

# Custom API key header (x-api-key)
net-benchmark http benchmark \
  --targets https://api.example.com/echo \
  --method POST \
  --headers "x-api-key:sk-abc123"

# mTLS client certificate
net-benchmark http benchmark \
  --targets https://mtls.example.com \
  --cert client.pem --cert-key client-key.pem

# Proxy with auth
net-benchmark http benchmark \
  --targets https://example.com \
  --proxy http://proxy:8080 \
  --auth "basic:proxyuser:proxypass"
```

---

## Security headers audited

Every request captures the presence or absence of:

- `Strict-Transport-Security` (HSTS)
- `Content-Security-Policy` (CSP)
- `X-Frame-Options`
- `X-Content-Type-Options`
- `Referrer-Policy`
- `Permissions-Policy`

The Excel Security Headers sheet colour-codes presence (green) and absence (red) per target.

---

## CDN fingerprinting

Detected automatically per request:

- Cloudflare
- Amazon CloudFront
- Fastly
- Akamai
- Google CDN
- Azure CDN

---

## Full security audit example

```bash
net-benchmark http benchmark \
  --targets https://www.example.com,https://api.example.com \
  --assert status=200 \
  --assert header_exists=strict-transport-security \
  --assert header_value=X-Content-Type-Options=nosniff \
  --formats excel,pdf \
  --output ./security_audit
```

---

## Assertions reference

| Assert flag | Description |
|---|---|
| `--assert status=200` | Assert HTTP status code |
| `--assert body_contains=success` | Assert body contains string |
| `--assert header_exists=X-Cache` | Assert header is present |
| `--assert header_value=X-Cache=HIT` | Assert header equals value |
| `--assert max_latency=500` | Assert total latency ≤ N ms |
| `--assert content_type=application/json` | Assert Content-Type |
| `--assert response_size_min=100` | Assert response body ≥ N bytes |
| `--assert response_size_max=10000` | Assert response body ≤ N bytes |
