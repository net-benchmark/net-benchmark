# SSL Check

```{admonition} Coming in v0.6.0
:class: note

The SSL check tool is planned for **version 0.6.0**.
[Contributions welcome](https://github.com/net-benchmark/net-benchmark/blob/main/CONTRIBUTING.md).
```

## Planned features

- Check certificate expiration dates
- Validate certificate chains and trust stores
- Monitor multiple hosts with alerts
- Flag wildcard certificates and SANs

## Planned usage

```bash
net-benchmark ssl check \
  --hosts "api.myservice.com,www.myservice.com" \
  --alert-days 30
```

## TLS cert capture (available now in HTTP benchmark)

While the dedicated SSL check tool is not yet released, the HTTP benchmark
already captures inline TLS certificate data per request:

```bash
net-benchmark http benchmark \
  --targets https://api.example.com \
  --formats excel
```

Each result includes: expiry days, CN, issuer, SANs, and wildcard detection.
