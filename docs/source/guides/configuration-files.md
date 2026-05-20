# Configuration Files

## Resolvers JSON format

```json
{
  "resolvers": [
    {
      "name": "Cloudflare",
      "ip": "1.1.1.1",
      "ipv6": "2606:4700:4700::1111"
    },
    {
      "name": "Google DNS",
      "ip": "8.8.8.8",
      "ipv6": "2001:4860:4860::8888"
    },
    {
      "name": "My Pi-hole",
      "ip": "192.168.1.1"
    }
  ]
}
```

`ipv6` is optional. Pass with `--resolvers path/to/resolvers.json`.

---

## Domains text file format

```text
# Popular websites
google.com
github.com
stackoverflow.com

# Corporate domains
microsoft.com
apple.com
amazon.com

# CDN and cloud
cloudflare.com
aws.amazon.com
```

Lines starting with `#` are treated as comments and ignored.
Pass with `--domains path/to/domains.txt`.

---

## HTTP targets file

Plain text, one URL per line:

```text
https://api.example.com/health
https://www.example.com
https://cdn.example.com/static/test.js
```

Pass with `--targets path/to/targets.txt`.

---

## Generate YAML configuration (DNS)

```bash
# Generate sample configuration
net-benchmark dns generate-config --output sample_config.yaml

# Category-specific configurations
net-benchmark dns generate-config --category security --output security_test.yaml
net-benchmark dns generate-config --category family --output family_protection.yaml
net-benchmark dns generate-config --category performance --output performance_test.yaml
net-benchmark dns generate-config --category privacy --output privacy_audit.yaml
```

Then pass the generated file to a benchmark run:

```bash
net-benchmark dns benchmark \
  --resolvers privacy_audit.yaml \
  --formats csv
```

---

## Inline inputs (no files needed)

For quick runs, supply values directly on the command line.
File detection takes priority over inline parsing.

```bash
# DNS — named resolvers
--resolvers "Cloudflare,Google,Quad9"

# DNS — IP addresses
--resolvers "1.1.1.1,8.8.8.8,9.9.9.9"

# DNS — mixed
--resolvers "1.1.1.1,Cloudflare,8.8.8.8"

# DNS — single value
--resolvers "1.1.1.1"

# DNS — domains
--domains "google.com,github.com,cloudflare.com"

# HTTP — targets
--targets "https://example.com,https://httpbin.org/get"
```
