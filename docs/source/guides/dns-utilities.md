# DNS Utilities

## Resolver management

```bash
# Show default resolvers and domains
net-benchmark dns list-defaults

# Browse all available resolvers
net-benchmark dns list-resolvers

# Browse with detailed information
net-benchmark dns list-resolvers --details

# Filter by category
net-benchmark dns list-resolvers --category security
net-benchmark dns list-resolvers --category privacy
net-benchmark dns list-resolvers --category family

# Export resolvers to different formats
net-benchmark dns list-resolvers --format csv
net-benchmark dns list-resolvers --format json
```

## Domain management

```bash
# List all test domains
net-benchmark dns list-domains

# Show domains by category
net-benchmark dns list-domains --category tech
net-benchmark dns list-domains --category ecommerce
net-benchmark dns list-domains --category social

# Limit results
net-benchmark dns list-domains --count 10
net-benchmark dns list-domains --category news --count 5

# Export domain list
net-benchmark dns list-domains --format csv
net-benchmark dns list-domains --format json
```

## Category overview

```bash
# View all available categories
net-benchmark dns list-categories
```

## Configuration management

```bash
# Generate sample configuration
net-benchmark dns generate-config --output sample_config.yaml

# Category-specific configurations
net-benchmark dns generate-config --category security --output security_test.yaml
net-benchmark dns generate-config --category family --output family_protection.yaml
net-benchmark dns generate-config --category performance --output performance_test.yaml

# Custom configuration for specific use case
net-benchmark dns generate-config --category privacy --output privacy_audit.yaml
```

## Automation & CI

### Cron jobs

```bash
# Daily monitoring
0 2 * * * /usr/local/bin/net-benchmark dns benchmark --use-defaults --formats csv --quiet --output /var/log/net_benchmark/daily_$(date +\%Y\%m\%d)

# Time-based variability (every 6 hours)
0 */6 * * * /usr/local/bin/net-benchmark dns benchmark --use-defaults --formats csv --quiet --output /var/log/net_benchmark/$(date +\%Y\%m\%d_\%H)
```

### GitHub Actions

```yaml
- name: DNS Performance Test
  run: |
    pip install net-benchmark
    net-benchmark dns benchmark \
      --resolvers "1.1.1.1,8.8.8.8" \
      --domains "api.service.com,database.service.com" \
      --formats csv \
      --quiet
```
