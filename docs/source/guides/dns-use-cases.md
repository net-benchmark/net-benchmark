# DNS Use Cases

## For developers: optimize API performance

```bash
# Find fastest DNS for your API endpoints
net-benchmark dns benchmark \
  --domains api.myapp.com,cdn.myapp.com \
  --record-types A,AAAA \
  --resolvers production.json \
  --iterations 10
```

**Result:** Reduce API latency by 100–300 ms.

---

## For DevOps/SRE: validate before migration

```bash
# Test new DNS provider before switching
net-benchmark dns benchmark \
  --resolvers current-dns.json,new-dns.json \
  --use-defaults \
  --dnssec-validate \
  --output migration-report/ \
  --formats csv,excel
```

**Result:** Verify performance and security before migration.

---

## For self-hosters: prove Pi-hole performance

```bash
# Compare Pi-hole against public resolvers
net-benchmark dns compare \
  --resolvers pihole.local,1.1.1.1,8.8.8.8,9.9.9.9 \
  --domains common-sites.txt \
  --rounds 10
```

**Result:** Data-driven proof your self-hosted DNS is faster (or not!).

---

## For network admins: automated health checks

```bash
# Add to crontab for monthly reports
0 0 1 * * net-benchmark dns benchmark \
  --use-defaults \
  --output /var/reports/dns/ \
  --formats excel,csv \
  --domain-stats \
  --error-breakdown
```

**Result:** Automated compliance and SLA reporting.

---

## For privacy advocates: test encrypted DNS

```bash
# Benchmark privacy-focused DoH/DoT resolvers
net-benchmark dns benchmark \
  --doh \
  --resolvers privacy-resolvers.json \
  --domains sensitive-sites.txt \
  --dnssec-validate
```

**Result:** Find fastest encrypted DNS without sacrificing privacy.

---

## Network administrator

```bash
# Compare internal vs external DNS
net-benchmark dns benchmark \
  --resolvers "192.168.1.1,1.1.1.1,8.8.8.8,9.9.9.9" \
  --domains "internal.company.com,google.com,github.com,api.service.com" \
  --formats excel,pdf \
  --timeout 3 \
  --max-concurrent 50 \
  --output ./network_audit

# Test DNS failover scenarios
net-benchmark dns benchmark \
  --resolvers data/primary_resolvers.json \
  --domains data/business_critical_domains.txt \
  --record-types A,AAAA \
  --retries 3 \
  --formats csv,excel \
  --output ./failover_test
```

---

## ISP & network operator

```bash
# Comprehensive ISP resolver comparison
net-benchmark dns benchmark \
  --resolvers data/isp_resolvers.json \
  --domains data/popular_domains.txt \
  --timeout 5 \
  --max-concurrent 100 \
  --formats csv,excel,pdf \
  --output ./isp_performance_analysis

# Regional performance testing
net-benchmark dns benchmark \
  --resolvers data/regional_resolvers.json \
  --domains data/regional_domains.txt \
  --formats excel \
  --quiet \
  --output ./regional_analysis
```

---

## Developer & DevOps

```bash
# Test application dependencies
net-benchmark dns benchmark \
  --resolvers "1.1.1.1,8.8.8.8" \
  --domains "api.github.com,registry.npmjs.org,pypi.org,docker.io,aws.amazon.com" \
  --formats csv \
  --quiet \
  --output ./app_dependencies

# CI/CD integration test
net-benchmark dns benchmark \
  --resolvers data/ci_resolvers.json \
  --domains data/ci_domains.txt \
  --timeout 2 \
  --formats csv \
  --quiet
```

---

## Security auditor

```bash
# Security-focused resolver testing
net-benchmark dns benchmark \
  --resolvers data/security_resolvers.json \
  --domains data/malware_test_domains.txt \
  --formats csv,pdf \
  --output ./security_audit

# Privacy-focused testing
net-benchmark dns benchmark \
  --resolvers data/privacy_resolvers.json \
  --domains data/tracking_domains.txt \
  --formats excel \
  --output ./privacy_analysis
```

---

## Enterprise IT

```bash
# Corporate network assessment
net-benchmark dns benchmark \
  --resolvers data/enterprise_resolvers.json \
  --domains data/corporate_domains.txt \
  --record-types A,AAAA,MX,TXT,SRV \
  --timeout 10 \
  --max-concurrent 25 \
  --retries 2 \
  --formats csv,excel,pdf \
  --output ./enterprise_dns_audit

# Multi-location testing
net-benchmark dns benchmark \
  --resolvers data/global_resolvers.json \
  --domains data/international_domains.txt \
  --formats excel \
  --output ./global_performance
```
