# Resolver Reference

## Browse built-in resolvers

```bash
net-benchmark dns list-resolvers
net-benchmark dns list-resolvers --details
net-benchmark dns list-resolvers --category security
net-benchmark dns list-resolvers --category privacy
net-benchmark dns list-resolvers --category family
net-benchmark dns list-resolvers --category performance
net-benchmark dns list-resolvers --format csv
net-benchmark dns list-resolvers --format json
```

## Common named resolvers

| Name | Primary IP | IPv6 | Notes |
|---|---|---|---|
| `Cloudflare` | `1.1.1.1` | `2606:4700:4700::1111` | Fast, privacy-focused |
| `Google` | `8.8.8.8` | `2001:4860:4860::8888` | Reliable anycast |
| `Quad9` | `9.9.9.9` | `2620:fe::fe` | Security-filtered |
| `OpenDNS` | `208.67.222.222` | — | Family / parental filters available |
| `AdGuard` | `94.140.14.14` | — | Ad-blocking resolver |
| `Mullvad` | `194.242.2.2` | — | Privacy / no-logging |

## Categories

| Category | Description |
|---|---|
| `performance` | Public anycast resolvers optimised for speed |
| `security` | Resolvers with malware / threat blocking |
| `privacy` | No-logging, privacy-preserving resolvers |
| `family` | Family-safe, adult content filtered |

## Custom resolver JSON

```json
{
  "resolvers": [
    { "name": "My DNS", "ip": "192.168.1.1" },
    { "name": "Backup", "ip": "192.168.1.2", "ipv6": "fd00::2" }
  ]
}
```
