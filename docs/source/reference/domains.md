# Domain Reference

## Browse built-in domains

```bash
net-benchmark dns list-domains
net-benchmark dns list-domains --category tech
net-benchmark dns list-domains --category ecommerce
net-benchmark dns list-domains --category social
net-benchmark dns list-domains --category news
net-benchmark dns list-domains --count 10
net-benchmark dns list-domains --format csv
net-benchmark dns list-domains --format json
```

## Domain categories

| Category | Examples |
|---|---|
| `tech` | github.com, stackoverflow.com, cloudflare.com |
| `ecommerce` | amazon.com, shopify.com, ebay.com |
| `social` | twitter.com, reddit.com, linkedin.com |
| `news` | bbc.com, nytimes.com, cnn.com |
| `cdn` | cdnjs.cloudflare.com, jsdelivr.net |
| `cloud` | aws.amazon.com, azure.com, googleapis.com |

## Custom domain file

Plain text, one domain per line, `#` for comments:

```text
# My production endpoints
api.myapp.com
cdn.myapp.com

# Third-party dependencies
api.stripe.com
auth0.com
```

Pass with `--domains path/to/domains.txt`.

## Inline domains

```bash
--domains "google.com,github.com,cloudflare.com"
```
