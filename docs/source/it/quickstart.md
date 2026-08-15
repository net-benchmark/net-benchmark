# Avvio rapido

Questa pagina raccoglie i comandi con cui iniziare. Per l'installazione vedi
[Installazione](installation.md).

## DNS

```bash
# Test default resolvers against popular domains
net-benchmark dns benchmark --use-defaults --formats csv,excel
```

I risultati vengono salvati automaticamente in `./benchmark_results/` con un CSV
riepilogativo, i dati grezzi di dettaglio e report PDF/Excel opzionali.

### Comandi a colpo d'occhio

| Comando | Cosa fa | Esempio rapido |
|---|---|---|
| `benchmark` | Benchmark DNS completo con esportazioni | `net-benchmark dns benchmark --use-defaults` |
| `top` | Classifica tutti i resolver per velocità | `net-benchmark dns top --limit 5` |
| `compare` | Confronto affiancato tra resolver | `net-benchmark dns compare Cloudflare Google Quad9` |
| `monitoring` | Monitoraggio continuo con avvisi | `net-benchmark dns monitoring --use-defaults` |

```bash
# Find your fastest resolver right now
net-benchmark dns top --limit 5

# Compare the big three
net-benchmark dns compare Cloudflare Google Quad9 --show-details

# Monitor with DoT and alerts for 1 hour
net-benchmark dns monitoring --use-defaults --dot \
  --interval 30 --duration 3600 \
  --alert-latency 150 --output monitor.log
```

## HTTP

```bash
# Test 5 built-in targets with a single iteration
net-benchmark http benchmark --use-defaults
```

```bash
# First-run recommendations
net-benchmark http benchmark --use-defaults --formats csv,excel
net-benchmark http benchmark --use-defaults --iterations 5   # meaningful jitter/consistency
```

### Comandi a colpo d'occhio

| Comando | Cosa fa | Esempio rapido |
|---|---|---|
| `benchmark` | Benchmark HTTP completo con esportazioni | `net-benchmark http benchmark --use-defaults` |
| `top` | Classifica i target per velocità | `net-benchmark http top --use-defaults --limit 5` |
| `compare` | Confronto affiancato dei target | `net-benchmark http compare api.example.com api2.example.com` |
| `monitoring` | Monitoraggio continuo con avvisi | `net-benchmark http monitoring --use-defaults` |
| `load-test` | Test di carico prolungato con modellazione del traffico configurabile | `net-benchmark http load-test -t https://api.example.com --mode throughput --duration 30` |
| `merge-load-test` | Unisce i riepiloghi dei worker di un'esecuzione distribuita | `net-benchmark http merge-load-test ./nodes/*.json -o ./merged` |

```bash
# Find your fastest endpoint right now
net-benchmark http top --use-defaults --limit 5

# Compare two APIs side-by-side
net-benchmark http compare api.example.com api2.example.com --iterations 3 --show-details

# Monitor with alerts for 1 hour
net-benchmark http monitoring --use-defaults \
  --interval 30 --duration 3600 \
  --alert-latency 500 --alert-failure-rate 5

# Load-test an endpoint to find its throughput ceiling
net-benchmark http load-test -t https://api.example.com/health --mode throughput --duration 30 --max-concurrency 300
```

## Passi successivi

- [Benchmark DNS](dns-benchmark.md) — resolver, DNSSEC, DoH/DoT
- [Benchmark HTTP](http-benchmark.md) — latenza, TTFB, header di sicurezza, TLS
- [Test di carico HTTP](http-load-test.md) — carico prolungato e distribuito
- [Formati di esportazione](export-formats.md)
