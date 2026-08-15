# Benchmark DNS

Testa le prestazioni dei *resolver*: DNS in chiaro, DNSSEC, DoH/DoT.

## Perché questo strumento?

La risoluzione DNS è spesso il collo di bottiglia nascosto delle prestazioni di
rete. Un resolver lento può aggiungere centinaia di millisecondi a ogni
richiesta.

### Il problema

- ⏱️ **Collo di bottiglia nascosto**: il DNS può aggiungere oltre 300 ms a ogni richiesta
- 🤷 **Prestazioni ignote**: la maggior parte degli sviluppatori non testa mai il proprio DNS
- 🌍 **La posizione conta**: quale sia il resolver "più veloce" dipende da dove ti trovi TU
- 🔒 **La sicurezza varia**: il supporto a DNSSEC, DoH e DoT cambia moltissimo

### La soluzione

net-benchmark ti aiuta a:

- 🔍 **Trovare il più veloce** resolver DNS per la TUA posizione
- 📊 **Ottenere dati reali** — P95, P99, jitter, punteggi di consistenza
- 🛡️ **Validare la sicurezza** — verifica DNSSEC integrata
- 🚀 **Testare su larga scala** — oltre 100 query concorrenti in pochi secondi

### Ideale per

- ✅ **Sviluppatori** che ottimizzano le prestazioni delle API
- ✅ **DevOps/SRE** che validano gli SLA dei resolver
- ✅ **Self-hoster** che confrontano Pi-hole/Unbound con i DNS pubblici
- ✅ **Amministratori di rete** che eseguono controlli di conformità

## Avvio rapido

```bash
# Test default resolvers against popular domains
net-benchmark dns benchmark --use-defaults --formats csv,excel
```

I risultati vengono salvati automaticamente in `./benchmark_results/` con un CSV
riepilogativo, i dati grezzi di dettaglio e report PDF/Excel opzionali.

> Per i dettagli di installazione, vedi [Installazione](installation.md).
> Per l'esportazione PDF, vedi [Formati di esportazione](export-formats.md).

## Comandi a colpo d'occhio

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

## Funzionalità principali

### 🚀 Prestazioni

- **Query asincrone** — testa oltre 100 resolver simultaneamente
- **Iterazioni multiple** — ripeti i benchmark più volte per maggiore accuratezza
- **Analisi statistica** — media, mediana, P95, P99, jitter, consistenza
- **Controllo della cache** — testa con o senza caching DNS

### 🔒 Sicurezza e privacy

- **Validazione DNSSEC** — verifica le catene di fiducia crittografiche
- **DNS-over-HTTPS (DoH)** — benchmarking DNS cifrato
- **DNS-over-TLS (DoT)** — test del trasporto sicuro
- **DNS-over-QUIC (DoQ)** — supporto QUIC sperimentale

### 📊 Analisi ed esportazione

- **Formati multipli** — CSV, Excel, PDF, JSON (vedi [Formati di esportazione](export-formats.md))
- **Report visivi** — grafici e diagrammi
- **Statistiche per dominio** — analisi delle prestazioni dominio per dominio
- **Ripartizione degli errori** — individua i resolver problematici

### 🏢 Funzionalità enterprise

- **Autenticazione TSIG** — query enterprise sicure
- **Trasferimenti di zona** — validazione AXFR/IXFR
- **Aggiornamenti dinamici** — testa le operazioni di scrittura DNS
- **Report di conformità** — documentazione pronta per l'audit

### 🌐 Multipiattaforma

- **Linux, macOS, Windows** — funziona ovunque
- **Adatto a CI/CD** — output JSON, codici di uscita
- **Supporto IDNA** — nomi di dominio internazionalizzati
- **Rilevamento automatico** — individuazione del DNS via WMI su Windows

## Sicurezza e DNS cifrato

Tre protocolli sono pienamente supportati — ognuno aggiunge privacy al costo di
un po' di latenza.

| Protocollo | Flag | Overhead tipico | Quando usarlo |
|---|---|---|---|
| UDP in chiaro | *(predefinito)* | riferimento di base | Benchmarking della latenza |
| DNS-over-HTTPS | `--doh` | +50–200 ms | Privacy, aggiramento di firewall |
| DNS-over-TLS | `--dot` | +200–500 ms a freddo, ~50 ms a caldo | Trasporto cifrato |
| DNSSEC | `--dnssec-validate` | +30–100 ms | Validazione dell'integrità del resolver |

> ⚠️ **Compromessi**
>
> - DoH e DoT aggiungono l'overhead dell'handshake TLS alla prima query di ogni
>   resolver. Usa `--warmup-fast` per assorbirlo prima di misurare.
> - `--dnssec-validate` richiede i record RRSIG e impone il flag AD. Solo circa
>   il 33% dei domini comuni è firmato DNSSEC — aspettati risultati
>   `DNSSEC_FAILED` sui domini non firmati. I valori di latenza con e senza
>   questo flag **non sono direttamente confrontabili**.
> - I risultati su rete mobile/hotspot mostrano una varianza da 2 a 5 volte
>   superiore rispetto all'ethernet cablato. Usa `--iterations 5` e confronta la
>   latenza mediana, non la media.

```bash
# DoH benchmark
net-benchmark dns benchmark --use-defaults --doh

# DoT with DNSSEC on signed domains
net-benchmark dns benchmark --use-defaults --dot --dnssec-validate

# Compare DoH resolvers
net-benchmark dns compare Cloudflare Google Quad9 --doh
```

Vincoli da tenere presenti:

```bash
# --doh and --dot are mutually exclusive
# ERROR: --doh and --dot are mutually exclusive.

# --doh-url count must match --resolvers count
# ERROR: --doh-url has 1 URL(s) but --resolvers has 2 resolver(s). Counts must match.

# Custom IP with --doh requires --doh-url
# ERROR: --doh requires a DoH URL for: 192.168.1.1. Use --doh-url to supply them explicitly.
```
