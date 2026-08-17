# net-benchmark

benchmarking di rete veloce ed estensibile — dns, http e ssl da una sola cli.

**Demo**

[![Demo](src/net_benchmark/gifs/net_benchmark_demo_1280.gif)](https://github.com/net-benchmark/net-benchmark)
*Guarda la demo completa di 2:09 dei benchmark DNS e HTTP*

**Se lo trovi utile, valuta di lasciare una ⭐ — aiuta altre persone a scoprire il progetto.**

[![PyPI version](https://badge.fury.io/py/net-benchmark.svg)](https://pypi.org/project/net-benchmark)
[![Python](https://img.shields.io/pypi/pyversions/net-benchmark.svg)](https://pypi.org/project/net-benchmark)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI](https://github.com/net-benchmark/net-benchmark/actions/workflows/ci.yml/badge.svg)](https://github.com/net-benchmark/net-benchmark/actions)
[![Downloads](https://pepy.tech/badge/net-benchmark)](https://pepy.tech/project/net-benchmark)
[![Docs](https://readthedocs.org/projects/net-benchmark/badge/?version=latest)](https://net-benchmark.readthedocs.io/en/latest/)
[![Discussions](https://img.shields.io/github/discussions/net-benchmark/net-benchmark)](https://github.com/net-benchmark/net-benchmark/discussions)
[![PyPI - Wheel](https://img.shields.io/pypi/wheel/net-benchmark)](https://pypi.org/project/net-benchmark)
[![GitHub Stars](https://img.shields.io/github/stars/net-benchmark/net-benchmark?style=social)](https://github.com/net-benchmark/net-benchmark/stargazers)

```bash
pip install net-benchmark
pip install net-benchmark[pdf]   # with pdf export
```

> **Successore di [dns-benchmark-tool](https://github.com/net-benchmark/dns-benchmark-tool)** — pienamente retrocompatibile.
> Il comando `dns-benchmark` continua a funzionare come alias.

## Perché net-benchmark?

La maggior parte degli strumenti di rete risponde a una sola domanda e si ferma
lì. `dig` ti dice che un resolver ha risposto. `curl` ti dice che una richiesta
è andata a buon fine. `ab` ti dà un numero senza dirti se quel numero riguarda
il server o la macchina su cui l'hai eseguito.

net-benchmark esiste per produrre **evidenze su cui puoi agire e che puoi
consegnare a qualcun altro**:

| | |
|---|---|
| **Una sola CLI, tre livelli** | DNS, HTTP e TLS da un unico strumento con un solo modello di output — niente più incollare insieme tre utility per spiegare un singolo caricamento lento. |
| **Misurazioni difendibili** | Tempi per fase (DNS, TCP, TLS, TTFB), percentili calcolati da istogrammi reali e metriche che vengono *omesse* anziché riportate come uno zero fuorviante quando non sono calcolabili. |
| **Report, non scrollback** | CSV, Excel con grafici, PDF e JSON — l'artefatto finisce nel ticket, nel documento di migrazione o nel job di CI. |
| **Pronto per la CI** | `--threshold 'p95_latency<400'` esce con codice diverso da zero. I nomi delle metriche vengono validati prima che la corsa inizi, così un refuso costa un secondo invece di un intero test di carico. |
| **DNS cifrato come cittadino di prima classe** | DoH e DoT con validazione DNSSEC, non come ripensamento. |
| **Onesto sui propri limiti** | Se il collo di bottiglia è lo strumento stesso, lo dice — e `--workers` ti permette di rimuoverlo. |

**Domande tipiche a cui risponde:**

```bash
# "Which resolver is actually fastest from this network?"
net-benchmark dns top --limit 5

# "Is our new CDN faster than the old origin?"
net-benchmark http compare https://old.example.com https://new.example.com

# "Can checkout hold 400 requests/second before we open the sale?"
net-benchmark http load-test -t https://checkout.example.com/api/cart \
  --mode sustained --rps 400 --duration 300 --workers 4 \
  --threshold 'p95_latency<400'
```

### Novità della 0.5.2

**Test di carico distribuito.** Un singolo processo Python è di norma il collo
di bottiglia molto prima del tuo target. `--workers N` genera il carico da N
processi separati con avvio sincronizzato, e i percentili vengono ricalcolati a
partire dagli istogrammi uniti anziché essere mediati — mediare i P95 dei vari
worker restituisce un numero diverso, non un'approssimazione. Le esecuzioni
possono anche estendersi su più macchine tramite una barriera di avvio condivisa
e il nuovo collector `merge-load-test`. Vedi
[Test di carico](#-test-di-carico).

Inoltre: soglie pass/fail per la CI, output live per intervallo, controllo del
backlog in modo che il sovraccarico si manifesti come richieste scartate anziché
come latenza gonfiata, e codici di successo definiti dall'utente tramite
`--expected-status`.

## Indice

- [Perché net-benchmark?](#perché-net-benchmark)
- [Installazione](#installazione)
- [Strumenti](#strumenti)
  - [Benchmark DNS](#benchmark-dns)
  - [Benchmark HTTP](#benchmark-http)
    - [Test di carico](#-test-di-carico)
  - [Controllo SSL](#controllo-ssl)
- [Formati di esportazione](#formati-di-esportazione)
- [Workflow di rilascio](#workflow-di-rilascio)
- [Link e supporto](#link-e-supporto)
- [Contribuire](#contribuire)
- [Licenza](#licenza)

---

## Installazione

```bash
pip install net-benchmark          # core
pip install net-benchmark[pdf]     # with pdf export
```

### Requisiti

- Python 3.9+
- gestore di pacchetti pip

### Installazione dai sorgenti

```bash
git clone https://github.com/net-benchmark/net-benchmark.git
cd net-benchmark
pip install -e .
```

### Verifica dell'installazione

```bash
net-benchmark --version
net-benchmark dns --help
net-benchmark http --help

# See all available options for a specific command
net-benchmark dns benchmark --help
net-benchmark http benchmark --help
```

### Prima esecuzione

```bash
# Test with defaults (recommended for first time)
net-benchmark dns benchmark --use-defaults --formats csv,excel

# HTTP test with defaults
net-benchmark http benchmark --use-defaults --formats csv,excel
```

---

## Strumenti

### Benchmark DNS

<details>
<summary><strong>Benchmark DNS</strong> — testa le prestazioni dei resolver dns, dnssec, doh/dot</summary>

#### 🎯 Perché questo strumento?

La risoluzione DNS è spesso il collo di bottiglia nascosto delle prestazioni di rete. Un resolver lento può aggiungere centinaia di millisecondi a ogni richiesta.

##### Il problema

- ⏱️ **Collo di bottiglia nascosto**: il DNS può aggiungere oltre 300 ms a ogni richiesta
- 🤷 **Prestazioni ignote**: la maggior parte degli sviluppatori non testa mai il proprio DNS
- 🌍 **La posizione conta**: quale sia il resolver "più veloce" dipende da dove ti trovi TU
- 🔒 **La sicurezza varia**: il supporto a DNSSEC, DoH e DoT cambia moltissimo

##### La soluzione

net-benchmark ti aiuta a:

- 🔍 **Trovare il più veloce** resolver DNS per la TUA posizione
- 📊 **Ottenere dati reali** - P95, P99, jitter, punteggi di consistenza
- 🛡️ **Validare la sicurezza** - verifica DNSSEC integrata
- 🚀 **Testare su larga scala** - oltre 100 query concorrenti in pochi secondi

##### Ideale per

- ✅ **Sviluppatori** che ottimizzano le prestazioni delle API
- ✅ **DevOps/SRE** che validano gli SLA dei resolver
- ✅ **Self-hoster** che confrontano Pi-hole/Unbound con i DNS pubblici
- ✅ **Amministratori di rete** che eseguono controlli di conformità

---

#### Avvio rapido

```bash
# Test default resolvers against popular domains
net-benchmark dns benchmark --use-defaults --formats csv,excel
```

I risultati vengono salvati automaticamente in `./benchmark_results/` con un CSV riepilogativo, i dati grezzi di dettaglio e report PDF/Excel opzionali.

> Per i dettagli di installazione, vedi [Installazione](#installazione).  
> Per l'esportazione PDF, vedi [Dipendenze PDF](#pdf-dependencies) sotto [Formati di esportazione](#formati-di-esportazione).

---

#### ⚡ Comandi a colpo d'occhio

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

---

#### ✨ Funzionalità principali

##### 🚀 Prestazioni

- **Query asincrone** - testa oltre 100 resolver simultaneamente
- **Iterazioni multiple** - ripeti i benchmark più volte per maggiore accuratezza
- **Analisi statistica** - media, mediana, P95, P99, jitter, consistenza
- **Controllo della cache** - testa con o senza caching DNS

##### 🔒 Sicurezza e privacy

- **Validazione DNSSEC** - verifica le catene di fiducia crittografiche
- **DNS-over-HTTPS (DoH)** - benchmarking DNS cifrato
- **DNS-over-TLS (DoT)** - test del trasporto sicuro
- **DNS-over-QUIC (DoQ)** - supporto QUIC sperimentale

##### 📊 Analisi ed esportazione

- **Formati multipli** - CSV, Excel, PDF, JSON (vedi [Formati di esportazione](#formati-di-esportazione) per i dettagli)
- **Report visivi** - grafici e diagrammi
- **Statistiche per dominio** - analisi delle prestazioni dominio per dominio
- **Ripartizione degli errori** - individua i resolver problematici

##### 🏢 Funzionalità enterprise

- **Autenticazione TSIG** - query enterprise sicure
- **Trasferimenti di zona** - validazione AXFR/IXFR
- **Aggiornamenti dinamici** - testa le operazioni di scrittura DNS
- **Report di conformità** - documentazione pronta per l'audit

##### 🌐 Multipiattaforma

- **Linux, macOS, Windows** - funziona ovunque
- **Adatto a CI/CD** - output JSON, codici di uscita
- **Supporto IDNA** - nomi di dominio internazionalizzati
- **Rilevamento automatico** - individuazione del DNS via WMI su Windows

---

#### 🔒 Sicurezza e DNS cifrato

Tre protocolli sono pienamente supportati — ognuno aggiunge privacy al costo di un po' di latenza.

| Protocollo | Flag | Overhead tipico | Quando usarlo |
|---|---|---|---|
| UDP in chiaro | *(predefinito)* | riferimento di base | Benchmarking della latenza |
| DNS-over-HTTPS | `--doh` | +50–200 ms | Privacy, aggiramento di firewall |
| DNS-over-TLS | `--dot` | +200–500 ms a freddo, ~50 ms a caldo | Trasporto cifrato |
| DNSSEC | `--dnssec-validate` | +30–100 ms | Validazione dell'integrità del resolver |

> ⚠️ **Compromessi**
> - DoH e DoT aggiungono l'overhead dell'handshake TLS alla prima query di ogni resolver. Usa `--warmup-fast` per assorbirlo prima di misurare.
> - `--dnssec-validate` richiede i record RRSIG e impone il flag AD. Solo circa il 33% dei domini comuni è firmato DNSSEC — aspettati risultati `DNSSEC_FAILED` sui domini non firmati. I valori di latenza con e senza questo flag **non sono direttamente confrontabili**.
> - I risultati su rete mobile/hotspot mostrano una varianza da 2 a 5 volte superiore rispetto all'ethernet cablato. Usa `--iterations 5` e confronta la latenza mediana, non la media.

```bash
# DoH benchmark
net-benchmark dns benchmark \
  --resolvers "Cloudflare,Google" \
  --domains "cloudflare.com,google.com" \
  --doh --warmup-fast

# custom resolvers — must supply urls 1:1, order matters, or it fails early
net-benchmark dns benchmark \
  --resolvers "Cloudflare,Google" \
  --domains "bing.com,google.com" \
  --doh \
  --doh-url "https://cloudflare-dns.com/dns-query,https://dns.google/dns-query" \
  --iterations 1 \
  --formats csv \
  --output ./doh_results_explicit_urls

# DoT with DNSSEC on signed domains
net-benchmark dns benchmark \
  --resolvers "Cloudflare,Quad9" \
  --domains "cloudflare.com,quad9.net" \
  --dot \
  --dnssec-validate

# DOH rank top resolvers
# Note: `top` without --category tests every resolver in the database, and
# --doh fails fast if ANY of them has no DoH URL. Narrow with --category,
# or supply --doh-url, if you hit that.
net-benchmark dns top --doh --limit 5

# DOT rank top resolvers
net-benchmark dns top --dot --metric reliability --limit 5

# Compare DoH resolvers
net-benchmark dns compare Cloudflare Google --doh --iterations 3

# Monitor with DoT
net-benchmark dns monitoring --use-defaults --dot \
  --interval 60 --alert-latency 300

# DoH + DNSSEC enforced + export
net-benchmark dns benchmark --use-defaults --doh --dnssec-validate --formats csv,excel

# DoT + DNSSEC enforced + multiple iterations
net-benchmark dns benchmark \
  --resolvers "Cloudflare,Quad9,Google" \
  --domains "cloudflare.com,quad9.net,google.com" \
  --dot \
  --dnssec-validate \
  --iterations 5 \
  --formats excel

# DoH + custom urls + monitoring
net-benchmark dns monitoring \
  --resolvers "Cloudflare,Google" \
  --doh \
  --doh-url "https://cloudflare-dns.com/dns-query,https://dns.google/dns-query" \
  --interval 30 --duration 7200
```

**Esempi di fallimento immediato** — questi falliscono subito, prima che venga eseguita qualsiasi query:

```bash
# --doh and --dot are mutually exclusive
net-benchmark dns benchmark --use-defaults --doh --dot
# ERROR: --doh and --dot are mutually exclusive.

# --doh-url count must match --resolvers count
net-benchmark dns benchmark --resolvers "Cloudflare,Google" --domains "bing.com,google.com" --doh \
  --doh-url "https://cloudflare-dns.com/dns-query"
# ERROR: --doh-url has 1 URL(s) but --resolvers has 2 resolver(s). Counts must match.

# Custom IP with --doh requires --doh-url
net-benchmark dns benchmark --resolvers "192.168.1.1" --domains "google.com" --doh
# ERROR: --doh requires a DoH URL for: 192.168.1.1. Use --doh-url to supply them explicitly.
```

---

#### 🔧 Funzionalità avanzate

> ⚠️ Questi flag sono **documentati per trasparenza** ma non ancora implementati.  
> Rappresentano funzionalità avanzate in arrivo.

- `--zone-transfer` → test di trasferimento di zona AXFR/IXFR *(in arrivo)*
- `--tsig` → query autenticate con TSIG *(in arrivo)*
- `--idna` → supporto ai nomi di dominio internazionalizzati *(in arrivo)*

<details>
<summary><b>🚀 Prestazioni e concorrenza</b></summary>

<br>

- **I/O asincrono con dnspython** - testa oltre 100 resolver simultaneamente
- **Supporto al framework Trio** - operazioni asincrone ad alta concorrenza
- **Concorrenza configurabile** - controlla il numero massimo di query concorrenti
- **Logica di ritentativo** - backoff esponenziale per le query fallite
- **Simulazione della cache** - testa con o senza caching DNS
- **Benchmark multi-iterazione** - ripeti i test più volte per maggiore accuratezza
- **Fase di riscaldamento** - pre-riscalda le cache DNS prima del test
- **Analisi statistica** - media, mediana, P95, P99, jitter, punteggi di consistenza

**Esempio:**

```bash
net-benchmark dns benchmark \
  --max-concurrent 200 \
  --iterations 5 \
  --timeout 3.0 \
  --warmup
```

</details>

<details>
<summary><b>🔒 Sicurezza e privacy</b></summary>

<br>

- **Validazione DNSSEC** - verifica le catene di fiducia crittografiche
- **DNS-over-HTTPS (DoH)** - benchmarking DNS cifrato via HTTPS
- **DNS-over-TLS (DoT)** - test del livello di trasporto sicuro
- **DNS-over-QUIC (DoQ)** - supporto sperimentale al protocollo QUIC
- **Autenticazione TSIG** - firme di transazione per DNS enterprise
- **Supporto EDNS0** - funzionalità DNS estese e payload più grandi

**Esempio:**

```bash
# Test DoH resolvers
net-benchmark dns benchmark \
  --doh \
  --resolvers doh-providers.json \
  --dnssec-validate
```

</details>

<details>
<summary><b>🏢 Enterprise e migrazione</b></summary>

<br>

- **Trasferimenti di zona (AXFR/IXFR)** - validazione dei trasferimenti completi e incrementali
- **Aggiornamenti DNS dinamici** - testa le operazioni di scrittura e aggiornamento DNS
- **Supporto EDNS0** - opzioni DNS estese, client subnet, payload più grandi
- **Integrazione WMI su Windows** - rileva automaticamente le impostazioni DNS attive del sistema
- **Reportistica di conformità** - genera report PDF/Excel pronti per l'audit
- **Validazione SLA** - traccia disponibilità e soglie prestazionali

**Esempio:**

```bash
# Validate DNS migration
net-benchmark dns benchmark \
  --resolvers old-provider.json,new-provider.json \
  --domains business-domains.txt \
  --output migration-report/ \
  --formats pdf,excel
# Zone-transfer (AXFR/IXFR) validation is not implemented yet — see
# "Advanced Capabilities" above.
```

</details>

<details>
<summary><b>📊 Analisi e reportistica</b></summary>

<br>

- **Statistiche per dominio** - analizza le prestazioni dominio per dominio
- **Statistiche per tipo di record** - confronta A, AAAA, MX, TXT, ecc.
- **Ripartizione degli errori** - categorizza e conta i tipi di errore
- **Matrici di confronto** - confronti affiancati fra resolver
- **Analisi di tendenza** - prestazioni nel tempo (con esecuzioni multiple)
- **Migliore per criterio** - individua il resolver migliore per latenza/affidabilità/consistenza

**Esempio:**

```bash
# Detailed analysis
net-benchmark dns benchmark \
  --use-defaults \
  --domain-stats \
  --record-type-stats \
  --error-breakdown \
  --formats csv,excel,pdf
```

</details>

<details>
<summary><b>🌐 Internazionalizzazione e compatibilità</b></summary>

<br>

- **Supporto IDNA** - nomi di dominio internazionalizzati (IDN)
- **Tipi di record multipli** - A, AAAA, MX, TXT, CNAME, NS, SOA, PTR, SRV, CAA
- **Multipiattaforma** - Linux, macOS, Windows (supporto nativo)
- **Integrazione CI/CD** - output JSON, codici di uscita corretti, modalità silenziosa
- **Resolver personalizzati** - caricali da JSON, testa i tuoi server DNS
- **Domini personalizzati** - testa la tua lista specifica di domini

**Esempio:**

```bash
# Test internationalized domains
net-benchmark dns benchmark \
  --domains international-domains.txt \
  --record-types A,AAAA,MX \
  --resolvers custom-resolvers.json
```

</details>

> 💡 **Alla maggior parte degli utenti bastano le funzionalità di base.** Queste capacità avanzate sono lì quando ti servono.

---

#### 💼 Casi d'uso

##### 🔧 Per sviluppatori: ottimizzare le prestazioni delle API

```bash
# Find fastest DNS for your API endpoints
net-benchmark dns benchmark \
  --domains api.myapp.com,cdn.myapp.com \
  --record-types A,AAAA \
  --resolvers production.json \
  --iterations 10
```

**Risultato:** riduzione della latenza delle API di 100-300 ms

---

##### 🛡️ Per DevOps/SRE: validare prima della migrazione

```bash
# Test new DNS provider before switching
# (--use-defaults would OVERRIDE --resolvers, so pass --domains instead)
net-benchmark dns benchmark \
  --resolvers current-dns.json,new-dns.json \
  --domains business-domains.txt \
  --dnssec-validate \
  --output migration-report/ \
  --formats csv,excel
```

**Risultato:** verifica di prestazioni e sicurezza prima della migrazione

---

##### 🏠 Per i self-hoster: dimostrare le prestazioni di Pi-hole

```bash
# Compare Pi-hole against public resolvers
# (resolvers are POSITIONAL arguments, not a --resolvers option)
net-benchmark dns compare pihole.local 1.1.1.1 8.8.8.8 9.9.9.9 \
  --domains common-sites.txt \
  --iterations 10
```

**Risultato:** prova basata sui dati che il tuo DNS self-hosted è più veloce (o non lo è!)

---

##### 📊 Per amministratori di rete: controlli di salute automatizzati

```bash
# Add to crontab for monthly reports
0 0 1 * * net-benchmark dns benchmark \
  --use-defaults \
  --output /var/reports/dns/ \
  --formats excel,csv \
  --domain-stats \
  --error-breakdown
```

**Risultato:** reportistica automatizzata di conformità e SLA

---

##### 🔐 Per i sostenitori della privacy: testare il DNS cifrato

```bash
# Benchmark privacy-focused DoH/DoT resolvers
net-benchmark dns benchmark \
  --doh \
  --resolvers privacy-resolvers.json \
  --domains sensitive-sites.txt \
  --dnssec-validate
```

**Risultato:** trova il DNS cifrato più veloce senza sacrificare la privacy

---

#### 📖 Esempi di utilizzo

##### Utilizzo di base
```bash
# Basic test with progress bars
net-benchmark dns benchmark --use-defaults --formats csv,excel

# Basic test without progress bars
net-benchmark dns benchmark --use-defaults --formats csv,excel --quiet

# Test with custom resolvers and domains
net-benchmark dns benchmark --resolvers data/resolvers.json --domains data/domains.txt

# Quick test with only CSV output
net-benchmark dns benchmark --use-defaults --formats csv
```

##### Utilizzo avanzato

```bash
# Export a machine-readable bundle
net-benchmark dns benchmark --use-defaults --json --output ./results

# Test specific record types
net-benchmark dns benchmark --use-defaults --formats csv,excel --record-types A,AAAA,MX

# Custom output location and formats
net-benchmark dns benchmark \
  --use-defaults \
  --output ./my-results \
  --formats csv,excel

# Include detailed statistics
net-benchmark dns benchmark \
  --use-defaults \
  --formats csv,excel \
  --record-type-stats \
  --error-breakdown

# High concurrency with retries
net-benchmark dns benchmark \
  --use-defaults \
  --formats csv,excel \
  --max-concurrent 200 \
  --timeout 3.0 \
  --retries 3

# Website migration planning
net-benchmark dns benchmark \
  --resolvers data/global_resolvers.json \
  --domains data/migration_domains.txt \
  --formats excel,pdf \
  --output ./migration_analysis

# DNS provider selection
net-benchmark dns benchmark \
  --resolvers data/provider_candidates.json \
  --domains data/business_domains.txt \
  --formats csv,excel \
  --output ./provider_selection

# Network troubleshooting
net-benchmark dns benchmark \
  --resolvers "192.168.1.1,1.1.1.1,8.8.8.8" \
  --domains "problematic-domain.com,working-domain.com" \
  --timeout 10 \
  --retries 3 \
  --formats csv \
  --output ./troubleshooting

# Security assessment
net-benchmark dns benchmark \
  --resolvers data/security_resolvers.json \
  --domains data/security_test_domains.txt \
  --formats pdf \
  --output ./security_assessment

# Performance monitoring
net-benchmark dns benchmark \
  --use-defaults \
  --formats csv \
  --quiet \
  --output /var/log/net_benchmark/$(date +%Y%m%d_%H%M%S)
```

#### Supporto agli input inline per resolver e domini

Questa funzionalità introduce il pieno supporto ai valori inline separati da
virgola per i flag `--resolvers` e `--domains`.

##### Nuove capacità

1. **resolver inline**: `--resolvers "1.1.1.1,8.8.8.8,9.9.9.9"`
2. **domini inline**: `--domains "google.com,github.com"`
3. **valori singoli**: `--resolvers "1.1.1.1"` oppure `--domains "google.com"`
4. **resolver per nome**: `--resolvers "cloudflare,google,quad9"`
5. **input misto**: `--resolvers "1.1.1.1,cloudflare,8.8.8.8"`

##### Retrocompatibilità

- tutte le configurazioni esistenti basate su file continuano a funzionare
- nessuna modifica incompatibile alla cli
- il rilevamento del file ha priorità sull'interpretazione inline

##### Esempi di utilizzo

###### Prima (funzionavano solo i file)

```bash
net-benchmark dns benchmark \
    --resolvers data/resolvers.json \
    --domains data/domains.txt
```

###### Adesso (funzionano entrambi)

```bash
# Inline (New)
net-benchmark dns benchmark \
    --resolvers "1.1.1.1,8.8.8.8,9.9.9.9" \
    --domains "google.com,github.com" \
    --timeout 10 \
    --retries 3 \
    --formats csv \
    --output ./troubleshooting

# Files (STILL WORKS)
net-benchmark dns benchmark \
    --resolvers data/resolvers.json \
    --domains data/domains.txt \
    --formats csv
```

###### Resolver per nome

```bash
net-benchmark dns benchmark \
    --resolvers "Cloudflare,Google,Quad9" \
    --domains "google.com,github.com" \
    --timeout 10 \
    --retries 3 \
    --formats csv \
    --output ./troubleshooting_named
```

###### Input misto

```bash
net-benchmark dns benchmark \
    --resolvers "1.1.1.1,Cloudflare,8.8.8.8" \
    --domains "google.com,github.com" \
    --timeout 10 \
    --retries 3 \
    --formats csv \
    --output ./troubleshooting_mixed
```

###### Valore singolo

```bash
net-benchmark dns benchmark \
    --resolvers "1.1.1.1" \
    --domains "google.com" \
    --timeout 10 \
    --retries 3 \
    --formats csv \
    --output ./troubleshooting
```

#### 🔧 Utility

##### Gestione dei resolver

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

##### Gestione dei domini

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

##### Panoramica delle categorie

```bash
# View all available categories
net-benchmark dns list-categories
```

##### Gestione della configurazione

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

---

#### Guida completa all'utilizzo

##### Test rapido delle prestazioni

```bash
# Basic test with progress bars
net-benchmark dns benchmark --use-defaults

# Quick test with only CSV output
net-benchmark dns benchmark --use-defaults --formats csv --quiet

# Test specific record types
net-benchmark dns benchmark --use-defaults --record-types A,AAAA,MX
```

Flag analitici aggiuntivi:

```bash
# Include domain and record-type analytics and error breakdown
net-benchmark dns benchmark --use-defaults \
  --domain-stats --record-type-stats --error-breakdown
```

Esportazione JSON:

```bash
# Export a machine-readable bundle
net-benchmark dns benchmark --use-defaults --json --output ./results
```

##### Amministratore di rete

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

##### ISP e operatore di rete

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

##### Sviluppatore e DevOps

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

##### Auditor di sicurezza

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

##### IT aziendale

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

#### 🔍 Nuove opzioni della CLI

| Opzione            | Descrizione                                                                 | Esempio                                                                 |
|--------------------|-----------------------------------------------------------------------------|-------------------------------------------------------------------------|
| `--iterations, -i` | Esegue l'intero ciclo di benchmark **N volte**                              | `net-benchmark dns benchmark --use-defaults -i 3`                           |
| `--use-cache`      | Consente il riuso dei risultati in cache fra le iterazioni                  | `net-benchmark dns benchmark --use-defaults -i 3 --use-cache`               |
| `--warmup`         | Esegue un **riscaldamento completo** (tutti i resolver × domini × tipi di record) | `net-benchmark dns benchmark --use-defaults --warmup`                       |
| `--warmup-fast`    | Esegue un **riscaldamento leggero** (una sonda per resolver)                | `net-benchmark dns benchmark --use-defaults --warmup-fast`                  |
| `--include-charts` | Incorpora grafici e diagrammi nei report PDF/Excel per l'analisi visiva delle prestazioni | `net-benchmark dns benchmark --use-defaults --formats pdf,excel --include-charts` |

---

#### ⚡ Comandi della CLI

##### 🚀 Top

Classifica rapidamente i resolver per velocità e affidabilità.

```bash
# Rank resolvers quickly
net-benchmark dns top

# Use custom domain list
net-benchmark dns top -d domains.txt

# Export results to JSON
net-benchmark dns top -o results.json
```

---

##### 📊 Compare

Confronta i resolver affiancati con statistiche di dettaglio.

```bash
# Compare Cloudflare, Google, and Quad9
net-benchmark dns compare Cloudflare Google Quad9

# Compare by IP addresses
net-benchmark dns compare 1.1.1.1 8.8.8.8 9.9.9.9

# Show detailed per-domain breakdown
net-benchmark dns compare Cloudflare Google --show-details

# Export results to CSV
net-benchmark dns compare Cloudflare Google -o results.csv
```

---

##### 🔄 Monitoring

Monitora in continuo le prestazioni dei resolver con avvisi.

```bash
# Monitor default resolvers continuously (every 60s)
net-benchmark dns monitoring --use-defaults

# Monitor with custom resolvers and domains
net-benchmark dns monitoring -r resolvers.json -d domains.txt

# Run monitoring for 1 hour with alerts
net-benchmark dns monitoring --use-defaults --interval 30 --duration 3600 \
  --alert-latency 150 --alert-failure-rate 5 --output monitor.log
```

---

##### 🌟 Panoramica dei comandi

| Comando      | Scopo | Caso d'uso tipico | Opzioni principali | Output |
|--------------|---------|------------------|-------------|--------|
| **top**      | Classifica rapida dei resolver per velocità e affidabilità | Verifica veloce di quale resolver sia il migliore in questo momento | `--domains`, `--record-types`, `--output` | Elenco ordinato di resolver con latenza e tasso di successo |
| **compare**  | Confronto affiancato di resolver specifici | Benchmarking dettagliato sui resolver/domini scelti | `--domains`, `--record-types`, `--iterations`, `--output`, `--show-details` | Tabella dei resolver con latenza, tasso di successo e ripartizione per dominio |
| **monitoring** | Monitoraggio continuo con avvisi | Tracciamento in tempo reale delle prestazioni dei resolver | `--interval`, `--duration`, `--alert-latency`, `--alert-failure-rate`, `--output`, `--use-defaults` | Indicatori di stato live, avvisi, file di log opzionale |

---

#### 📊 Miglioramenti dell'analisi

- **Numero di iterazioni**: mostrato quando viene eseguita più di un'iterazione.  
- **Hit di cache**: indica quante query sono state servite dalla cache (quando `--use-cache` è attivo).  
- **Tracciamento dei fallimenti**: i resolver con errori ripetuti vengono conteggiati e possono essere ispezionati con `get_failed_resolvers()`.  
- **Statistiche della cache**: disponibili tramite `get_cache_stats()`, che mostra il numero di voci in cache e se la cache è abilitata.  
- **Risultati del riscaldamento**: le query di warmup sono marcate con `iteration=0` nei dati grezzi, così è facile escluderle in analisi.  

Esempio di output riepilogativo:

```markdown

=== BENCHMARK SUMMARY ===
Total queries: 150
Successful: 140 (93.33%)
Average latency: 212.45 ms
Median latency: 198.12 ms
Fastest resolver: Cloudflare
Slowest resolver: Quad9
Iterations: 3
Cache hits: 40 (26.7%)
```

#### ⚡ Buone pratiche

| Modalità        | Flag consigliati                                                                  | Scopo                                                                   |
|-----------------|------------------------------------------------------------------------------------|-------------------------------------------------------------------------|
| **Esecuzione rapida**   | `--iterations 1 --timeout 1 --retries 0 --warmup-fast`                     | Feedback veloce, pochi ritentativi, riscaldamento leggero. Buona per controlli rapidi. |
| **Esecuzione approfondita**| `--iterations 3 --use-cache --warmup --timeout 5 --retries 2`           | Passaggi multipli, cache attiva, riscaldamento completo. Ideale per benchmarking dettagliato. |
| **Modalità debug**  | `--iterations 1 --timeout 10 --retries 0 --quiet`                              | Timeout lungo, nessun ritentativo, output minimo. Utile per diagnosticare problemi dei resolver. |
| **Esecuzione bilanciata**| `--iterations 2 --use-cache --warmup-fast --timeout 2 --retries 1`        | Una via di mezzo: velocità moderata, qualche ritentativo, cache attiva, riscaldamento rapido. |

#### ⚙️ File di configurazione

##### Formato JSON dei resolver

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
    }
  ]
}
```

##### Formato del file di testo dei domini

```txt
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

---

#### Ottimizzazione delle prestazioni

```bash
# Large-scale testing (1000+ queries)
net-benchmark dns benchmark \
  --resolvers data/many_resolvers.json \
  --domains data/many_domains.txt \
  --max-concurrent 50 \
  --timeout 3 \
  --quiet \
  --formats csv

# Unstable networks
net-benchmark dns benchmark \
  --resolvers data/backup_resolvers.json \
  --domains data/critical_domains.txt \
  --timeout 10 \
  --retries 3 \
  --max-concurrent 10

# Quick diagnostics
net-benchmark dns benchmark \
  --resolvers "1.1.1.1,8.8.8.8" \
  --domains "google.com,cloudflare.com" \
  --formats csv \
  --quiet \
  --timeout 2
```

---

#### Risoluzione dei problemi

```bash
# Command not found
pip install -e .
net-benchmark dns --help

# PDF generation fails (Ubuntu/Debian) – see [PDF dependencies](#pdf-dependencies)
sudo apt-get install libcairo2 libpango-1.0-0 libpangocairo-1.0-0 \
  libgdk-pixbuf2.0-0 libffi-dev shared-mime-info
# Or skip PDF
net-benchmark dns benchmark --use-defaults --formats csv,excel

# Network timeouts
net-benchmark dns benchmark --use-defaults --timeout 10 --retries 3
net-benchmark dns benchmark --use-defaults --max-concurrent 25
```

##### Modalità debug

```bash
# Verbose run
net-benchmark dns benchmark --use-defaults --formats csv

# Minimal configuration
net-benchmark dns benchmark --resolvers "1.1.1.1" --domains "google.com" --formats csv
```

---

#### Automazione e CI

##### Job cron

```bash
# Daily monitoring
0 2 * * * /usr/local/bin/net-benchmark dns benchmark --use-defaults --formats csv --quiet --output /var/log/net_benchmark/daily_$(date +\%Y\%m\%d)

# Time-based variability (every 6 hours)
0 */6 * * * /usr/local/bin/net-benchmark dns benchmark --use-defaults --formats csv --quiet --output /var/log/net_benchmark/$(date +\%Y\%m\%d_\%H)
```

##### Esempio con GitHub Actions

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

---

#### Screenshot

Colloca le immagini in `src/net_benchmark/dns_benchmark/docs/screenshots/`:

- `src/net_benchmark/dns_benchmark/docs/screenshots/cli_run.png`
- `src/net_benchmark/dns_benchmark/docs/screenshots/excel_report.png`
- `src/net_benchmark/dns_benchmark/docs/screenshots/pdf_summary.png`
- `src/net_benchmark/dns_benchmark/docs/screenshots/pdf_charts.png`
- `src/net_benchmark/dns_benchmark/docs/screenshots/excel_charts.png`
- `src/net_benchmark/dns_benchmark/docs/screenshots/real_time_monitoring.png`

##### 1. Esecuzione del benchmark da CLI

[![CLI Benchmark Run](src/net_benchmark/dns_benchmark/docs/screenshots/cli_run.png)](https://github.com/net-benchmark/net-benchmark)

##### 2. Report Excel prodotto

[![Excel Report Output](src/net_benchmark/dns_benchmark/docs/screenshots/excel_report.png)](https://github.com/net-benchmark/net-benchmark)

##### 3. Sintesi esecutiva in PDF

[![PDF Executive Summary](src/net_benchmark/dns_benchmark/docs/screenshots/pdf_summary.png)](https://github.com/net-benchmark/net-benchmark)

##### 4. Grafici PDF

[![PDF Charts](src/net_benchmark/dns_benchmark/docs/screenshots/pdf_charts.png)](https://github.com/net-benchmark/net-benchmark)

##### 5. Grafici Excel

[![Excel Charts](src/net_benchmark/dns_benchmark/docs/screenshots/excel_charts.png)](https://github.com/net-benchmark/net-benchmark)

##### 6. Monitoraggio in tempo reale

[![Real Time Monitoring](src/net_benchmark/dns_benchmark/docs/real_time_tracking.gif)](https://github.com/net-benchmark/net-benchmark)

#### Ottenere aiuto

```bash
net-benchmark dns --help
net-benchmark dns benchmark --help
net-benchmark dns top --help
net-benchmark dns compare --help
net-benchmark dns monitoring --help
net-benchmark dns list-defaults --help
net-benchmark dns list-resolvers --help
net-benchmark dns list-domains --help
net-benchmark dns list-categories --help
net-benchmark dns generate-config --help
```

Scenari comuni:

```bash
# I'm new — where to start?
net-benchmark dns list-defaults
net-benchmark dns benchmark --use-defaults

# Test specific resolvers
net-benchmark dns list-resolvers --category security
net-benchmark dns benchmark --resolvers data/security_resolvers.json --domains data/domains.txt

# Generate a management report
net-benchmark dns benchmark --use-defaults --formats excel,pdf \
  --domain-stats --record-type-stats --error-breakdown --json \
  --output ./management_report
```

---

#### ❓ Domande frequenti

<details>
<summary><b>Perché il DNS del mio ISP non è il più veloce?</b></summary>

Il DNS locale dell'ISP ha spesso un vantaggio di caching, ma può mancare di:
- Rete anycast globale (più lento per i domini distanti)
- Validazione DNSSEC
- Funzionalità di privacy (DoH/DoT)
- Garanzie di affidabilità

Prova entrambi e decidi in base alle TUE priorità!

</details>

<details>
<summary><b>Ogni quanto dovrei fare il benchmark del DNS?</b></summary>

- **Una tantum**: quando scegli il fornitore DNS
- **Ogni mese**: per i controlli di salute della rete
- **Prima di una migrazione**: quando cambi fornitore
- **Dopo un problema**: per diagnosticare le prestazioni

</details>

<details>
<summary><b>Posso testare il mio server DNS?</b></summary>

Sì! Basta aggiungerlo a un file JSON di resolver personalizzato:

```json
{
  "resolvers": [
    {"name": "My DNS", "ip": "192.168.1.1"}
  ]
}
```

</details>

<details>
<summary><b>Questo strumento è sicuro da usare in produzione?</b></summary>

Sì! Lo strumento esegue solo lookup DNS (operazioni di lettura). NON:
- Modifica i record DNS
- Esegue attacchi
- Invia dati a server esterni

Tutti i test sono normali query DNS che qualsiasi resolver gestisce ogni giorno.

</details>

<details>
<summary><b>Perché i risultati variano da un'esecuzione all'altra?</b></summary>

Le prestazioni DNS variano a causa di:
- Condizioni di rete
- Caching DNS (del resolver e degli intermediari)
- Carico del server
- Cambiamenti nell'instradamento geografico

Esegui più iterazioni (`--iterations 5`) per risultati più stabili.

</details>

</details>

---

### Benchmark HTTP

<details open>
<summary><strong>Benchmark HTTP</strong> — latenza, TTFB, header di sicurezza, fingerprinting CDN, certificati TLS</summary>

#### 🎯 Perché questo strumento?

Ogni richiesta HTTP nasconde una dozzina di segnali di prestazioni e sicurezza — DNS, TCP, TLS, redirect, compressione, caching, instradamento CDN e software del server.  
La maggior parte degli strumenti misura solo la latenza totale. net‑benchmark ti dà il quadro completo.

##### Il problema

- ⏱️ **Colli di bottiglia nascosti** — il ritardo è nel DNS, nel TCP, nel TLS o nel server stesso?
- 🔗 **Redirect silenziosi** — ogni hop aggiunge latenza che non vedi senza i tempi per singolo hop
- 🔒 **Header di sicurezza mancanti** — CSP, HSTS, X‑Frame‑Options spesso assenti
- 🕵️ **CDN sconosciuta** — quale CDN sta davvero servendo il tuo traffico?
- 📜 **Certificati scaduti** — difficili da intercettare prima che rompano la produzione

##### La soluzione

net‑benchmark ti aiuta a:

- 🔍 **Scomporre ogni richiesta** — DNS → TCP → TLS → TTFB → TTLB, tutto in millisecondi
- 📊 **Ottenere statistiche reali** — P95, P99, jitter, punteggi di consistenza
- 🛡️ **Verificare la sicurezza** — HSTS, CSP, X‑Frame‑Options, fingerprinting CDN, fughe di informazioni dall'header Server
- 📜 **Catturare i certificati TLS** — giorni alla scadenza, CN, emittente, SAN, rilevamento wildcard
- 🚀 **Testare su larga scala** — oltre 50 richieste concorrenti in pochi secondi

##### Ideale per

- ✅ **Sviluppatori** che ottimizzano le prestazioni delle API
- ✅ **DevOps/SRE** che validano gli SLA di CDN e server di origine
- ✅ **Ingegneri della sicurezza** che verificano gli header di sicurezza HTTP e l'igiene TLS
- ✅ **Fornitori di API** che misurano endpoint con autenticazione, header e payload nel corpo

---

#### Avvio rapido

```bash
# Test 5 built‑in targets with a single iteration
net-benchmark http benchmark --use-defaults
```

I risultati vengono salvati automaticamente in `./benchmark_results/` con un CSV riepilogativo, i dati grezzi di dettaglio e report PDF/Excel opzionali.

```bash
# First‑run recommendations
net-benchmark http benchmark --use-defaults --formats csv,excel
net-benchmark http benchmark --use-defaults --iterations 5   # meaningful jitter/consistency
```

---

#### ⚡ Comandi a colpo d'occhio

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

# Compare two APIs side‑by‑side
net-benchmark http compare api.example.com api2.example.com --iterations 3 --show-details

# Monitor with alerts for 1 hour
net-benchmark http monitoring --use-defaults \
  --interval 30 --duration 3600 \
  --alert-latency 500 --alert-failure-rate 5

# Load-test an endpoint to find its throughput ceiling
net-benchmark http load-test -t https://api.example.com/health --mode throughput --duration 30 --max-concurrency 300
```

---

#### ✨ Funzionalità principali

##### 🚀 Prestazioni

- **Motore asincrono** — httpx con HTTP/2, pooling delle connessioni, concorrenza a semaforo
- **Scomposizione dei tempi** — risoluzione DNS, connessione TCP, handshake TLS, TTFB, TTLB, latenza totale
- **Iterazioni multiple** — ripeti i benchmark più volte per accuratezza statistica
- **Analisi statistica** — media, mediana, P95, P99, jitter, punteggio di consistenza
- **Ritentativi con backoff** — backoff esponenziale sui fallimenti (come nel motore DNS)
- **Concorrenza configurabile** — controlla il numero massimo di richieste concorrenti
- **Fase di riscaldamento** — warmup opzionale con HEAD o completo prima della misurazione

##### 🔒 Sicurezza e TLS

- **Audit degli header di sicurezza** — HSTS, CSP, X‑Frame‑Options, X‑Content‑Type‑Options, Referrer‑Policy, Permissions‑Policy
- **Fingerprinting CDN** — rileva Cloudflare, CloudFront, Fastly, Akamai, Google, Azure CDN
- **Rilevamento di fughe dall'header Server** — segnala la divulgazione di software e versione
- **Cattura inline dei certificati TLS** — giorni alla scadenza, CN, emittente, SAN, rilevamento wildcard
- **Rilevamento dei downgrade** — catene di redirect HTTPS→HTTP e fallback HTTP/2→HTTP/1.1
- **IPv4 vs IPv6** — rilevamento dual‑stack per richiesta
- **Rilevamento Alt‑Svc** — server che annuncia HTTP/3

##### 🔐 Autenticazione ed enterprise

- **Basic auth, token Bearer, API key personalizzata** — `--auth basic:user:pass`, `--auth bearer:token`, `--headers x-api-key:key`
- **Certificati client mTLS** — `--cert` + `--cert-key`
- **Supporto proxy** — `--proxy http://proxy:8080`
- **Override SNI** — `--sni example.com`
- **Binding sull'interfaccia** — `--local-address 192.168.1.100`
- **Iniezione dell'ID di richiesta** — `--inject-request-id` aggiunge l'header X‑Request‑ID
- **User‑Agent personalizzato** — `--user-agent "MyBot/1.0"`
- **Cookie** — flag `--cookie "name=value"` ripetibile

##### 🧪 Asserzioni e validazione

- **Asserzione sul codice di stato** — `--assert status=200`
- **Asserzione sul contenuto del corpo** — `--assert body_contains=success`
- **Asserzione sull'esistenza di un header** — `--assert header_exists=X-Cache`
- **Asserzione sul valore di un header** — `--assert header_value=X-Cache=HIT`
- **Asserzione sulla latenza massima** — `--assert max_latency=500`
- **Asserzione sul content‑type** — `--assert content_type=application/json`
- **Asserzione sulla dimensione della risposta** — `--assert response_size_min=100`, `--assert response_size_max=10000`

##### 📊 Analisi ed esportazione

- **Formati multipli** — CSV, Excel, PDF, JSON (vedi [Formati di esportazione](#formati-di-esportazione))
- **Report visivi** — grafici e diagrammi in Excel/PDF
- **Statistiche per target** — latenza, TTFB, tasso di HTTP/2, tasso di redirect, dimensione compressa
- **Analisi degli header di cache** — presenza di Cache‑Control, ETag, Last‑Modified, Age
- **Distribuzione dei codici di stato** — ripartizione 2xx/3xx/4xx/5xx
- **Ripartizione degli errori** — individua i target problematici

---

#### 🔧 HTTP/2, redirect e rilevamento dei downgrade

| Funzionalità | Cosa cattura |
|---|---|
| Negoziazione HTTP/2 | Risultato ALPN (`h2` o `http/1.1`) per richiesta |
| Rilevamento del downgrade HTTP/2 | Segnala quando ci si aspettava HTTP/2 ma è stato negoziato HTTP/1.1 |
| Catena di redirect | Elenco completo degli hop con URL, codice di stato e durata per ciascuno |
| Rilevamento dei downgrade | Segnala qualsiasi redirect HTTPS→HTTP nella catena |
| Dimensione compressa | Header Content‑Length catturato per l'analisi della banda |

```bash
# Force HTTP/1.1 to compare performance
net-benchmark http benchmark --use-defaults --no-http2

# Watch redirect chains
net-benchmark http benchmark --targets https://github.com --iterations 1

# Detect HTTP/2 downgrades (useful behind corporate proxies)
net-benchmark http benchmark --use-defaults --iterations 3
```

---

#### 🔒 Esempi di sicurezza e autenticazione

```bash
# Basic auth
net-benchmark http benchmark \
  --targets https://httpbin.org/basic-auth/user/pass \
  --auth "basic:user:pass"

# Bearer token (standard OAuth2)
net-benchmark http benchmark \
  --targets https://api.example.com/data \
  --auth "bearer:sk-abc123"

# Custom API key header (x‑api‑key)
net-benchmark http benchmark \
  --targets https://api.example.com/echo \
  --method POST \
  --headers "x-api-key:sk-abc123"

# mTLS client certificate
net-benchmark http benchmark \
  --targets https://mtls.example.com \
  --cert client.pem --cert-key client-key.pem

# Proxy with credentials
# (--auth authenticates to the ORIGIN, not the proxy — put proxy
#  credentials in the proxy URL itself)
net-benchmark http benchmark \
  --targets https://example.com \
  --proxy http://proxyuser:proxypass@proxy:8080
```

---

#### 💼 Casi d'uso

##### 🔧 Per sviluppatori: ottimizzare le prestazioni delle API

```bash
# Find fastest endpoint and break down timing
net-benchmark http benchmark \
  --targets https://api.myapp.com/v1/users,https://api.myapp.com/v2/users \
  --method GET \
  --headers "Authorization:Bearer token" \
  --iterations 5
```

**Risultato:** individua con precisione se il collo di bottiglia è il DNS, il TCP, il TLS o la logica del server.

---

##### 🛡️ Per DevOps/SRE: validare una migrazione CDN

```bash
# Compare old origin vs new CDN
net-benchmark http compare \
  https://origin.example.com \
  https://cdn.example.com \
  --iterations 5 --show-details
```

**Risultato:** prova basata sui dati che la tua CDN è (o non è) più veloce.

---

##### 🔐 Per ingegneri della sicurezza: verificare gli endpoint pubblici

```bash
# Full security audit with assertions
net-benchmark http benchmark \
  --targets https://www.example.com,https://api.example.com \
  --assert status=200 \
  --assert header_exists=strict-transport-security \
  --assert header_value=X-Content-Type-Options=nosniff \
  --formats excel,pdf \
  --output ./security_audit
```

**Risultato:** pagella immediata della copertura degli header di sicurezza e dello stato dei certificati TLS.

---

##### 🏢 Per l'enterprise: controlli di salute automatizzati

```bash
# Add to crontab for hourly reports
0 * * * * net-benchmark http benchmark \
  --targets targets.txt \
  --assert status=200 --assert max_latency=1000 \
  --formats csv --quiet \
  --output /var/reports/http/$(date +\%Y\%m\%d_\%H)
```

**Risultato:** conformità agli SLA automatizzata e andamento delle prestazioni nel tempo.

---

#### 📖 Esempi di utilizzo

##### Utilizzo di base

```bash
# Test built‑in defaults
net-benchmark http benchmark --use-defaults

# Custom targets from file
net-benchmark http benchmark --targets ./targets.txt

# Inline targets (comma‑separated)
net-benchmark http benchmark --targets "https://example.com,https://httpbin.org/get"

# Quick test with only CSV output
net-benchmark http benchmark --use-defaults --formats csv --quiet

# Multiple iterations for statistical accuracy
net-benchmark http benchmark --use-defaults --iterations 5

# Custom HTTP method with body
net-benchmark http benchmark \
  --targets https://api.example.com/echo \
  --method POST \
  --body '{"action":"test"}'

# Body from file
echo '{"name":"test","value":42}' > payload.json
net-benchmark http benchmark \
  --targets https://api.example.com/echo \
  --method POST \
  --body-file payload.json
```

##### Utilizzo avanzato

```bash
# Export all formats with charts
net-benchmark http benchmark \
  --use-defaults \
  --formats csv,excel,pdf \
  --include-charts \
  --json \
  --output ./full_report

# Separate timeout control
net-benchmark http benchmark \
  --targets https://slow-api.example.com \
  --connect-timeout 5 --read-timeout 30 --write-timeout 10

# Query parameters without hacking the URL
net-benchmark http benchmark \
  --targets https://api.example.com/search \
  --params "page=1,limit=50,q=test"

# High concurrency with warmup
net-benchmark http benchmark \
  --use-defaults \
  --max-concurrent 100 \
  --warmup-fast \
  --iterations 3

# Full assertion suite
net-benchmark http benchmark \
  --targets https://api.example.com/health \
  --assert status=200 \
  --assert body_contains=ok \
  --assert max_latency=500 \
  --assert content_type=application/json \
  --assert response_size_min=10
```

##### Integrazione CI/CD

```yaml
- name: HTTP Endpoint Health Check
  run: |
    pip install net-benchmark
    net-benchmark http benchmark \
      --targets "https://api.prod.example.com/health,https://web.prod.example.com" \
      --assert status=200 \
      --assert max_latency=1000 \
      --formats csv \
      --quiet
```

---

#### ⚡ Comandi della CLI

##### 🚀 Top

Classifica rapidamente i target per velocità o affidabilità.

```bash
# Rank default targets by latency
net-benchmark http top --use-defaults --limit 5

# Rank by TTFB
net-benchmark http top --use-defaults --limit 5 --metric ttfb

# Rank by success rate
net-benchmark http top --targets targets.txt --limit 10 --metric success
```

---

##### 📊 Compare

Misura target specifici affiancati con statistiche di dettaglio.

```bash
# Compare two targets
net-benchmark http compare https://example.com https://httpbin.org/get

# Auto‑scheme (https:// added if missing)
net-benchmark http compare api.example.com api2.example.com

# With auth and iterations
net-benchmark http compare api.example.com api2.example.com \
  --auth "bearer:token" --iterations 5

# Show per‑iteration breakdown
net-benchmark http compare api.example.com api2.example.com \
  --iterations 3 --show-details

# Export comparison
net-benchmark http compare api.example.com api2.example.com \
  --output comparison.csv
```

---

##### 🔄 Monitoring

Monitora in continuo i target con avvisi configurabili.

```bash
# Monitor defaults every 60 seconds
net-benchmark http monitoring --use-defaults

# Monitor with custom targets and alerts
net-benchmark http monitoring \
  --targets targets.txt \
  --interval 30 \
  --duration 3600 \
  --alert-latency 500 \
  --alert-failure-rate 5 \
  --output ./monitoring_logs

# Page only on unreachable origins, not on a legitimate 403
net-benchmark http monitoring \
  --targets https://internal-api.example.com \
  --expected-status 200,403 \
  --alert-transport-error-rate 5 \
  --interval 60
```

> `http monitoring` non ha `--proxy`. Il supporto proxy si trova su `http benchmark`
> e `http compare`.

---

#### ⚡ Test di carico

`net-benchmark http load-test` genera traffico prolungato verso uno o più
target HTTP usando tre strategie di modellazione del carico. A differenza di
`benchmark` (numero fisso di iterazioni), load-test resta in esecuzione per una
durata e riporta il throughput ottenuto, i percentili di latenza e il
comportamento a livello di connessione.

Dalla **0.5.2** il carico può essere generato anche da più worker paralleli —
processi separati sulla stessa macchina, o macchine del tutto distinte — con
avvio sincronizzato e unione statisticamente corretta.

> Riferimento completo: **[HTTP Load Testing](https://net-benchmark.readthedocs.io/en/latest/it/http-load-test.html)**

##### Modalità

| Modalità     | Cosa fa                                           | Caso d'uso                        |
|--------------|----------------------------------------------------|------------------------------------|
| `throughput` | Satura il target fino a `--max-concurrency`        | Trovare il tetto massimo           |
| `sustained`  | Mantiene un `--rps` fisso per `--duration`         | Validazione di SLA / capacità      |
| `ramp-up`    | Aumenta la concorrenza a gradini, poi la mantiene al picco | Trovare gradualmente il punto di rottura |

##### Esempi

**Throughput — quanto può spingere questo endpoint?**
```bash
net-benchmark http load-test \
  -t https://api.staging.example.com/health \
  --mode throughput \
  --duration 30 \
  --max-concurrency 300 \
  --formats csv,excel \
  --include-charts
```

**Sustained — validare un obiettivo di capacità fisso**
```bash
net-benchmark http load-test \
  -t https://checkout.example.com/api/cart \
  --mode sustained \
  --rps 150 \
  --duration 300 \
  --formats csv,excel,json
```
`--rps` è obbligatorio in modalità sustained — la CLI fallisce subito con un
messaggio chiaro se manca.

**Ramp-up — trovare dove le cose iniziano a rompersi**
```bash
net-benchmark http load-test \
  -t https://api.example.com/search \
  --mode ramp-up \
  --start-concurrency 5 \
  --ramp-concurrency 500 \
  --ramp-duration 120 \
  --hold-duration 60 \
  --max-total-rps 1000 \
  --formats csv,excel,pdf
```
`--max-total-rps` è un *tetto di sicurezza*, non una frequenza obiettivo — usa
`sustained` se vuoi una frequenza fissa. Esiste perché contro target molto
veloci (localhost, sidecar di service mesh) nient'altro limita la frequenza
delle richieste. Il valore predefinito è `ramp-concurrency * 50`, di norma
abbastanza generoso da non scattare mai contro servizi realmente limitati dalla rete.

**Confrontare più target (per es. canary vs. stable)**
```bash
net-benchmark http load-test \
  -t https://api-v1.example.com,https://api-v2.example.com \
  --mode sustained --rps 100 --duration 120 \
  --formats excel --include-charts
```
Ogni target viene eseguito in parallelo nel proprio pool di connessioni.
L'esportazione Excel produce un foglio di confronto più fogli per target con le
richieste grezze e la timeline.

**Diagnostica di protocollo/trasporto sotto carico**
```bash
net-benchmark http load-test \
  -t https://cdn.example.com/asset.js \
  --mode throughput --duration 60 --max-concurrency 200 \
  --enable-tls-resumption --enable-push-detection \
  --formats json
```
Il riuso delle connessioni viene sempre tracciato e non richiede alcun flag —
`--enable-connection-reuse` è deprecato e non ha alcun effetto. Gli altri due
rilevamenti sono opzionali, perché aggiungono contabilità per ogni richiesta:
attivali solo quando stai davvero indagando sulla ripresa di sessione TLS o sul
comportamento del push HTTP/2.

##### Come leggere i risultati

| Metrica | Significato |
|---|---|
| **Achieved RPS** | Richieste *completate* nella finestra di esecuzione. Averne chieste 400 e ottenute 180 significa che il target non riesce a stare al passo. |
| **Avg blocked** | Attesa di uno slot di connessione libero. Lato **tuo**. |
| **Avg waiting** | Attesa della risposta del server. Lato **loro**. |

`blocked` che cresce mentre `waiting` resta piatto è il segnale più utile
dell'output: stai misurando il tuo generatore di carico anziché il target. È
esattamente il problema che `--workers` esiste per risolvere.

##### Generazione distribuita del carico (0.5.2)

Un singolo processo Python — un GIL, un event loop, un pool di connessioni — è
spesso il collo di bottiglia molto prima del target. `--workers` genera il
carico da N **processi separati**, avviati contro una barriera condivisa di
orologio di sistema e uniti alla fine.

```bash
# Baseline: one process.
net-benchmark http load-test -t https://api.example.com/health \
  --mode throughput --duration 20 --max-concurrency 50

# Four processes. --max-concurrency is PER WORKER: 200 in flight overall.
net-benchmark http load-test -t https://api.example.com/health \
  --mode throughput --duration 20 --max-concurrency 50 --workers 4
```

Aspettati una pausa di circa 5 s prima che partano le richieste — è la barriera
di avvio, dimensionata perché ogni interprete generato abbia finito di importare prima che l'esecuzione inizi.

- Gli RPS scalano con il numero di worker e `blocked` resta piatto → il singolo
  processo era il tetto, e l'hai rimosso.
- RPS piatti, `waiting` che cresce → il target è saturo. È un risultato, non un fallimento.
- RPS piatti, `blocked` che cresce → un limite della macchina (NIC, CPU, porte).
  I processi sfuggono al GIL, non alla scheda di rete.

**Ripartizione della frequenza.** `--rps` è il **totale** dell'esecuzione e viene diviso fra i worker:

```bash
# 4 workers pace 100 RPS each; the merged summary reports 400.
net-benchmark http load-test -t https://api.example.com/cart \
  --mode sustained --rps 400 --duration 30 --workers 4 --max-backlog 20
```

**Topologie dei target.** Con più target, `--target-distribution` decide che
cosa moltiplica `--workers` — e cambia il significato di `--rps`:

| Valore | Comportamento | `--rps` è | Da usare quando |
|---|---|---|---|
| `replicate` (predefinito) | Ogni worker esegue ogni target | il **totale** dell'esecuzione, suddiviso | Vuoi saturare una sola origine |
| `shard` | I target sono distribuiti round-robin, uno per worker | **per target**, non diviso | Vuoi misurare più target in parallelo |

##### Su più macchine (0.5.2)

La generazione multi-processo elimina il GIL e il singolo event loop. Non
elimina la NIC, né il fatto che tutto il traffico parta da un solo punto. Per
avere traffico che arriva davvero da più regioni, esegui un nodo per regione
contro una barriera condivisa e poi unisci i risultati.

```bash
# 1. Pick the barrier — prints the epoch to paste onto every node.
net-benchmark http load-test -t https://example.com \
  --duration 60 --start-delay 120 --quiet
# [i]   Start barrier: 1754320000.000 (epoch seconds, UTC)

# 2. Every node: IDENTICAL --start-at, its own labels and rate share.
net-benchmark http load-test -t https://example.com \
  --mode sustained --rps 250 --duration 60 \
  --start-at 1754320000.000 --warmup 10 \
  --worker-id hel1 --region eu-north \
  --emit-summary hel1.json --formats csv

# 3. Collect and merge.
net-benchmark http merge-load-test ./nodes/*.json \
  -o ./merged --threshold 'p95_latency<500'
```

I percentili vengono ricalcolati dall'istogramma di latenza unito. Mediare i
valori P95 di più nodi non dà il P95 della loro unione — è un numero diverso,
non un'approssimazione.

L'esecuzione su ciascun nodo scrive comunque le proprie esportazioni locali;
`--formats` su `load-test` richiede almeno un formato e non può essere
svuotato. Il file che conta per l'unione è quello indicato da `--emit-summary`
— tieni ristretto il `--formats` del nodo (`csv`) invece di provare a disattivare le esportazioni.

`--warmup` apre le connessioni *prima* della barriera: senza di esso un avvio
sincronizzato è un avvio a freddo sincronizzato e i primi secondi misurano gli
handshake TLS. Dove lo scostamento di orologio è stato misurato, l'unione viene
rifiutata oltre i 50 ms di deriva — il fatto che i nodi concordino su un epoch
dimostra solo che è stato *comunicato* loro lo stesso valore.

##### Soglie pass/fail (CI)

Vengono interpretate *prima* che l'esecuzione inizi, nome della metrica
compreso, così un refuso costa un secondo anziché un intero test di carico.

```bash
net-benchmark http load-test \
  -t https://staging.example.com/api/health \
  --mode sustained --rps 200 --duration 60 \
  --workers 4 --max-backlog 50 --warmup 10 \
  --expected-status 200,404 \
  --threshold 'p95_latency<400' \
  --threshold 'success_rate>99.5' \
  --threshold 'dropped_rate<1'
```

I percentili sopravvivono a un'unione. Le metriche di dispersione e di tempi per
fase (`std_latency`, `jitter`, `consistency_score`, `p95_ttfb_ms`,
`p95_duration_ms`, `p95_blocked_ms`, `p95_waiting_ms`) no, e vengono
**rifiutate su un'esecuzione unita** anziché passare contro uno zero strutturale.
Restano esatte con `--workers 1` e per singolo worker in `*_workers.csv`.

##### Formati di output

| Formato | Contenuti                                                    |
|---------|----------------------------------------------------------------|
| `csv`   | Risultati grezzi, riepilogo, riepilogo per worker, timeline per intervallo, ripartizione degli errori, istogramma delle latenze |
| `excel` | Foglio di confronto + fogli per target con dati grezzi/timeline, grafici opzionali |
| `pdf`   | Report con grafici (richiede `pip install net-benchmark[pdf]`) |
| `json`  | Bundle strutturato completo, tutti i target                    |

> **Nota:** l'esportazione PDF fallisce in modo non bloccante — se `weasyprint`
> non è installato, l'esecuzione si completa comunque e gli altri formati
> vengono comunque scritti; controlla nell'output della CLI la presenza di `PDF export failed`.

##### Limiti e insidie

- **I flag di concorrenza sono per worker.** `--workers 4 --max-concurrency 50`
  significa 200 richieste in volo; lo stesso vale per `--max-backlog` e
  `--max-total-rps`. `--rps` è l'eccezione sotto `replicate`.
- **Le righe grezze per richiesta non sopravvivono a `--workers > 1`.**
  `*_raw.csv` e i fogli Excel per target restano vuoti indipendentemente da
  `--no-retain-results`. Tutte le statistiche, gli intervalli e gli istogrammi sopravvivono.
- **`--live` funziona solo con un worker.** La callback non può essere inviata a
  un processo generato; sopra un worker la CLI avvisa anziché non stampare nulla in silenzio.
- **I worker che verranno uniti devono concordare su `--interval-bucket`.**
  Larghezze non corrispondenti vengono rifiutate.
- **Un worker morto significa carico mai offerto.** I fallimenti sono riportati
  per target anziché confluire nel riepilogo unito.

---

#### ⚡ Buone pratiche

| Modalità | Flag consigliati | Scopo |
|---|---|---|
| **Esecuzione rapida** | `--iterations 1 --warmup-fast` | Feedback veloce, riscaldamento leggero |
| **Esecuzione approfondita** | `--iterations 5 --warmup --timeout 10 --retries 2` | Passaggi multipli, riscaldamento completo, ideale per benchmarking dettagliato |
| **Modalità debug** | `--iterations 1 --timeout 30 --retries 0` | Timeout lungo, nessun ritentativo, utile per diagnosticare problemi degli endpoint |
| **Test di API** | `--method POST --body '{}' --headers "Auth:token" --assert status=200` | Invia payload e valida le risposte |

---

#### 📊 Cosa mostra il riepilogo

```text
============================================
| Total requests:   5                      |
| Successful:       4 (80.00%)             |
| Avg latency:      1047.25 ms             |
| Avg TTFB:         772.20 ms              |
| HTTP/2 rate:      100.0%                 |
| HSTS coverage:    60.0%                  |
| Assertion pass:   100.0%                 |
| Fastest target:   https://www.apple.com  |
| Slowest target:   https://www.github.com |
============================================
```

---

#### 🔧 Risoluzione dei problemi

```bash
# Command not found
pip install -e .
net-benchmark http --help

# PDF generation fails (Ubuntu/Debian) – see PDF dependencies
sudo apt-get install libcairo2 libpango-1.0-0 libpangocairo-1.0-0 \
  libgdk-pixbuf2.0-0 libffi-dev shared-mime-info
# Or skip PDF
net-benchmark http benchmark --use-defaults --formats csv,excel

# Network timeouts
net-benchmark http benchmark --use-defaults --timeout 30 --retries 3
net-benchmark http benchmark --use-defaults --max-concurrent 10

# SSL errors on internal servers
net-benchmark http benchmark --targets https://internal.local --no-verify-ssl
```

---

#### Ottenere aiuto

```bash
net-benchmark http --help
net-benchmark http benchmark --help
net-benchmark http top --help
net-benchmark http compare --help
net-benchmark http monitoring --help
net-benchmark http load-test --help
net-benchmark http merge-load-test --help
```

Scenari comuni:

```bash
# I'm new — where to start?
net-benchmark http benchmark --use-defaults

# Test a specific API with auth
net-benchmark http benchmark \
  --targets https://api.example.com/echo \
  --method POST \
  --headers "x-api-key:sk-abc123" \
  --body '{"test":true}'

# Generate a security audit report
net-benchmark http benchmark \
  --targets https://www.example.com \
  --assert status=200 \
  --assert header_exists=strict-transport-security \
  --formats excel,pdf \
  --output ./security_audit
```

---

#### ❓ Domande frequenti

**Perché la mia API è più lenta del previsto?**
La scomposizione dei tempi (DNS → TCP → TLS → TTFB → TTLB) ti dice esattamente dove se ne va il tempo. Se il DNS è lento, controlla il resolver. Se il TLS è lento, controlla la dimensione della catena di certificati o l'OCSP stapling. Se il TTFB è lento, il collo di bottiglia è la logica del server o il database.

**Ogni quanto dovrei misurare gli endpoint HTTP?**
- **Una tantum**: quando scegli una CDN o un fornitore di API
- **Ogni giorno**: per gli endpoint di produzione critici
- **Prima del deploy**: per intercettare regressioni di prestazioni
- **Dopo un incidente**: per validare le correzioni

**Posso testare endpoint protetti da autenticazione?**
Sì — funzionano `--auth basic:user:pass`, `--auth bearer:token` oppure `--headers x-api-key:key`. È supportato anche mTLS tramite `--cert` e `--cert-key`.

**Questo strumento è sicuro da usare in produzione?**
Sì! Esegue solo normali richieste HTTP (operazioni di lettura). Non modifica dati, non esegue attacchi e non invia dati a server esterni.

**Perché i risultati variano da un'esecuzione all'altra?**
Le prestazioni HTTP variano per condizioni di rete, carico del server, cambi di instradamento CDN e ripresa di sessione TLS. Esegui più iterazioni (`--iterations 5`) per risultati più stabili. Usa `--warmup-fast` per assorbire gli effetti di avvio a freddo.

**Qual è la differenza fra `benchmark` e `load-test`?**
`benchmark` esegue un numero fisso di iterazioni per target per ottenere tempi dettagliati per richiesta e header di sicurezza. `load-test` resta in esecuzione per una durata prestabilita con concorrenza o RPS configurabili, per misurare throughput, saturazione e latenza di coda sotto carico prolungato. Usa `benchmark` per audit di prestazioni una tantum; usa `load-test` per il capacity planning e gli stress test.

</details>

---

### Controllo SSL

<details>
<summary><strong>Controllo SSL</strong> — scadenza dei certificati, validazione della catena <em>(in arrivo nella 0.6.0)</em></summary>

#### Funzionalità pianificate

- controllo delle date di scadenza dei certificati
- validazione delle catene di certificati e dei trust store
- monitoraggio di più host con avvisi

> **Stato:** pianificato per la versione 0.6.0 — [i contributi sono benvenuti](CONTRIBUTING.md)

</details>

---

## Formati di esportazione

| formato | flag | note |
|--------|------|-------|
| CSV | `--formats csv` | risultati grezzi + riepilogo + statistiche opzionali per dominio/tipo di record/errore |
| Excel | `--formats excel` | cartella di lavoro formattata con grafici e foglio DNSSEC |
| PDF | `--formats pdf` | richiede `pip install net-benchmark[pdf]` (vedi sotto) |
| JSON | `--json` | payload strutturato completo (flag separato) |

### Output CSV

- Dati grezzi: risultati delle singole query con timestamp e metadati
- Statistiche di riepilogo: metriche aggregate per resolver
- Statistiche per dominio: metriche dominio per dominio (con `--domain-stats`)
- Statistiche per tipo di record: metriche per tipo di record (con `--record-type-stats`)
- Ripartizione degli errori: conteggi per tipo di errore (con `--error-breakdown`)

### Report Excel

- Foglio dei dati grezzi: tutti i risultati delle query con formattazione
- Riepilogo dei resolver: statistiche complete con formattazione condizionale
- Statistiche per dominio: prestazioni dominio per dominio (opzionale)
- Statistiche per tipo di record: prestazioni per tipo di record (opzionale)
- Ripartizione degli errori: conteggi aggregati degli errori (opzionale)
- Analisi delle prestazioni: grafici e analisi comparativa

### Report PDF

- Sintesi esecutiva: risultati chiave e raccomandazioni
- Grafici delle prestazioni: confronto delle latenze; grafico opzionale del tasso di successo
- Classifica dei resolver: ordinata per latenza media
- Analisi dettagliata: approfondimento tecnico con i percentili

### 📄 Esportazione PDF opzionale

Per impostazione predefinita lo strumento supporta le esportazioni **CSV** ed **Excel**.  
L'esportazione PDF richiede la dipendenza aggiuntiva **weasyprint**, che non viene installata automaticamente per evitare problemi di esecuzione su alcune piattaforme.

### Esportazioni specifiche per HTTP

| File CSV | Contenuti |
|----------|----------|
| `*_raw.csv` | Risultati delle singole richieste con scomposizione dei tempi |
| `*_summary.csv` | Statistiche aggregate per target |
| `*_security.csv` | Matrice di presenza degli header di sicurezza |
| `*_ttfb.csv` | Analisi del time‑to‑first‑byte |
| `*_protocols.csv` | Distribuzione HTTP/1.1 vs HTTP/2 |

### Report Excel (HTTP)

- Foglio **Raw Data**: tutte le richieste con tempi, header di sicurezza, dettagli dei certificati
- Foglio **Target Summary**: statistiche complete per target
- Foglio **TTFB Analysis**: percentili del TTFB per target
- Foglio **Security Headers**: matrice di presenza con codifica a colori
- Foglio **Charts**: confronto delle latenze, confronto dei TTFB, tassi di successo (opzionale)

#### Installazione con supporto PDF

```bash
pip install net-benchmark[pdf]
```

#### Utilizzo

Una volta installato, puoi richiedere l'output PDF dalla CLI:

```bash
net-benchmark dns benchmark --use-defaults --formats pdf --output ./results
```

Se `weasyprint` non è installato e richiedi l'output PDF, la CLI mostrerà:

```bash
[-] Error during benchmark: PDF export requires 'weasyprint'. Install with: pip install net-benchmark[pdf]
```

### ⚠️ Configurazione di WeasyPrint (per l'esportazione PDF) {#pdf-dependencies}

Lo strumento usa **WeasyPrint** per generare i report PDF.  
Oltre al pacchetto Python servono alcune librerie di sistema aggiuntive.

#### 🛠 Linux (Debian/Ubuntu)

```bash
sudo apt install python3-pip libpango-1.0-0 libpangoft2-1.0-0 \
  libharfbuzz-subset0 libjpeg-dev libopenjp2-7-dev libffi-dev
```

#### 🛠 macOS (Homebrew)

```bash
brew install pango cairo libffi gdk-pixbuf jpeg openjpeg harfbuzz
```

#### 🛠 Windows

Installa le librerie GTK+ con uno di questi metodi:

- **MSYS2**: [scarica MSYS2](https://www.msys2.org/), poi esegui:

  ```bash
  pacman -S mingw-w64-x86_64-gtk3 mingw-w64-x86_64-libffi
  ```

- **Installer GTK+ a 64 bit**: [scarica il GTK+ Runtime](https://github.com/tschoonj/GTK-for-Windows-Runtime-Environment-Installer/releases) ed esegui l'installer.

Riavvia il terminale dopo l'installazione.

#### ✅ Verifica dell'installazione

Dopo aver installato le librerie di sistema, installa l'extra Python:

```bash
pip install net-benchmark[pdf]
```

Poi esegui:

```bash
net-benchmark dns benchmark --use-defaults --formats pdf --output ./results
```

### Esportazione JSON

- Bundle leggibile da una macchina che include:
  - Statistiche complessive
  - Statistiche dei resolver
  - Risultati grezzi delle query
  - Statistiche per dominio
  - Statistiche per tipo di record
  - Ripartizione degli errori

### Generare una configurazione di esempio

```bash
net-benchmark dns generate-config \
  --category privacy \
  --output my-config.yaml
```

---

## Workflow di rilascio

- **Prerequisiti**
  - **Chiave GPG configurata:** esegui `make gpg-check` per verificare.
  - **Protezione del branch:** main richiede commit firmati e CI verde.
  - **Pubblicazione da CI:** attivata sui tag firmati che corrispondono a vX.Y.Z.

- **Preparare il rilascio (firmato)**
  - **Incremento patch/minor/major:**
  
    ```bash
    make release-patch      # or: make release-minor / make release-major
    ```

    - Aggiorna le versioni.
    - Crea o riusa `release/X.Y.Z`.
    - Effettua un commit firmato e pubblica il branch.
  - **Apri la PR:** da `release/X.Y.Z` verso `main`, poi effettua il merge quando la CI passa.

- **Taggare e pubblicare**
  - **Crea il tag firmato e pubblicalo:**

    ```bash
    make release-tag VERSION=X.Y.Z
    ```

    - Tagga main con `vX.Y.Z` (firmato).
    - La CI pubblica su PyPI.

- **Alternativa manuale**
  - **Crea il branch ed effettua un commit firmato:**
  
    ```bash
    git checkout -b release/manually-update-version-based-on-release-pattern
    git add .
    git commit -S -m "Release release/$NEXT_VERSION"
    git push origin release/$NEXT_VERSION
    ```

  - **Apri la PR ed effettua il merge in main.**
  - **Poi tagga:**
  
    ```bash
    make release-tag VERSION=$NEXT_VERSION
    ```

- **Note**
  - **Commit firmati:** `git commit -S ...`
  - **Tag firmati:** `git tag -s vX.Y.Z -m "Release vX.Y.Z"`
  - **Sorgenti della versione:** `pyproject.toml` e `src/net_benchmark/__init__.py`

---

## Link e supporto

### Ufficiali

- **Documentazione**: [net-benchmark](https://net-benchmark.readthedocs.io/en/latest/it/index.html)

- **GitHub**: [net-benchmark/net-benchmark](https://github.com/net-benchmark/net-benchmark)

- **PyPI**: [net-benchmark](https://pypi.org/project/net-benchmark)

### Community

- **Discussioni**: [GitHub Discussions](https://github.com/net-benchmark/net-benchmark/discussions)
- **Issue**: [Segnalazioni di bug](https://github.com/net-benchmark/net-benchmark/issues)

---

## Contribuire

i contributi sono benvenuti. vedi [CONTRIBUTING.md](CONTRIBUTING.md).
questo progetto adotta un [modello di governance BDFL](GOVERNANCE.md) — @frankovo
ha l'ultima parola sulla direzione tecnica e sui rilasci.

---

## Licenza

MIT © [frankovo](https://github.com/frankovo)

> **Cerchi dns-benchmark-tool?**
> questo progetto ne è il successore. l'originale è archiviato su
> [net-benchmark/dns-benchmark-tool](https://github.com/net-benchmark/dns-benchmark-tool).

---
powered by [buildtools.net](https://buildtools.net) —
dashboard web, test multi-regione e funzionalità enterprise.
