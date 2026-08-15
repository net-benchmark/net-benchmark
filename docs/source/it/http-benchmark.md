# Benchmark HTTP

Latenza, TTFB, header di sicurezza, fingerprinting CDN, certificati TLS.

## Perché questo strumento?

Ogni richiesta HTTP nasconde una dozzina di segnali di prestazioni e sicurezza —
DNS, TCP, TLS, redirect, compressione, caching, instradamento CDN e software del
server. La maggior parte degli strumenti misura solo la latenza totale.
net-benchmark ti dà il quadro completo.

### Il problema

- ⏱️ **Colli di bottiglia nascosti** — il ritardo è nel DNS, nel TCP, nel TLS o nel server stesso?
- 🔗 **Redirect silenziosi** — ogni hop aggiunge latenza che non vedi senza i tempi per singolo hop
- 🔒 **Header di sicurezza mancanti** — CSP, HSTS, X-Frame-Options spesso assenti
- 🕵️ **CDN sconosciuta** — quale CDN sta davvero servendo il tuo traffico?
- 📜 **Certificati scaduti** — difficili da intercettare prima che rompano la produzione

### La soluzione

net-benchmark ti aiuta a:

- 🔍 **Scomporre ogni richiesta** — DNS → TCP → TLS → TTFB → TTLB, tutto in millisecondi
- 📊 **Ottenere statistiche reali** — P95, P99, jitter, punteggi di consistenza
- 🛡️ **Verificare la sicurezza** — HSTS, CSP, X-Frame-Options, fingerprinting CDN, fughe di informazioni dall'header Server
- 📜 **Catturare i certificati TLS** — giorni alla scadenza, CN, emittente, SAN, rilevamento wildcard
- 🚀 **Testare su larga scala** — oltre 50 richieste concorrenti in pochi secondi

### Ideale per

- ✅ **Sviluppatori** che ottimizzano le prestazioni delle API
- ✅ **DevOps/SRE** che validano gli SLA di CDN e server di origine
- ✅ **Ingegneri della sicurezza** che verificano gli header di sicurezza HTTP e l'igiene TLS
- ✅ **Fornitori di API** che misurano *endpoint* con autenticazione, header e payload nel corpo

## Avvio rapido

```bash
# Test 5 built-in targets with a single iteration
net-benchmark http benchmark --use-defaults
```

I risultati vengono salvati automaticamente in `./benchmark_results/` con un CSV
riepilogativo, i dati grezzi di dettaglio e report PDF/Excel opzionali.

```bash
# First-run recommendations
net-benchmark http benchmark --use-defaults --formats csv,excel
net-benchmark http benchmark --use-defaults --iterations 5   # meaningful jitter/consistency
```

## Comandi a colpo d'occhio

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

## Funzionalità principali

### 🚀 Prestazioni

- **Motore asincrono** — httpx con HTTP/2, pooling delle connessioni, concorrenza a semaforo
- **Scomposizione dei tempi** — risoluzione DNS, connessione TCP, handshake TLS, TTFB, TTLB, latenza totale
- **Iterazioni multiple** — ripeti i benchmark più volte per accuratezza statistica
- **Analisi statistica** — media, mediana, P95, P99, jitter, punteggio di consistenza
- **Ritentativi con backoff** — backoff esponenziale sui fallimenti (come nel motore DNS)
- **Concorrenza configurabile** — controlla il numero massimo di richieste concorrenti
- **Fase di riscaldamento** — warmup opzionale con HEAD o completo prima della misurazione

### 🔒 Sicurezza e TLS

- **Audit degli header di sicurezza** — HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
- **Fingerprinting CDN** — rileva Cloudflare, CloudFront, Fastly, Akamai, Google, Azure CDN
- **Rilevamento di fughe dall'header Server** — segnala la divulgazione di software e versione
- **Cattura inline dei certificati TLS** — giorni alla scadenza, CN, emittente, SAN, rilevamento wildcard
- **Rilevamento dei downgrade** — catene di redirect HTTPS→HTTP e fallback HTTP/2→HTTP/1.1
- **IPv4 vs IPv6** — rilevamento dual-stack per richiesta
- **Rilevamento Alt-Svc** — server che annuncia HTTP/3

## Buone pratiche

| Modalità | Flag consigliati | Scopo |
|---|---|---|
| **Esecuzione rapida** | `--iterations 1 --warmup-fast` | Feedback veloce, riscaldamento leggero |
| **Esecuzione approfondita** | `--iterations 5 --warmup --timeout 10 --retries 2` | Passaggi multipli, riscaldamento completo, ideale per benchmarking dettagliato |
| **Modalità debug** | `--iterations 1 --timeout 30 --retries 0` | Timeout lungo, nessun ritentativo, utile per diagnosticare problemi degli endpoint |
| **Test di API** | `--method POST --body '{}' --headers "Auth:token" --assert status=200` | Invia payload e valida le risposte |

## Vedi anche

- [Test di carico HTTP](http-load-test.md) — carico prolungato, distribuito e multi-macchina
- [Formati di esportazione](export-formats.md) — incluse le esportazioni specifiche per HTTP
