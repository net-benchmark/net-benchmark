# Test di carico HTTP

`net-benchmark http load-test` genera traffico prolungato verso uno o più
*target* HTTP usando tre strategie di modellazione del carico. A differenza di
`benchmark` (numero fisso di iterazioni), load-test resta in esecuzione per una
durata e riporta il *throughput* ottenuto, i percentili di latenza e il
comportamento a livello di connessione.

## Modalità

| Modalità     | Cosa fa                                            | Caso d'uso                        |
|--------------|----------------------------------------------------|------------------------------------|
| `throughput` | Satura il target fino a `--max-concurrency`        | Trovare il tetto massimo           |
| `sustained`  | Mantiene un `--rps` fisso per `--duration`         | Validazione di SLA / capacità      |
| `ramp-up`    | Aumenta la concorrenza a gradini, poi la mantiene al picco | Trovare gradualmente il punto di rottura |

## Esempi

**Throughput — quanto può spingere questo *endpoint*?**

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
  --enable-connection-reuse \
  --formats csv,excel,json
```

`--rps` è obbligatorio in modalità `sustained` — la CLI fallisce subito con un
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
veloci (`localhost`, *sidecar* di *service mesh*) nient'altro limita la
frequenza delle richieste. Il valore predefinito è `ramp-concurrency * 50`, di
norma abbastanza generoso da non scattare mai contro servizi realmente limitati
dalla rete.

**Confrontare più target (per es. *canary* vs. *stable*)**

```bash
net-benchmark http load-test \
  -t https://api-v1.example.com,https://api-v2.example.com \
  --mode sustained --rps 100 --duration 120 \
  --formats excel --include-charts
```

Ogni target viene eseguito in parallelo nel proprio *pool* di connessioni.
L'esportazione Excel produce un foglio di confronto più fogli per target con le
richieste grezze e la *timeline*.

**Diagnostica di protocollo/trasporto sotto carico**

```bash
net-benchmark http load-test \
  -t https://cdn.example.com/asset.js \
  --mode throughput --duration 60 --max-concurrency 200 \
  --enable-connection-reuse --enable-tls-resumption --enable-push-detection \
  --formats json
```

Questi rilevamenti sono opzionali, perché aggiungono contabilità per ogni
richiesta: attivali solo quando stai davvero indagando sul riuso delle
connessioni, sulla ripresa di sessione TLS o sul comportamento del *push*
HTTP/2.

## Formati di output

| Formato | Contenuti                                                      |
|---------|----------------------------------------------------------------|
| `csv`   | Risultati grezzi, riepilogo, timeline al secondo, ripartizione degli errori |
| `excel` | Foglio di confronto + fogli per target con dati grezzi/timeline, grafici opzionali |
| `pdf`   | Report con grafici (richiede `pip install net-benchmark[pdf]`)  |
| `json`  | *Bundle* strutturato completo, tutti i target                   |

> **Nota:** l'esportazione PDF fallisce in modo non bloccante — se `weasyprint`
> non è installato, l'esecuzione si completa comunque e gli altri formati
> vengono comunque scritti; controlla nell'output della CLI la presenza di
> `PDF export failed`.
