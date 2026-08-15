# Formati di esportazione

| formato | flag | note |
|--------|------|-------|
| CSV | `--formats csv` | risultati grezzi + riepilogo + statistiche opzionali per dominio/tipo di record/errore |
| Excel | `--formats excel` | cartella di lavoro formattata con grafici e foglio DNSSEC |
| PDF | `--formats pdf` | richiede `pip install net-benchmark[pdf]` (vedi sotto) |
| JSON | `--json` | payload strutturato completo (flag separato) |

## Output CSV

- Dati grezzi: risultati delle singole query con timestamp e metadati
- Statistiche di riepilogo: metriche aggregate per resolver
- Statistiche per dominio: metriche dominio per dominio (con `--domain-stats`)
- Statistiche per tipo di record: metriche per tipo di record (con `--record-type-stats`)
- Ripartizione degli errori: conteggi per tipo di errore (con `--error-breakdown`)

## Report Excel

- Foglio dei dati grezzi: tutti i risultati delle query con formattazione
- Riepilogo dei resolver: statistiche complete con formattazione condizionale
- Statistiche per dominio: prestazioni dominio per dominio (opzionale)
- Statistiche per tipo di record: prestazioni per tipo di record (opzionale)
- Ripartizione degli errori: conteggi aggregati degli errori (opzionale)
- Analisi delle prestazioni: grafici e analisi comparativa

## Report PDF

- Sintesi esecutiva: risultati chiave e raccomandazioni
- Grafici delle prestazioni: confronto delle latenze; grafico opzionale del tasso di successo
- Classifica dei resolver: ordinata per latenza media
- Analisi dettagliata: approfondimento tecnico con i percentili

## Esportazioni specifiche per HTTP

| File CSV | Contenuti |
|----------|----------|
| `*_raw.csv` | Risultati delle singole richieste con scomposizione dei tempi |
| `*_summary.csv` | Statistiche aggregate per target |
| `*_security.csv` | Matrice di presenza degli header di sicurezza |
| `*_ttfb.csv` | Analisi del time-to-first-byte |
| `*_protocols.csv` | Distribuzione HTTP/1.1 vs HTTP/2 |

### Report Excel (HTTP)

- Foglio **Raw Data**: tutte le richieste con tempi, header di sicurezza, dettagli dei certificati
- Foglio **Target Summary**: statistiche complete per target
- Foglio **TTFB Analysis**: percentili del TTFB per target
- Foglio **Security Headers**: matrice di presenza con codifica a colori
- Foglio **Charts**: confronto delle latenze, confronto dei TTFB, tassi di successo (opzionale)

## Esportazione JSON

*Bundle* leggibile da una macchina che include:

- Statistiche complessive
- Statistiche dei resolver
- Risultati grezzi delle query
- Statistiche per dominio
- Statistiche per tipo di record
- Ripartizione degli errori

(pdf-dependencies)=
## Esportazione PDF opzionale

Per impostazione predefinita lo strumento supporta le esportazioni **CSV** ed
**Excel**. L'esportazione PDF richiede la dipendenza aggiuntiva **weasyprint**,
che non viene installata automaticamente per evitare problemi di esecuzione su
alcune piattaforme.

### Installazione con supporto PDF

```bash
pip install net-benchmark[pdf]
```

### Utilizzo

Una volta installato, puoi richiedere l'output PDF dalla CLI:

```bash
net-benchmark dns benchmark --use-defaults --formats pdf --output ./results
```

Se `weasyprint` non è installato e richiedi l'output PDF, la CLI mostrerà:

```bash
[-] Error during benchmark: PDF export requires 'weasyprint'. Install with: pip install net-benchmark[pdf]
```

### Configurazione di WeasyPrint

Lo strumento usa **WeasyPrint** per generare i report PDF. Oltre al pacchetto
Python servono alcune librerie di sistema aggiuntive.

#### Linux (Debian/Ubuntu)

```bash
sudo apt install python3-pip libpango-1.0-0 libpangoft2-1.0-0 \
  libharfbuzz-subset0 libjpeg-dev libopenjp2-7-dev libffi-dev
```

#### macOS (Homebrew)

```bash
brew install pango cairo libffi gdk-pixbuf jpeg openjpeg harfbuzz
```

#### Windows

Installa le librerie GTK+ con uno di questi metodi:

- **MSYS2**: [scarica MSYS2](https://www.msys2.org/), poi esegui:

  ```bash
  pacman -S mingw-w64-x86_64-gtk3 mingw-w64-x86_64-libffi
  ```

- **Installer GTK+ a 64 bit**: [scarica il GTK+ Runtime](https://github.com/tschoonj/GTK-for-Windows-Runtime-Environment-Installer/releases) ed esegui l'installer.

Riavvia il terminale dopo l'installazione.

#### Verifica dell'installazione

Dopo aver installato le librerie di sistema, installa l'extra Python:

```bash
pip install net-benchmark[pdf]
```

Poi esegui:

```bash
net-benchmark dns benchmark --use-defaults --formats pdf --output ./results
```

## Generare una configurazione di esempio

```bash
net-benchmark dns generate-config \
  --category privacy \
  --output my-config.yaml
```
