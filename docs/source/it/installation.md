# Installazione

```bash
pip install net-benchmark          # core
pip install net-benchmark[pdf]     # with pdf export
```

## Requisiti

- Python 3.9+
- gestore di pacchetti pip

## Installazione dai sorgenti

```bash
git clone https://github.com/net-benchmark/net-benchmark.git
cd net-benchmark
pip install -e .
```

## Verifica dell'installazione

```bash
net-benchmark --version
net-benchmark dns --help
net-benchmark http --help

# See all available options for a specific command
net-benchmark dns benchmark --help
net-benchmark http benchmark --help
```

## Prima esecuzione

```bash
# Test with defaults (recommended for first time)
net-benchmark dns benchmark --use-defaults --formats csv,excel

# HTTP test with defaults
net-benchmark http benchmark --use-defaults --formats csv,excel
```

I risultati vengono salvati automaticamente in `./benchmark_results/` con un CSV
riepilogativo, i dati grezzi di dettaglio e report PDF/Excel opzionali.

## Esportazione PDF

L'esportazione PDF richiede la dipendenza aggiuntiva **weasyprint**, che non
viene installata automaticamente per evitare problemi di esecuzione su alcune
piattaforme. Oltre al pacchetto Python servono alcune librerie di sistema:
vedi [Formati di esportazione](export-formats.md).

## Passi successivi

- [Avvio rapido](quickstart.md) — i primi comandi utili
- [Benchmark DNS](dns-benchmark.md)
- [Benchmark HTTP](http-benchmark.md)
