# Installation

## Requirements

- Python 3.9–3.12
- pip package manager
- Linux, macOS, or Windows

---

## Standard install

```bash
pip install net-benchmark          # core
pip install net-benchmark[pdf]     # with PDF export
```

---

## Verify installation

```bash
net-benchmark --version
net-benchmark dns --help
net-benchmark http --help

# See all options for a specific command
net-benchmark dns benchmark --help
net-benchmark http benchmark --help
```

---

## Install from source

```bash
git clone https://github.com/net-benchmark/net-benchmark.git
cd net-benchmark
pip install -e .
```

---

(pdf-dependencies)=
## WeasyPrint — PDF export

PDF export requires WeasyPrint and system-level C libraries.

**Linux (Debian / Ubuntu)**

```bash
sudo apt install python3-pip libpango-1.0-0 libpangoft2-1.0-0 \
  libharfbuzz-subset0 libjpeg-dev libopenjp2-7-dev libffi-dev
```

**macOS (Homebrew)**

```bash
brew install pango cairo libffi gdk-pixbuf jpeg openjpeg harfbuzz
```

**Windows — MSYS2**

```powershell
pacman -S mingw-w64-x86_64-gtk3 mingw-w64-x86_64-libffi
```

Or download the [GTK+ 64-bit Runtime Installer](https://github.com/tschoonj/GTK-for-Windows-Runtime-Environment-Installer/releases).
Restart your terminal after installation.

After installing system libraries:

```bash
pip install net-benchmark[pdf]
```

Verify:

```bash
net-benchmark dns benchmark --use-defaults --formats pdf --output ./results
```

If WeasyPrint is missing, the CLI prints:

```
[-] Error during benchmark: PDF export requires 'weasyprint'. Install with: pip install net-benchmark[pdf]
```

---

## Upgrading

```bash
pip install --upgrade net-benchmark
```
