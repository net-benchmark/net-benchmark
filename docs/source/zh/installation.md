# 安装指南

## 系统要求

- Python 3.9–3.12
- pip 包管理器
- Linux、macOS 或 Windows

---

## 标准安装

```bash
pip install net-benchmark          # 核心版本
pip install net-benchmark[pdf]     # 含 PDF 导出
```

---

## 验证安装

```bash
net-benchmark --version
net-benchmark dns --help
net-benchmark http --help

# 查看特定命令的所有选项
net-benchmark dns benchmark --help
net-benchmark http benchmark --help
```

---

## 从源码安装

```bash
git clone https://github.com/net-benchmark/net-benchmark.git
cd net-benchmark
pip install -e .
```

---

## WeasyPrint（PDF 导出）

PDF 导出需要 WeasyPrint 及系统级 C 库。

**Linux（Debian / Ubuntu）**

```bash
sudo apt install python3-pip libpango-1.0-0 libpangoft2-1.0-0 \
  libharfbuzz-subset0 libjpeg-dev libopenjp2-7-dev libffi-dev
```

**macOS（Homebrew）**

```bash
brew install pango cairo libffi gdk-pixbuf jpeg openjpeg harfbuzz
```

**Windows — MSYS2**

```powershell
pacman -S mingw-w64-x86_64-gtk3 mingw-w64-x86_64-libffi
```

安装完成后重启终端，然后：

```bash
pip install net-benchmark[pdf]
```

---

## 升级

```bash
pip install --upgrade net-benchmark
```
