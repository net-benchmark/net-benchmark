# 快速开始

## 第一次运行 — DNS

```bash
# 使用默认设置测试（新用户推荐）
net-benchmark dns benchmark --use-defaults --formats csv,excel
```

## 第一次运行 — HTTP

```bash
# HTTP 测试使用默认设置
net-benchmark http benchmark --use-defaults --formats csv,excel
```

测试结果自动保存到 `./benchmark_results/`，包含汇总 CSV、原始 CSV 和 Excel 工作簿。

---

## 常用命令

```bash
# 立即找到最快的 DNS 解析器
net-benchmark dns top --limit 5

# 对比三大 DNS 解析器
net-benchmark dns compare Cloudflare Google Quad9 --show-details

# 使用 DoT 监控 DNS，运行 1 小时
net-benchmark dns monitoring --use-defaults --dot \
  --interval 30 --duration 3600 \
  --alert-latency 150 --output monitor.log

# 立即找到最快的 HTTP 端点
net-benchmark http top --limit 5

# 并排比较两个 API
net-benchmark http compare api.example.com api2.example.com --iterations 3 --show-details

# 监控 HTTP 端点，运行 1 小时
net-benchmark http monitoring --use-defaults \
  --interval 30 --duration 3600 \
  --alert-latency 500 --alert-failure-rate 5
```

---

## 查看帮助

```bash
net-benchmark dns --help
net-benchmark dns benchmark --help
net-benchmark http --help
net-benchmark http benchmark --help
```
