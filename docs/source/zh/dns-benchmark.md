# DNS 基准测试

## 为什么要测试 DNS？

DNS 解析通常是网络性能中隐藏的瓶颈。慢速解析器可能为每个请求增加 **300 毫秒以上** 的延迟。

**net-benchmark 帮你：**
- 找到**你所在位置**最快的 DNS 解析器
- 获取真实数据 — P95、P99、抖动、一致性分数
- 验证安全性 — 内置 DNSSEC 验证
- 大规模测试 — 数秒内并发 100+ 个查询

---

## 命令总览

| 命令 | 功能 | 示例 |
|---|---|---|
| `benchmark` | 完整 DNS 基准测试并导出 | `net-benchmark dns benchmark --use-defaults` |
| `top` | 按速度排列所有解析器 | `net-benchmark dns top --limit 5` |
| `compare` | 并排对比解析器 | `net-benchmark dns compare Cloudflare Google Quad9` |
| `monitoring` | 持续监控并告警 | `net-benchmark dns monitoring --use-defaults` |

---

## benchmark 命令

```bash
# 使用默认设置测试
net-benchmark dns benchmark --use-defaults --formats csv,excel

# 静默模式（无进度条）
net-benchmark dns benchmark --use-defaults --formats csv,excel --quiet

# 自定义解析器和域名
net-benchmark dns benchmark --resolvers data/resolvers.json --domains data/domains.txt

# 仅输出 CSV
net-benchmark dns benchmark --use-defaults --formats csv

# 内联解析器（按 IP）
net-benchmark dns benchmark \
  --resolvers "1.1.1.1,8.8.8.8,9.9.9.9" \
  --domains "google.com,github.com" \
  --formats csv

# 内联解析器（按名称）
net-benchmark dns benchmark \
  --resolvers "Cloudflare,Google,Quad9" \
  --domains "google.com,github.com" \
  --formats csv

# 混合输入
net-benchmark dns benchmark \
  --resolvers "1.1.1.1,Cloudflare,8.8.8.8" \
  --domains "google.com,github.com" \
  --formats csv

# 多次迭代以提高统计精度
net-benchmark dns benchmark --use-defaults --iterations 3 --use-cache

# 导出为 JSON 机器可读格式
net-benchmark dns benchmark --use-defaults --json --output ./results

# 包含详细分析
net-benchmark dns benchmark \
  --use-defaults \
  --domain-stats --record-type-stats --error-breakdown \
  --formats csv,excel
```

### 新 CLI 选项

| 选项 | 说明 |
|---|---|
| `--iterations, -i` | 运行完整基准测试循环 N 次 |
| `--use-cache` | 允许跨迭代重用缓存结果 |
| `--warmup` | 运行完整预热（所有解析器 × 域名 × 记录类型） |
| `--warmup-fast` | 轻量级预热（每个解析器一次探测） |
| `--include-charts` | 在 PDF/Excel 报告中嵌入图表 |

---

## top 命令

```bash
# 快速排列解析器
net-benchmark dns top

# 使用自定义域名列表
net-benchmark dns top -d domains.txt

# DoH 前 5 名
net-benchmark dns top --doh --limit 5

# DoT 可靠性排名
net-benchmark dns top --dot --metric reliability --limit 5
```

---

## compare 命令

```bash
# 比较 Cloudflare、Google 和 Quad9
net-benchmark dns compare Cloudflare Google Quad9

# 按 IP 地址比较
net-benchmark dns compare 1.1.1.1 8.8.8.8 9.9.9.9

# 显示详细的每域名分解
net-benchmark dns compare Cloudflare Google --show-details

# 比较 DoH 解析器
net-benchmark dns compare Cloudflare Google --doh --iterations 3
```

---

## monitoring 命令

```bash
# 持续监控默认解析器（每 60 秒）
net-benchmark dns monitoring --use-defaults

# 运行 1 小时，设置告警
net-benchmark dns monitoring --use-defaults --interval 30 --duration 3600 \
  --alert-latency 150 --alert-failure-rate 5 --output monitor.log

# 使用 DoT 监控
net-benchmark dns monitoring --use-defaults --dot \
  --interval 60 --alert-latency 300
```

---

## 加密 DNS（DoH / DoT / DNSSEC）

```bash
# DoH 基准测试
net-benchmark dns benchmark \
  --resolvers "Cloudflare,Google" \
  --domains "cloudflare.com,google.com" \
  --doh --warmup-fast

# DoT + DNSSEC
net-benchmark dns benchmark \
  --resolvers "Cloudflare,Quad9" \
  --domains "cloudflare.com,quad9.net" \
  --dot --dnssec-validate
```

```{warning}
`--doh` 和 `--dot` 互斥，不能同时使用。
```

---

## 基准测试汇总示例

```text
=== 基准测试汇总 ===
总查询数：    150
成功：        140（93.33%）
平均延迟：    212.45 毫秒
中位延迟：    198.12 毫秒
最快解析器：  Cloudflare
最慢解析器：  Quad9
迭代次数：    3
缓存命中：    40（26.7%）
```
