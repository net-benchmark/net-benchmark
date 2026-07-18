# HTTP 基准测试

每个 HTTP 请求背后隐藏着十几个性能和安全信号 — DNS、TCP、TLS、重定向、压缩、缓存、CDN 路由和服务器软件。net-benchmark 为你提供完整的全貌。

---

## 命令总览

| 命令 | 功能 | 示例 |
|---|---|---|
| `benchmark` | 完整 HTTP 基准测试并导出 | `net-benchmark http benchmark --use-defaults` |
| `top` | 按速度排列所有目标 | `net-benchmark http top --limit 5` |
| `compare` | 并排对比目标 | `net-benchmark http compare api.example.com api2.example.com` |
| `monitoring` | 持续监控并告警 | `net-benchmark http monitoring --use-defaults` |
| `load-test` | 持续负载测试，支持流量整形 | `net-benchmark http load-test -t https://api.example.com --mode throughput --duration 30` |

---

## benchmark 命令

```bash
# 测试内置默认目标
net-benchmark http benchmark --use-defaults

# 推荐的首次运行方式
net-benchmark http benchmark --use-defaults --formats csv,excel
net-benchmark http benchmark --use-defaults --iterations 5

# 内联目标（逗号分隔）
net-benchmark http benchmark --targets "https://example.com,https://httpbin.org/get"

# 自定义 HTTP 方法和请求体
net-benchmark http benchmark \
  --targets https://api.example.com/echo \
  --method POST \
  --body '{"action":"test"}'

# 使用自定义请求头的 API 密钥认证
net-benchmark http benchmark \
  --targets https://api.example.com/echo \
  --method POST \
  --headers "x-api-key:sk-abc123"

# Bearer Token 认证
net-benchmark http benchmark \
  --targets https://api.example.com/data \
  --auth "bearer:sk-abc123"

# 完整断言套件
net-benchmark http benchmark \
  --targets https://api.example.com/health \
  --assert status=200 \
  --assert body_contains=ok \
  --assert max_latency=500 \
  --assert content_type=application/json

# 导出所有格式含图表
net-benchmark http benchmark \
  --use-defaults \
  --formats csv,excel,pdf \
  --include-charts \
  --json \
  --output ./full_report
```

---

## top 命令

```bash
# 按延迟排列默认目标
net-benchmark http top --use-defaults --limit 5

# 按 TTFB 排列
net-benchmark http top --use-defaults --limit 5 --metric ttfb

# 按成功率排列
net-benchmark http top --targets targets.txt --limit 10 --metric success
```

---

## compare 命令

```bash
# 比较两个目标
net-benchmark http compare https://example.com https://httpbin.org/get

# 自动补全 scheme（如未填写 https:// 则自动添加）
net-benchmark http compare api.example.com api2.example.com

# 显示每次迭代的详细分解
net-benchmark http compare api.example.com api2.example.com \
  --iterations 3 --show-details
```

---

## monitoring 命令

```bash
# 每 60 秒监控默认目标
net-benchmark http monitoring --use-defaults

# 自定义目标和告警
net-benchmark http monitoring \
  --targets targets.txt \
  --interval 30 \
  --duration 3600 \
  --alert-latency 500 \
  --alert-failure-rate 5 \
  --output ./monitoring_logs
```

---

## load-test 命令

```bash
# 吞吐量模式——寻找端点天花板
net-benchmark http load-test \
  -t https://api.staging.example.com/health \
  --mode throughput \
  --duration 30 \
  --max-concurrency 300 \
  --formats csv,excel

# 持续模式——验证固定 RPS 容量（--rps 必需）
net-benchmark http load-test \
  -t https://checkout.example.com/api/cart \
  --mode sustained \
  --rps 150 \
  --duration 300 \
  --formats csv,excel,json

# 阶梯模式——逐步增压找出崩溃点
net-benchmark http load-test \
  -t https://api.example.com/search \
  --mode ramp-up \
  --start-concurrency 5 \
  --ramp-concurrency 500 \
  --ramp-duration 120 \
  --hold-duration 60 \
  --formats csv,excel,pdf

# 对比多个目标（如 canary vs stable）
net-benchmark http load-test \
  -t https://api-v1.example.com,https://api-v2.example.com \
  --mode sustained --rps 100 --duration 120 \
  --formats excel --include-charts
```

---

## HTTP 汇总示例

```text
============================================
| 总请求数：    5                           |
| 成功：        4（80.00%）                 |
| 平均延迟：    1047.25 毫秒                |
| 平均 TTFB：   772.20 毫秒                 |
| HTTP/2 率：   100.0%                      |
| HSTS 覆盖：   60.0%                       |
| 断言通过：    100.0%                      |
| 最快目标：    https://www.apple.com       |
| 最慢目标：    https://www.github.com      |
============================================
```

---

## 获取帮助

```bash
net-benchmark http --help
net-benchmark http benchmark --help
net-benchmark http top --help
net-benchmark http compare --help
net-benchmark http monitoring --help
net-benchmark http load-test --help
```
