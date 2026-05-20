# 常见问题

**为什么我的 ISP DNS 不是最快的？**

本地 ISP DNS 通常有缓存优势，但往往缺乏全球 anycast 网络、DNSSEC 验证、隐私功能（DoH/DoT）和可靠性保证。
使用 `net-benchmark dns compare` 对比测试，根据你的优先需求做决定。

**`DNSSEC_FAILED` 是什么意思？**

解析器未为查询域名返回有效的 DNSSEC 签名（AD 标志）。这对于未签名的域名是**预期行为**，
不是工具的问题 — 常见域名中只有约 33% 是 DNSSEC 签名的。

**为什么两次运行结果不同？**

网络条件、DNS 缓存、服务器负载和地理 anycast 路由变化都会影响结果。
运行 `--iterations 5` 并比较中位延迟，结果会更稳定。

**为什么我的 API 比预期慢？**

HTTP 测试的时序分解（DNS → TCP → TLS → TTFB → TTLB）告诉你时间花在哪里了。
如果 DNS 慢，检查你的解析器；如果 TLS 慢，检查证书链大小；如果 TTFB 慢，服务器逻辑或数据库是瓶颈。

**PDF 导出失败怎么办？**

安装 WeasyPrint 及系统级 C 库，详见 [安装指南](installation.md)。
或者跳过 PDF：`--formats csv,excel`。

**安装后找不到命令？**

```bash
pip install -e .
python -m net_benchmark.dns_benchmark.cli --help
python -m net_benchmark.http_bench.cli --help
```

确保 Python 的 `bin` / `Scripts` 目录在你的 `PATH` 中。

**这个工具在生产环境中安全吗？**

是的。它只执行标准 DNS 查询和 HTTP 读取请求。不会修改 DNS 记录、修改服务器数据、发动攻击或向外部服务器发送数据。
