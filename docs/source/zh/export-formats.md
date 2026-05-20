# 导出格式

## 格式总览

| 格式 | 参数 | 说明 |
|---|---|---|
| CSV | `--formats csv` | 原始结果 + 汇总 + 可选的域名/记录类型/错误统计 |
| Excel | `--formats excel` | 带图表和条件格式的格式化工作簿 |
| PDF | `--formats pdf` | 需要 `pip install net-benchmark[pdf]` |
| JSON | `--json` | 完整结构化数据（单独参数，可与 `--formats` 组合使用） |

多种格式可以组合：

```bash
net-benchmark dns benchmark --use-defaults --formats csv,excel,pdf --json
net-benchmark http benchmark --use-defaults --formats csv,excel,pdf --json
```

---

## PDF 安装

```bash
pip install net-benchmark[pdf]
net-benchmark dns benchmark --use-defaults --formats pdf --output ./results
```

如果未安装 WeasyPrint，CLI 会显示：

```
[-] Error during benchmark: PDF export requires 'weasyprint'. Install with: pip install net-benchmark[pdf]
```

---

## 包含图表

```bash
net-benchmark dns benchmark --use-defaults --formats pdf,excel --include-charts
net-benchmark http benchmark --use-defaults --formats pdf,excel --include-charts
```
