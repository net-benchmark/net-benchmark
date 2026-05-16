import os

import pandas as pd

from net_benchmark.http_bench.analysis import HTTPAnalyzer
from net_benchmark.http_bench.exporters import (
    HTTPCSVExporter,
    HTTPExcelExporter,
    HTTPExportBundle,
)


class TestCSVExporter:
    def test_export_raw_results(self, tmp_path, sample_results):
        path = tmp_path / "raw.csv"
        HTTPCSVExporter.export_raw_results(sample_results, str(path))
        df = pd.read_csv(path)
        assert len(df) == len(sample_results)

    def test_export_summary_statistics(self, tmp_path, sample_results):
        analyzer = HTTPAnalyzer(sample_results)
        path = tmp_path / "summary.csv"
        HTTPCSVExporter.export_summary_statistics(analyzer, str(path))
        df = pd.read_csv(path)
        assert len(df) == 1
        assert "avg_dns_ms" in df.columns

    def test_export_security_statistics(self, tmp_path, sample_results):
        analyzer = HTTPAnalyzer(sample_results)
        path = tmp_path / "sec.csv"
        HTTPCSVExporter.export_security_statistics(analyzer, str(path))
        df = pd.read_csv(path)
        assert "strict-transport-security" in df.columns

    def test_export_ttfb_statistics(self, tmp_path, sample_results):
        analyzer = HTTPAnalyzer(sample_results)
        path = tmp_path / "ttfb.csv"
        HTTPCSVExporter.export_ttfb_statistics(analyzer, str(path))
        df = pd.read_csv(path)
        assert "avg_ttfb_ms" in df.columns


class TestExcelExporter:
    def test_export_results(self, tmp_path, sample_results):
        analyzer = HTTPAnalyzer(sample_results)
        path = tmp_path / "report.xlsx"
        HTTPExcelExporter.export_results(sample_results, analyzer, str(path))
        assert os.path.exists(path)

    def test_export_with_charts(self, tmp_path, sample_results):
        analyzer = HTTPAnalyzer(sample_results)
        path = tmp_path / "report_charts.xlsx"
        HTTPExcelExporter.export_results(
            sample_results, analyzer, str(path), include_charts=True
        )
        assert os.path.exists(path)


class TestJSONExport:
    def test_export_json(self, tmp_path, sample_results):
        analyzer = HTTPAnalyzer(sample_results)
        path = tmp_path / "report.json"
        HTTPExportBundle.export_json(sample_results, analyzer, str(path))
        assert os.path.exists(path)
        import json

        with open(path) as f:
            data = json.load(f)
        assert "overall" in data
        assert "target_stats" in data
        assert "raw_results" in data
