"""Unit tests for load_test_exporters.py."""

import json
import os

import pandas as pd
import pytest

from net_benchmark.http_bench.core import HTTPProtocol, HTTPResult, QueryStatus
from net_benchmark.http_bench.load_test import LoadTestMode, _summarize, _TimedResult
from net_benchmark.http_bench.load_test_exporters import (
    LoadTestCSVExporter,
    LoadTestExcelExporter,
    LoadTestExportBundle,
    LoadTestPDFExporter,
    _sheet_name,
    combined_error_breakdown,
    error_breakdown,
)

try:
    from weasyprint import HTML
except ImportError:
    HTML = None


# ---------------------------------------------------------------------------
# Helpers — same fake_result shape as http_test_load_test.py
# ---------------------------------------------------------------------------


def fake_result(
    target: str = "https://example.com",
    total_ms: float = 100.0,
    status: QueryStatus = QueryStatus.SUCCESS,
    error_message: str = None,
) -> HTTPResult:
    """Return a minimal HTTPResult with a valid protocol so HTTPAnalyzer
    doesn't crash on r.protocol.value."""
    return HTTPResult(
        target=target,
        method="GET",
        start_time=1.0,
        end_time=1.0 + total_ms / 1000.0,
        total_ms=total_ms,
        status=status,
        iteration=1,
        http_status_code=200 if status == QueryStatus.SUCCESS else 500,
        error_message=error_message,
        protocol=HTTPProtocol.HTTP2,
        connection_id="conn-1",
        tls_resumed=False,
    )


def make_summary(
    target: str = "https://example.com",
    mode: LoadTestMode = LoadTestMode.THROUGHPUT,
    n_success: int = 8,
    n_fail: int = 2,
    target_rps: float = None,
    connections_opened: int = 3,
):
    """Build a real LoadTestSummary via _summarize."""
    timed = []
    offset = 0.0
    for i in range(n_success):
        r = fake_result(target=target, total_ms=50.0 + i, status=QueryStatus.SUCCESS)
        timed.append(_TimedResult(r, offset))
        offset += 0.3
    for i in range(n_fail):
        r = fake_result(
            target=target,
            total_ms=999.0,
            status=QueryStatus.TIMEOUT,
            error_message="Request timeout",
        )
        timed.append(_TimedResult(r, offset))
        offset += 0.3

    return _summarize(
        mode=mode,
        target=target,
        duration_s=max(offset, 1.0),
        timed_results=timed,
        target_rps=target_rps,
        connections_opened=connections_opened,
    )


@pytest.fixture
def summary_a():
    return make_summary(target="https://a.com")


@pytest.fixture
def summary_b():
    return make_summary(
        target="https://b.com", mode=LoadTestMode.SUSTAINED, target_rps=100.0
    )


@pytest.fixture
def summaries(summary_a, summary_b):
    return [summary_a, summary_b]


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


class TestSheetName:
    def test_strips_scheme_and_invalid_chars(self):
        name = _sheet_name("https://a.com:8443/path?x=1")
        assert ":" not in name
        assert "/" not in name
        assert "?" not in name

    def test_truncates_to_31_minus_suffix(self):
        long_target = "https://" + "x" * 50 + ".com"
        name = _sheet_name(long_target, suffix=" Raw")
        assert len(name) <= 31

    def test_dedupes_against_used_set(self):
        used = set()
        n1 = _sheet_name("https://samehost.com", suffix=" Raw", used=used)
        n2 = _sheet_name("https://samehost.com", suffix=" Raw", used=used)
        assert n1 != n2
        assert n1 in used and n2 in used

    def test_no_used_set_returns_raw_name(self):
        name = _sheet_name("https://x.com")
        assert name == "x.com"


class TestErrorBreakdown:
    def test_error_breakdown_counts_by_message(self, summary_a):
        counts = error_breakdown(summary_a)
        assert counts.get("Request timeout") == 2

    def test_error_breakdown_falls_back_to_status_code(self):
        summary = make_summary(n_success=0, n_fail=0)
        r = fake_result(status=QueryStatus.UNKNOWN_ERROR, error_message=None)
        summary.results.append(r)
        counts = error_breakdown(summary)
        assert "HTTP 500" in counts

    def test_combined_error_breakdown_sums_across_targets(self, summaries):
        combined = combined_error_breakdown(summaries)
        assert combined["Request timeout"] == 4


# ---------------------------------------------------------------------------
# JSON bundle
# ---------------------------------------------------------------------------


class TestExportBundle:
    def test_export_json_structure(self, tmp_path, summaries):
        path = tmp_path / "bundle.json"
        LoadTestExportBundle.export_json(summaries, str(path))
        assert path.exists()
        with open(path) as f:
            data = json.load(f)
        assert len(data["targets"]) == 2
        assert data["targets"][0]["target"] == "https://a.com"
        assert "combined_error_breakdown" in data
        assert data["combined_error_breakdown"]["Request timeout"] == 4
        assert "generated_at" in data

    def test_export_json_round_trips_enums(self, tmp_path, summary_a):
        path = tmp_path / "bundle.json"
        LoadTestExportBundle.export_json([summary_a], str(path))
        with open(path) as f:
            json.load(f)  # no exception


# ---------------------------------------------------------------------------
# CSV
# ---------------------------------------------------------------------------


class TestCSVExporter:
    def test_export_raw_results(self, tmp_path, summaries):
        path = tmp_path / "raw.csv"
        LoadTestCSVExporter.export_raw_results(summaries, str(path))
        df = pd.read_csv(path)
        total_results = sum(len(s.results) for s in summaries)
        assert len(df) == total_results
        assert "load_test_mode" in df.columns
        assert set(df["load_test_mode"].unique()) == {"throughput", "sustained"}

    def test_export_summary(self, tmp_path, summaries):
        path = tmp_path / "summary.csv"
        LoadTestCSVExporter.export_summary(summaries, str(path))
        df = pd.read_csv(path)
        assert len(df) == 2
        assert "achieved_rps" in df.columns
        assert "connection_reuse_rate_pct" in df.columns
        assert pd.isna(df.loc[df["target"] == "https://a.com", "target_rps"].iloc[0])
        assert df.loc[df["target"] == "https://b.com", "target_rps"].iloc[0] == 100.0

    def test_export_intervals(self, tmp_path, summaries):
        path = tmp_path / "intervals.csv"
        LoadTestCSVExporter.export_intervals(summaries, str(path))
        df = pd.read_csv(path)
        assert len(df) > 0
        assert "window_index" in df.columns
        assert "error_count" in df.columns

    def test_export_intervals_empty_when_no_intervals(self, tmp_path):
        empty_summary = make_summary(n_success=0, n_fail=0)
        path = tmp_path / "intervals_empty.csv"
        LoadTestCSVExporter.export_intervals([empty_summary], str(path))
        # Exporting an empty intervals list produces an empty CSV with no columns.
        # Check that the file was created and has no data (or minimal header).
        assert os.path.exists(path)
        with open(path) as f:
            content = f.read().strip()
        # Either empty or just a header line without data.
        assert content == "" or content == "target,window_index,..."  # adjust as needed

    def test_export_error_breakdown(self, tmp_path, summaries):
        path = tmp_path / "errors.csv"
        LoadTestCSVExporter.export_error_breakdown(summaries, str(path))
        df = pd.read_csv(path)
        assert set(df["target"].unique()) == {"https://a.com", "https://b.com"}
        assert (df["error_message"] == "Request timeout").all()
        assert (df["count"] == 2).all()


# ---------------------------------------------------------------------------
# Excel
# ---------------------------------------------------------------------------


class TestExcelExporter:
    def test_export_results_no_charts(self, tmp_path, summaries):
        path = tmp_path / "report.xlsx"
        LoadTestExcelExporter.export_results(summaries, str(path), include_charts=False)
        assert os.path.exists(path)

    def test_export_results_with_charts(self, tmp_path, summaries):
        path = tmp_path / "report_charts.xlsx"
        LoadTestExcelExporter.export_results(summaries, str(path), include_charts=True)
        assert os.path.exists(path)

    def test_export_results_cleans_up_temp_charts(
        self, tmp_path, summaries, monkeypatch
    ):
        created_dirs = []
        import net_benchmark.http_bench.load_test_exporters as lte

        orig_mkdtemp = lte.tempfile.mkdtemp

        def spy_mkdtemp(*a, **kw):
            d = orig_mkdtemp(*a, **kw)
            created_dirs.append(d)
            return d

        monkeypatch.setattr(lte.tempfile, "mkdtemp", spy_mkdtemp)

        path = tmp_path / "report_cleanup.xlsx"
        LoadTestExcelExporter.export_results(summaries, str(path), include_charts=True)

        assert created_dirs, "expected mkdtemp to be called for chart generation"
        for d in created_dirs:
            assert not os.path.exists(d) or os.listdir(d) == []

    def test_sheet_names_deduped_across_multiple_targets_with_same_host(self, tmp_path):
        long_prefix = "https://" + "verylonghostnameexample" * 2 + "-a.com"
        s1 = make_summary(target=long_prefix + "1")
        s2 = make_summary(target=long_prefix + "2")
        path = tmp_path / "dedup.xlsx"
        LoadTestExcelExporter.export_results([s1, s2], str(path), include_charts=False)
        assert os.path.exists(path)


# ---------------------------------------------------------------------------
# PDF
# ---------------------------------------------------------------------------


@pytest.mark.skipif(HTML is None, reason="weasyprint not installed")
class TestPDFExporter:
    def test_export_results_no_charts(self, tmp_path, summaries):
        path = tmp_path / "report.pdf"
        LoadTestPDFExporter.export_results(summaries, str(path), include_charts=False)
        assert os.path.exists(path)

    def test_export_results_with_charts(self, tmp_path, summaries):
        path = tmp_path / "report_charts.pdf"
        LoadTestPDFExporter.export_results(summaries, str(path), include_charts=True)
        assert os.path.exists(path)

    def test_export_results_no_intervals_skips_timeline_charts(self, tmp_path):
        empty_summary = make_summary(n_success=0, n_fail=0)
        path = tmp_path / "no_intervals.pdf"
        LoadTestPDFExporter.export_results(
            [empty_summary], str(path), include_charts=True
        )
        assert os.path.exists(path)


class TestPDFExporterMissingDependency:
    def test_raises_when_weasyprint_unavailable(self, tmp_path, summaries, monkeypatch):
        import net_benchmark.http_bench.load_test_exporters as lte

        monkeypatch.setattr(lte, "HTML", None)
        with pytest.raises(RuntimeError, match="weasyprint"):
            LoadTestPDFExporter.export_results(
                summaries, str(tmp_path / "x.pdf"), include_charts=False
            )
