"""End-to-end pipeline tests."""
import os
import sys
import json
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.scanner.semgrep_runner import run_semgrep
from src.taint.taint_analyzer import analyze_taint
from src.report.reporter import generate_report, report_to_dict
from src.report.html_reporter import generate_html_report

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES_DIR = os.path.join(PROJECT_ROOT, "rules")
SAMPLE_DIR = os.path.join(PROJECT_ROOT, "tests", "sample_code")


def _run_pipeline(source_dir):
    """Helper: run full pipeline on a directory."""
    findings = run_semgrep(source_dir, RULES_DIR)
    total_files = sum(
        1 for r, _, fs in os.walk(source_dir) for f in fs if f.endswith(".java")
    )
    taint_results = []
    for f in findings:
        if os.path.isfile(f.file_path):
            with open(f.file_path, "r", encoding="utf-8") as fp:
                source = fp.read()
        else:
            source = f.code_snippet
        result = analyze_taint(f, source, use_mock=True)
        taint_results.append(result)
    return findings, taint_results, total_files


class TestFullPipeline:
    def test_vulnerable_all_confirmed(self):
        vuln_dir = os.path.join(SAMPLE_DIR, "vulnerable")
        findings, results, _ = _run_pipeline(vuln_dir)
        confirmed = [r for r in results if r.verdict == "CONFIRMED"]
        assert len(confirmed) == 3

    def test_safe_no_confirmed(self):
        safe_dir = os.path.join(SAMPLE_DIR, "safe")
        findings, results, _ = _run_pipeline(safe_dir)
        confirmed = [r for r in results if r.verdict == "CONFIRMED"]
        assert len(confirmed) == 0

    def test_all_samples_precision_recall(self):
        findings, results, total_files = _run_pipeline(SAMPLE_DIR)
        confirmed = [r for r in results if r.verdict == "CONFIRMED"]
        fp = [r for r in results if r.verdict == "FALSE_POSITIVE"]

        # All confirmed should be from vulnerable/
        for c in confirmed:
            assert "vulnerable" in c.finding.file_path

        # All false positives should be from safe/
        for f in fp:
            assert "safe" in f.finding.file_path


class TestReportGeneration:
    def test_generate_report(self):
        findings, results, total_files = _run_pipeline(SAMPLE_DIR)
        report = generate_report(SAMPLE_DIR, results, total_files, len(findings))
        assert report.confirmed_count == 3
        assert report.false_positive_count == 2
        assert report.uncertain_count == 0
        assert report.metrics["precision_estimate"] > 0

    def test_report_to_dict(self):
        findings, results, total_files = _run_pipeline(SAMPLE_DIR)
        report = generate_report(SAMPLE_DIR, results, total_files, len(findings))
        d = report_to_dict(report)
        assert isinstance(d, dict)
        assert "findings" in d
        assert len(d["findings"]) == len(results)
        # Verify JSON serializable
        json.dumps(d, ensure_ascii=False)

    def test_html_report_generation(self, tmp_path):
        findings, results, total_files = _run_pipeline(SAMPLE_DIR)
        report = generate_report(SAMPLE_DIR, results, total_files, len(findings))
        html_path = str(tmp_path / "test_report.html")
        generate_html_report(report, html_path)
        assert os.path.exists(html_path)
        with open(html_path, "r") as f:
            content = f.read()
        assert "AI SAST" in content
        assert "CONFIRMED" in content


class TestBenchmark:
    def test_benchmark_runs(self):
        from benchmark.run_benchmark import run_benchmark
        result = run_benchmark(use_mock=True)
        assert result["success_criteria"]["all_passed"] is True
        assert result["llm_filtered"]["precision"] >= 0.70
        assert result["llm_filtered"]["recall"] >= 0.75
