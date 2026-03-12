"""Tests for Reachability analyzer."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.reachability.analyzer import analyze, ReachabilityReport, CVEReachabilityResult

REACHABLE_DIR = str(Path(__file__).parent / "sample_projects" / "reachable")
UNREACHABLE_DIR = str(Path(__file__).parent / "sample_projects" / "unreachable")


def test_reachable_cve_log4shell():
    report = analyze(REACHABLE_DIR, cve_ids=["CVE-2021-44228"])
    results = {r.cve_id: r for r in report.results}
    assert "CVE-2021-44228" in results
    assert results["CVE-2021-44228"].verdict == "Reachable"


def test_unreachable_cve_log4shell():
    report = analyze(UNREACHABLE_DIR, cve_ids=["CVE-2021-44228"])
    results = {r.cve_id: r for r in report.results}
    assert "CVE-2021-44228" in results
    assert results["CVE-2021-44228"].verdict == "Unreachable"


def test_reachable_has_call_path():
    report = analyze(REACHABLE_DIR, cve_ids=["CVE-2021-44228"])
    result = report.results[0]
    assert result.verdict == "Reachable"
    assert len(result.call_path) >= 2
    assert any("JndiLookup" in node for node in result.call_path)


def test_report_structure():
    report = analyze(REACHABLE_DIR, cve_ids=["CVE-2021-44228"])
    assert isinstance(report, ReachabilityReport)
    assert report.source_dir == REACHABLE_DIR
    assert report.analyzed_at is not None
    assert report.total_files >= 0
    assert "reachable_count" in report.summary
    assert "unreachable_count" in report.summary
    assert "conditional_count" in report.summary


def test_all_cves_analysis():
    report = analyze(REACHABLE_DIR)
    assert len(report.results) == 5


def test_summary_counts():
    report = analyze(REACHABLE_DIR, cve_ids=["CVE-2021-44228"])
    assert report.summary["reachable_count"] >= 1


def test_unreachable_confidence():
    report = analyze(UNREACHABLE_DIR, cve_ids=["CVE-2021-44228"])
    result = report.results[0]
    assert result.verdict == "Unreachable"
    assert result.confidence >= 0.7


def test_result_has_reasoning():
    report = analyze(REACHABLE_DIR, cve_ids=["CVE-2021-44228"])
    result = report.results[0]
    assert result.reasoning != ""
