"""Tests for Taint Analysis module."""
import os
import sys
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.scanner.semgrep_runner import run_semgrep, SemgrepFinding
from src.taint.taint_analyzer import analyze_taint, _check_source, _check_sanitizer
from src.llm.llm_taint import analyze_with_llm, _mock_analyze

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES_DIR = os.path.join(PROJECT_ROOT, "rules")
VULN_DIR = os.path.join(PROJECT_ROOT, "tests", "sample_code", "vulnerable")
SAFE_DIR = os.path.join(PROJECT_ROOT, "tests", "sample_code", "safe")


class TestCheckSource:
    def test_detects_getparameter(self):
        assert _check_source('String id = request.getParameter("id");')

    def test_detects_request_param(self):
        assert _check_source('@RequestParam String name')

    def test_no_source(self):
        assert not _check_source('String x = "hello";')


class TestCheckSanitizer:
    def test_detects_prepared_statement(self):
        found, _ = _check_sanitizer('conn.prepareStatement(sql)', "sql_injection")
        assert found

    def test_detects_html_escape(self):
        found, _ = _check_sanitizer('HtmlUtils.htmlEscape(input)', "xss")
        assert found

    def test_detects_filename_utils(self):
        found, _ = _check_sanitizer('FilenameUtils.getName(path)', "path_traversal")
        assert found

    def test_no_sanitizer(self):
        found, _ = _check_sanitizer('String x = a + b;', "sql_injection")
        assert not found


class TestMockLLM:
    def test_confirms_sqli(self):
        code = 'String query = "SELECT * FROM users WHERE id = \'" + userId + "\'";'
        result = _mock_analyze(code, "sql_injection", "test", "test-rule")
        assert result.verdict == "CONFIRMED"

    def test_fp_prepared_statement(self):
        code = 'PreparedStatement ps = conn.prepareStatement(sql);'
        result = _mock_analyze(code, "sql_injection", "test", "test-rule")
        assert result.verdict == "FALSE_POSITIVE"

    def test_fp_html_escape(self):
        code = 'String safe = HtmlUtils.htmlEscape(input);'
        result = _mock_analyze(code, "xss", "test", "test-rule")
        assert result.verdict == "FALSE_POSITIVE"

    def test_fp_filename_utils(self):
        code = 'String safe = FilenameUtils.getName(filename);'
        result = _mock_analyze(code, "path_traversal", "test", "test-rule")
        assert result.verdict == "FALSE_POSITIVE"


class TestTaintAnalysisVulnerable:
    def test_sqli_confirmed(self):
        findings = run_semgrep(VULN_DIR, RULES_DIR)
        sqli = [f for f in findings if f.vulnerability_type == "sql_injection"][0]
        with open(sqli.file_path, "r") as fp:
            source = fp.read()
        result = analyze_taint(sqli, source, use_mock=True)
        assert result.verdict == "CONFIRMED"

    def test_xss_confirmed(self):
        findings = run_semgrep(VULN_DIR, RULES_DIR)
        xss = [f for f in findings if f.vulnerability_type == "xss"][0]
        with open(xss.file_path, "r") as fp:
            source = fp.read()
        result = analyze_taint(xss, source, use_mock=True)
        assert result.verdict == "CONFIRMED"

    def test_path_traversal_confirmed(self):
        findings = run_semgrep(VULN_DIR, RULES_DIR)
        pt = [f for f in findings if f.vulnerability_type == "path_traversal"][0]
        with open(pt.file_path, "r") as fp:
            source = fp.read()
        result = analyze_taint(pt, source, use_mock=True)
        assert result.verdict == "CONFIRMED"


class TestTaintAnalysisSafe:
    def test_safe_xss_false_positive(self):
        findings = run_semgrep(SAFE_DIR, RULES_DIR)
        xss = [f for f in findings if f.vulnerability_type == "xss"]
        if xss:
            with open(xss[0].file_path, "r") as fp:
                source = fp.read()
            result = analyze_taint(xss[0], source, use_mock=True)
            assert result.verdict == "FALSE_POSITIVE"

    def test_safe_path_traversal_false_positive(self):
        findings = run_semgrep(SAFE_DIR, RULES_DIR)
        pt = [f for f in findings if f.vulnerability_type == "path_traversal"]
        if pt:
            with open(pt[0].file_path, "r") as fp:
                source = fp.read()
            result = analyze_taint(pt[0], source, use_mock=True)
            assert result.verdict == "FALSE_POSITIVE"
