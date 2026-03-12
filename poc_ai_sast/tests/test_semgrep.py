"""Tests for Semgrep scanner module."""
import os
import sys
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.scanner.semgrep_runner import run_semgrep, infer_vuln_type, SemgrepFinding

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES_DIR = os.path.join(PROJECT_ROOT, "rules")
VULN_DIR = os.path.join(PROJECT_ROOT, "tests", "sample_code", "vulnerable")
SAFE_DIR = os.path.join(PROJECT_ROOT, "tests", "sample_code", "safe")


class TestInferVulnType:
    def test_sqli(self):
        assert infer_vuln_type("java-sqli-string-concat") == "sql_injection"

    def test_xss(self):
        assert infer_vuln_type("java-xss-response-write") == "xss"

    def test_path_traversal(self):
        assert infer_vuln_type("java-path-traversal-file-new") == "path_traversal"

    def test_unknown(self):
        assert infer_vuln_type("some-other-rule") == "unknown"


class TestSemgrepRunnerVulnerable:
    def test_finds_sql_injection(self):
        findings = run_semgrep(VULN_DIR, RULES_DIR)
        sqli = [f for f in findings if f.vulnerability_type == "sql_injection"]
        assert len(sqli) >= 1
        assert any("UserController" in f.file_path for f in sqli)

    def test_finds_xss(self):
        findings = run_semgrep(VULN_DIR, RULES_DIR)
        xss = [f for f in findings if f.vulnerability_type == "xss"]
        assert len(xss) >= 1
        assert any("CommentController" in f.file_path for f in xss)

    def test_finds_path_traversal(self):
        findings = run_semgrep(VULN_DIR, RULES_DIR)
        pt = [f for f in findings if f.vulnerability_type == "path_traversal"]
        assert len(pt) >= 1
        assert any("FileController" in f.file_path for f in pt)

    def test_total_vulnerable_findings(self):
        findings = run_semgrep(VULN_DIR, RULES_DIR)
        assert len(findings) == 3


class TestSemgrepRunnerSafe:
    def test_safe_code_findings(self):
        findings = run_semgrep(SAFE_DIR, RULES_DIR)
        # Safe code may have Semgrep hits (overt pattern matching)
        # but should not have sql_injection since SafeUserController uses ?
        sqli = [f for f in findings if f.vulnerability_type == "sql_injection"]
        assert len(sqli) == 0
