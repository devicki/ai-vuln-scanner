from dataclasses import dataclass, field, asdict
from typing import List, Optional
import json
from datetime import datetime


@dataclass
class SASTReport:
    source_dir: str
    analyzed_at: str
    total_files: int
    semgrep_findings_count: int
    confirmed_count: int
    false_positive_count: int
    uncertain_count: int
    findings: List  # List[TaintAnalysisResult]
    metrics: dict


FIX_SUGGESTIONS = {
    "sql_injection": "PreparedStatement 또는 JdbcTemplate 파라미터 바인딩 사용",
    "xss": "HtmlUtils.htmlEscape() 또는 Thymeleaf th:text 사용",
    "path_traversal": "FilenameUtils.getName()으로 파일명만 추출 후 허용 경로 검증",
}


def generate_report(source_dir: str, findings: List, total_files: int, semgrep_count: int) -> SASTReport:
    """Generate a SASTReport from taint analysis results."""
    confirmed = sum(1 for f in findings if f.verdict == "CONFIRMED")
    false_positive = sum(1 for f in findings if f.verdict == "FALSE_POSITIVE")
    uncertain = sum(1 for f in findings if f.verdict == "UNCERTAIN")

    precision_estimate = confirmed / (confirmed + false_positive) if (confirmed + false_positive) > 0 else 0.0
    recall_estimate = confirmed / semgrep_count if semgrep_count > 0 else 0.0

    fp_reduction = (
        (semgrep_count - confirmed - uncertain) / semgrep_count * 100
        if semgrep_count > 0
        else 0.0
    )

    metrics = {
        "precision_estimate": round(precision_estimate, 4),
        "recall_estimate": round(recall_estimate, 4),
        "fp_reduction_rate": round(fp_reduction, 2),
    }

    return SASTReport(
        source_dir=source_dir,
        analyzed_at=datetime.now().isoformat(),
        total_files=total_files,
        semgrep_findings_count=semgrep_count,
        confirmed_count=confirmed,
        false_positive_count=false_positive,
        uncertain_count=uncertain,
        findings=findings,
        metrics=metrics,
    )


def _finding_to_dict(finding) -> dict:
    """Convert a TaintAnalysisResult to a JSON-serializable dict."""
    semgrep = finding.finding
    vuln_type = getattr(semgrep, "vulnerability_type", "unknown")

    # Use fix_suggestion from TaintAnalysisResult if available, else fallback
    fix = getattr(finding, "fix_suggestion", "") or FIX_SUGGESTIONS.get(vuln_type, "")

    return {
        "verdict": finding.verdict,
        "confidence": finding.confidence,
        "source_detected": finding.source_detected,
        "sanitizer_detected": finding.sanitizer_detected,
        "sanitizer_type": finding.sanitizer_type,
        "taint_path": finding.taint_path,
        "reasoning": finding.reasoning,
        "llm_assisted": finding.llm_assisted,
        "finding": {
            "rule_id": semgrep.rule_id,
            "file_path": semgrep.file_path,
            "start_line": semgrep.start_line,
            "end_line": semgrep.end_line,
            "code_snippet": semgrep.code_snippet,
            "message": semgrep.message,
            "severity": semgrep.severity,
            "cwe": semgrep.cwe,
            "vulnerability_type": vuln_type,
        },
        "fix_suggestion": fix,
    }


def report_to_dict(report: SASTReport) -> dict:
    """Convert a SASTReport to a JSON-serializable dict."""
    return {
        "source_dir": report.source_dir,
        "analyzed_at": report.analyzed_at,
        "total_files": report.total_files,
        "semgrep_findings_count": report.semgrep_findings_count,
        "confirmed_count": report.confirmed_count,
        "false_positive_count": report.false_positive_count,
        "uncertain_count": report.uncertain_count,
        "findings": [_finding_to_dict(f) for f in report.findings],
        "metrics": report.metrics,
    }
