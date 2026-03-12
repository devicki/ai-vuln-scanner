import os
import shutil
import subprocess
import traceback
from typing import Optional, List

from fastapi import FastAPI
from pydantic import BaseModel

from src.scanner.semgrep_runner import run_semgrep
from src.taint.taint_analyzer import analyze_taint
from src.report.reporter import generate_report, report_to_dict
from src.report.html_reporter import generate_html_report

app = FastAPI(title="AI SAST API")

RULES_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "rules")


class ScanRequest(BaseModel):
    source_dir: str
    vuln_types: Optional[List[str]] = None
    use_llm: bool = False
    output_html: bool = False


@app.post("/scan")
async def scan(request: ScanRequest):
    """Run the full SAST pipeline: semgrep -> taint analysis -> report."""
    try:
        # 1. Run Semgrep
        findings = run_semgrep(request.source_dir, RULES_DIR)

        # Filter by vulnerability types if specified
        if request.vuln_types:
            findings = [f for f in findings if f.vulnerability_type in request.vuln_types]

        # 2. Count Java files
        total_files = 0
        for root, _dirs, files in os.walk(request.source_dir):
            total_files += sum(1 for f in files if f.endswith(".java"))

        semgrep_count = len(findings)

        # 3. Taint analysis for each finding
        taint_results = []
        for finding in findings:
            try:
                source_path = finding.file_path
                if os.path.isfile(source_path):
                    with open(source_path, "r", encoding="utf-8", errors="ignore") as fp:
                        source_code = fp.read()
                else:
                    source_code = finding.code_snippet

                result = analyze_taint(finding, source_code, use_llm=request.use_llm)
                taint_results.append(result)
            except Exception:
                traceback.print_exc()
                continue

        # 4. Generate report
        report = generate_report(request.source_dir, taint_results, total_files, semgrep_count)
        report_dict = report_to_dict(report)

        # 5. Optional HTML report
        html_report_path = None
        if request.output_html:
            html_report_path = os.path.join(request.source_dir, "sast_report.html")
            generate_html_report(report, html_report_path)

        return {
            "status": "success",
            "report": report_dict,
            "html_report_path": html_report_path,
        }

    except Exception as e:
        traceback.print_exc()
        return {"status": "error", "message": str(e)}


@app.get("/health")
async def health():
    """Check service health and semgrep availability."""
    semgrep_available = shutil.which("semgrep") is not None

    if not semgrep_available:
        # Try running semgrep to double-check
        try:
            subprocess.run(
                ["semgrep", "--version"],
                capture_output=True,
                timeout=5,
            )
            semgrep_available = True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            semgrep_available = False

    return {"status": "ok", "semgrep_available": semgrep_available}
