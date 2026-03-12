import subprocess
import json
import shutil
from dataclasses import dataclass
from typing import List, Optional
import sys

@dataclass
class SemgrepFinding:
    rule_id: str
    file_path: str
    start_line: int
    end_line: int
    code_snippet: str
    message: str
    severity: str
    cwe: Optional[str]
    vulnerability_type: str

def check_semgrep_installed():
    if not shutil.which("semgrep"):
        print("ERROR: Semgrep이 설치되지 않았습니다.")
        print("설치 방법: pip install semgrep")
        print("Docker 대안: docker run --rm -v $(pwd):/src returntocorp/semgrep ...")
        sys.exit(1)

def infer_vuln_type(rule_id: str) -> str:
    rule_lower = rule_id.lower()
    if "sqli" in rule_lower or "sql" in rule_lower:
        return "sql_injection"
    elif "xss" in rule_lower:
        return "xss"
    elif "path" in rule_lower or "traversal" in rule_lower:
        return "path_traversal"
    return "unknown"

def run_semgrep(target_dir: str, rules_dir: str) -> List[SemgrepFinding]:
    check_semgrep_installed()

    cmd = [
        "semgrep", "--config", rules_dir,
        "--json", "--timeout", "60",
        "--no-git-ignore",
        "--x-ignore-semgrepignore-files",
        target_dir
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        output = result.stdout
        if not output.strip():
            return []

        data = json.loads(output)
        findings = []

        for r in data.get("results", []):
            rule_id = r.get("check_id", "")
            vuln_type = infer_vuln_type(rule_id)
            cwe = r.get("extra", {}).get("metadata", {}).get("cwe")

            finding = SemgrepFinding(
                rule_id=rule_id,
                file_path=r.get("path", ""),
                start_line=r.get("start", {}).get("line", 0),
                end_line=r.get("end", {}).get("line", 0),
                code_snippet=r.get("extra", {}).get("lines", ""),
                message=r.get("extra", {}).get("message", ""),
                severity=r.get("extra", {}).get("severity", "WARNING"),
                cwe=cwe,
                vulnerability_type=vuln_type,
            )
            findings.append(finding)

        return findings
    except subprocess.TimeoutExpired:
        print(f"WARNING: Semgrep timeout for {target_dir}")
        return []
    except json.JSONDecodeError as e:
        print(f"WARNING: Failed to parse Semgrep output: {e}")
        return []
