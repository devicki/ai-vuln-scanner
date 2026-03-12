import subprocess
import json
import shutil
from dataclasses import dataclass
from typing import List, Optional
import sys
import os

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

_INVALID_SNIPPETS = {"requires login", "login required", ""}

def _read_code_snippet(file_path: str, start_line: int, end_line: int, raw_lines: str) -> str:
    """extra.lines 가 무의미한 값이면 파일에서 직접 해당 라인을 읽어 반환."""
    if raw_lines.strip().lower() not in _INVALID_SNIPPETS:
        return raw_lines
    try:
        if not os.path.isfile(file_path):
            return raw_lines
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            all_lines = f.readlines()
        # 1-based → 0-based 인덱스 변환, 전후 2줄 컨텍스트 포함
        s = max(0, start_line - 1)
        e = min(len(all_lines), end_line)
        return "".join(all_lines[s:e]).rstrip()
    except Exception:
        return raw_lines

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

            file_path = r.get("path", "")
            start_line = r.get("start", {}).get("line", 0)
            end_line = r.get("end", {}).get("line", 0)

            # extra.lines 가 "requires login" 등 무의미한 값이면 직접 파일에서 읽음
            raw_lines = r.get("extra", {}).get("lines", "")
            code_snippet = _read_code_snippet(file_path, start_line, end_line, raw_lines)

            finding = SemgrepFinding(
                rule_id=rule_id,
                file_path=file_path,
                start_line=start_line,
                end_line=end_line,
                code_snippet=code_snippet,
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
