from dataclasses import dataclass, field
from typing import List, Optional, Literal
import re

from src.scanner.semgrep_runner import SemgrepFinding
from src.llm.llm_taint import analyze_with_llm, LLMVerdict, FIX_SUGGESTIONS

SOURCE_PATTERNS = [
    r'request\.getParameter\s*\(',
    r'@RequestParam',
    r'@PathVariable',
    r'request\.getHeader\s*\(',
    r'getParameter\s*\(',
]

SANITIZER_PATTERNS = {
    "sql_injection": [
        r'prepareStatement\s*\(',
        r'PreparedStatement',
        r'"[^"]*\?[^"]*"',
        r"'[^']*\?[^']*'",
    ],
    "xss": [
        r'HtmlUtils\.htmlEscape\s*\(',
        r'htmlEscape\s*\(',
        r'escapeHtml\s*\(',
        r'StringEscapeUtils\.escapeHtml',
    ],
    "path_traversal": [
        r'FilenameUtils\.getName\s*\(',
        r'\.normalize\s*\(\s*\)',
        r'getCanonicalPath\s*\(',
    ],
}

@dataclass
class TaintAnalysisResult:
    finding: SemgrepFinding
    verdict: Literal["CONFIRMED", "FALSE_POSITIVE", "UNCERTAIN"]
    confidence: float
    source_detected: bool
    sanitizer_detected: bool
    sanitizer_type: Optional[str]
    taint_path: List[str]
    reasoning: str
    llm_assisted: bool
    fix_suggestion: str = ""

def _check_source(code: str) -> bool:
    for pattern in SOURCE_PATTERNS:
        if re.search(pattern, code):
            return True
    return False

def _check_sanitizer(code: str, vuln_type: str) -> tuple:
    patterns = SANITIZER_PATTERNS.get(vuln_type, [])
    for pattern in patterns:
        if re.search(pattern, code):
            return True, pattern
    return False, None

def _build_taint_path(code: str, finding: SemgrepFinding) -> List[str]:
    path = []
    lines = code.split('\n')
    start = max(0, finding.start_line - 5)
    end = min(len(lines), finding.end_line + 2)

    for i, line in enumerate(lines[start:end], start=start+1):
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            continue
        if any(re.search(p, line) for p in SOURCE_PATTERNS):
            path.append(f"line {i}: {stripped[:80]} [SOURCE]")
        elif re.search(r'[+].*[+]|String\.format|createNativeQuery|\.write\(|new File\(|Paths\.get\(', line):
            path.append(f"line {i}: {stripped[:80]} [SINK]")
        elif re.search(r'String\s+\w+\s*=', line) and i >= finding.start_line - 3:
            path.append(f"line {i}: {stripped[:80]}")

    if not path:
        path.append(f"line {finding.start_line}: {finding.code_snippet[:80]}")
    return path

def analyze_taint(
    finding: SemgrepFinding,
    source_code: str,
    use_llm: bool = False,
    use_mock: bool = True
) -> TaintAnalysisResult:
    """Taint Flow 추적으로 오탐 필터링"""

    lines = source_code.split('\n')
    start = max(0, finding.start_line - 10)
    end = min(len(lines), finding.end_line + 10)
    context_code = '\n'.join(lines[start:end])

    snippet_start = max(0, finding.start_line - 5)
    snippet_end = min(len(lines), finding.end_line + 5)
    if snippet_end - snippet_start > 100:
        snippet_end = snippet_start + 100
    snippet = '\n'.join(lines[snippet_start:snippet_end])

    # 1. Source 패턴 검색
    source_detected = _check_source(context_code)

    # 2. Sanitizer 존재 여부 확인
    sanitizer_detected, sanitizer_type = _check_sanitizer(context_code, finding.vulnerability_type)

    # 3. Taint Path 구성
    taint_path = _build_taint_path(source_code, finding)

    fix_suggestion = FIX_SUGGESTIONS.get(finding.vulnerability_type, "")

    # LLM 위임 조건: 200줄 이상이거나 소스 추적 불가
    needs_llm = (len(lines) > 200) or (not source_detected and not sanitizer_detected)

    if sanitizer_detected and not needs_llm:
        return TaintAnalysisResult(
            finding=finding,
            verdict="FALSE_POSITIVE",
            confidence=0.90,
            source_detected=source_detected,
            sanitizer_detected=True,
            sanitizer_type=sanitizer_type,
            taint_path=taint_path,
            reasoning=f"코드에서 {sanitizer_type} Sanitizer가 감지되었습니다. {finding.vulnerability_type.replace('_', ' ')} 공격이 방지되어 있습니다.",
            llm_assisted=False,
            fix_suggestion=fix_suggestion,
        )

    if source_detected and not sanitizer_detected and not needs_llm:
        if use_llm or use_mock:
            llm_result = analyze_with_llm(
                snippet, finding.vulnerability_type,
                finding.message, finding.rule_id,
                use_mock=use_mock
            )
            return TaintAnalysisResult(
                finding=finding,
                verdict=llm_result.verdict,
                confidence=llm_result.confidence,
                source_detected=source_detected,
                sanitizer_detected=llm_result.sanitizer_detected,
                sanitizer_type=llm_result.sanitizer_type,
                taint_path=taint_path,
                reasoning=llm_result.reasoning,
                llm_assisted=True,
                fix_suggestion=llm_result.fix_suggestion,
            )
        else:
            return TaintAnalysisResult(
                finding=finding,
                verdict="CONFIRMED",
                confidence=0.80,
                source_detected=True,
                sanitizer_detected=False,
                sanitizer_type=None,
                taint_path=taint_path,
                reasoning=f"사용자 입력(Source)이 Sanitizer 없이 {finding.vulnerability_type.replace('_', ' ')} Sink에 도달합니다.",
                llm_assisted=False,
                fix_suggestion=fix_suggestion,
            )

    # LLM에 위임
    llm_result = analyze_with_llm(
        snippet, finding.vulnerability_type,
        finding.message, finding.rule_id,
        use_mock=use_mock
    )
    return TaintAnalysisResult(
        finding=finding,
        verdict=llm_result.verdict,
        confidence=llm_result.confidence,
        source_detected=source_detected or llm_result.source_detected,
        sanitizer_detected=llm_result.sanitizer_detected,
        sanitizer_type=llm_result.sanitizer_type,
        taint_path=taint_path,
        reasoning=llm_result.reasoning,
        llm_assisted=True,
        fix_suggestion=llm_result.fix_suggestion,
    )
