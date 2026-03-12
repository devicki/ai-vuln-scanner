import os
import json
import re
from dataclasses import dataclass
from typing import Optional, Literal

FIX_SUGGESTIONS = {
    "sql_injection": "PreparedStatement 또는 JdbcTemplate 파라미터 바인딩 사용: jdbcTemplate.queryForList(\"SELECT * FROM users WHERE id = ?\", userId)",
    "xss": "HtmlUtils.htmlEscape() 또는 Thymeleaf th:text 사용하여 출력 이스케이프 처리",
    "path_traversal": "FilenameUtils.getName()으로 파일명만 추출 후 허용 경로(BASE_DIR) 내에 있는지 검증",
}

@dataclass
class LLMVerdict:
    verdict: Literal["CONFIRMED", "FALSE_POSITIVE", "UNCERTAIN"]
    confidence: float
    source_detected: bool
    sanitizer_detected: bool
    sanitizer_type: Optional[str]
    reasoning: str
    fix_suggestion: str

def _mock_analyze(code_snippet: str, vulnerability_type: str, semgrep_message: str, rule_id: str) -> LLMVerdict:
    """Mock LLM 판정 로직"""
    code_lower = code_snippet.lower()

    # False Positive 패턴 검사
    if "preparedstatement" in code_lower or "preparestatement" in code_lower:
        return LLMVerdict(
            verdict="FALSE_POSITIVE", confidence=0.95,
            source_detected=True, sanitizer_detected=True,
            sanitizer_type="PreparedStatement",
            reasoning="PreparedStatement를 사용하여 파라미터화된 쿼리를 실행하고 있습니다. SQL Injection이 방지되어 있어 오탐으로 판정합니다.",
            fix_suggestion=FIX_SUGGESTIONS.get(vulnerability_type, "")
        )

    if "htmlutils.htmlescape" in code_lower or "escapehtml" in code_lower or "stringescapeutils" in code_lower:
        return LLMVerdict(
            verdict="FALSE_POSITIVE", confidence=0.95,
            source_detected=True, sanitizer_detected=True,
            sanitizer_type="HtmlUtils.htmlEscape",
            reasoning="HtmlUtils.htmlEscape()를 사용하여 출력을 이스케이프 처리하고 있습니다. XSS가 방지되어 있어 오탐으로 판정합니다.",
            fix_suggestion=FIX_SUGGESTIONS.get(vulnerability_type, "")
        )

    if "filenameutils.getname" in code_lower or ".normalize()" in code_lower or "getcanonicalpath" in code_lower:
        return LLMVerdict(
            verdict="FALSE_POSITIVE", confidence=0.90,
            source_detected=True, sanitizer_detected=True,
            sanitizer_type="FilenameUtils.getName",
            reasoning="FilenameUtils.getName() 또는 경로 정규화를 통해 Path Traversal이 방지되어 있습니다. 오탐으로 판정합니다.",
            fix_suggestion=FIX_SUGGESTIONS.get(vulnerability_type, "")
        )

    # True Positive 패턴 검사 (+ 연산자로 직접 연결)
    has_concat = ("\" +" in code_snippet or "+ \"" in code_snippet or
                  re.search(r'\w+\s*\+\s*\w+', code_snippet) is not None)
    has_source = any(p in code_lower for p in ["getparameter", "@requestparam", "getheader", "getbody"])

    if has_concat and has_source:
        return LLMVerdict(
            verdict="CONFIRMED", confidence=0.92,
            source_detected=True, sanitizer_detected=False,
            sanitizer_type=None,
            reasoning=f"사용자 입력이 Sanitizer 없이 직접 {vulnerability_type.replace('_', ' ')} 취약점 Sink에 연결되어 있습니다. 실제 취약점으로 판정합니다.",
            fix_suggestion=FIX_SUGGESTIONS.get(vulnerability_type, "")
        )

    if has_concat:
        return LLMVerdict(
            verdict="CONFIRMED", confidence=0.85,
            source_detected=True, sanitizer_detected=False,
            sanitizer_type=None,
            reasoning=f"문자열 연결 패턴이 감지되었습니다. Sanitizer가 없어 {vulnerability_type.replace('_', ' ')} 취약점이 존재할 가능성이 높습니다.",
            fix_suggestion=FIX_SUGGESTIONS.get(vulnerability_type, "")
        )

    return LLMVerdict(
        verdict="UNCERTAIN", confidence=0.5,
        source_detected=False, sanitizer_detected=False,
        sanitizer_type=None,
        reasoning="코드 패턴만으로는 취약점 여부를 확실하게 판정하기 어렵습니다. 추가적인 코드 컨텍스트 분석이 필요합니다.",
        fix_suggestion=FIX_SUGGESTIONS.get(vulnerability_type, "")
    )

def analyze_with_llm(
    code_snippet: str,
    vulnerability_type: str,
    semgrep_message: str,
    rule_id: str,
    use_mock: bool = True
) -> LLMVerdict:
    """LLM Taint Analysis - Mock 또는 실제 LLM 사용"""

    openai_key = os.environ.get("OPENAI_API_KEY")
    llm_base_url = os.environ.get("LLM_BASE_URL")

    if not use_mock and openai_key:
        return _call_openai(code_snippet, vulnerability_type, semgrep_message, rule_id, openai_key)
    elif not use_mock and llm_base_url:
        return _call_ollama(code_snippet, vulnerability_type, semgrep_message, rule_id, llm_base_url)
    else:
        return _mock_analyze(code_snippet, vulnerability_type, semgrep_message, rule_id)

def _call_openai(code_snippet, vulnerability_type, semgrep_message, rule_id, api_key) -> LLMVerdict:
    try:
        import openai
        client = openai.OpenAI(api_key=api_key)
        prompt = _build_prompt(code_snippet, vulnerability_type, semgrep_message, rule_id)
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1,
        )
        return _parse_llm_response(response.choices[0].message.content, vulnerability_type)
    except Exception as e:
        print(f"WARNING: OpenAI API 호출 실패: {e}. Mock 모드로 폴백")
        return _mock_analyze(code_snippet, vulnerability_type, semgrep_message, rule_id)

def _call_ollama(code_snippet, vulnerability_type, semgrep_message, rule_id, base_url) -> LLMVerdict:
    try:
        import openai
        llm_model = os.environ.get("LLM_MODEL", "deepseek-coder")
        client = openai.OpenAI(base_url=f"{base_url}/v1", api_key="ollama")
        prompt = _build_prompt(code_snippet, vulnerability_type, semgrep_message, rule_id)
        response = client.chat.completions.create(
            model=llm_model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1,
        )
        return _parse_llm_response(response.choices[0].message.content, vulnerability_type)
    except Exception as e:
        print(f"WARNING: Ollama API 호출 실패: {e}. Mock 모드로 폴백")
        return _mock_analyze(code_snippet, vulnerability_type, semgrep_message, rule_id)

def _build_prompt(code_snippet, vulnerability_type, semgrep_message, rule_id) -> str:
    return f"""당신은 Java 소스코드 보안 전문가입니다. 다음 코드가 실제 {vulnerability_type} 취약점인지 분석하세요.

Semgrep이 탐지한 잠재적 취약점:
- 규칙: {rule_id}
- 메시지: {semgrep_message}
- 취약 코드:
```java
{code_snippet}
```

분석 요청:
1. 사용자 입력(Source)이 실제로 이 코드에 도달하는가?
2. Source에서 위험한 연산(Sink)까지 경로에 Sanitizer(검증/이스케이프)가 존재하는가?
3. 이것이 실제 취약점(True Positive)인가, 오탐(False Positive)인가?

다음 JSON 형식으로만 답변하세요:
{{
  "verdict": "CONFIRMED|FALSE_POSITIVE|UNCERTAIN",
  "confidence": 0.0~1.0,
  "source_detected": true|false,
  "sanitizer_detected": true|false,
  "sanitizer_type": "설명 또는 null",
  "reasoning": "한국어로 판정 근거 2~3문장"
}}"""

def _parse_llm_response(response_text: str, vulnerability_type: str) -> LLMVerdict:
    try:
        json_match = re.search(r'\{[^{}]+\}', response_text, re.DOTALL)
        if json_match:
            data = json.loads(json_match.group())
            return LLMVerdict(
                verdict=data.get("verdict", "UNCERTAIN"),
                confidence=float(data.get("confidence", 0.5)),
                source_detected=data.get("source_detected", False),
                sanitizer_detected=data.get("sanitizer_detected", False),
                sanitizer_type=data.get("sanitizer_type"),
                reasoning=data.get("reasoning", "LLM 판단 결과"),
                fix_suggestion=FIX_SUGGESTIONS.get(vulnerability_type, "")
            )
    except Exception:
        pass
    return LLMVerdict(
        verdict="UNCERTAIN", confidence=0.5,
        source_detected=False, sanitizer_detected=False,
        sanitizer_type=None,
        reasoning="LLM 응답 파싱 실패. 수동 검토 필요.",
        fix_suggestion=FIX_SUGGESTIONS.get(vulnerability_type, "")
    )
