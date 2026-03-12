import os
import json
import logging
import re
from dataclasses import dataclass
from typing import Optional, Literal

logger = logging.getLogger(__name__)

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
    use_mock: bool = True,
    source_detected: bool = False,
    sanitizer_type: Optional[str] = None,
) -> LLMVerdict:
    """LLM Taint Analysis - Mock 또는 실제 LLM 사용

    LLM_PROVIDER 환경변수로 프로바이더 선택:
      claude  → Anthropic Claude API (ANTHROPIC_API_KEY 필요)
      openai  → OpenAI API           (OPENAI_API_KEY 필요)
      ollama  → Ollama 로컬 서버     (LLM_BASE_URL 필요)
    """
    if use_mock:
        return _mock_analyze(code_snippet, vulnerability_type, semgrep_message, rule_id)

    provider = os.environ.get("LLM_PROVIDER", "").lower()

    # 프로바이더 명시 지정
    if provider == "claude":
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if api_key:
            return _call_claude(code_snippet, vulnerability_type, semgrep_message, rule_id, api_key, source_detected, sanitizer_type)
        print("WARNING: LLM_PROVIDER=claude 이지만 ANTHROPIC_API_KEY 미설정. Mock 모드로 폴백")

    elif provider == "openai":
        api_key = os.environ.get("OPENAI_API_KEY")
        if api_key:
            return _call_openai(code_snippet, vulnerability_type, semgrep_message, rule_id, api_key, source_detected, sanitizer_type)
        print("WARNING: LLM_PROVIDER=openai 이지만 OPENAI_API_KEY 미설정. Mock 모드로 폴백")

    elif provider == "ollama":
        base_url = os.environ.get("LLM_BASE_URL")
        if base_url:
            return _call_ollama(code_snippet, vulnerability_type, semgrep_message, rule_id, base_url, source_detected, sanitizer_type)
        print("WARNING: LLM_PROVIDER=ollama 이지만 LLM_BASE_URL 미설정. Mock 모드로 폴백")

    else:
        # LLM_PROVIDER 미설정 시 키 존재 여부로 자동 감지
        anthropic_key = os.environ.get("ANTHROPIC_API_KEY")
        openai_key = os.environ.get("OPENAI_API_KEY")
        base_url = os.environ.get("LLM_BASE_URL")

        if anthropic_key:
            return _call_claude(code_snippet, vulnerability_type, semgrep_message, rule_id, anthropic_key, source_detected, sanitizer_type)
        elif openai_key:
            return _call_openai(code_snippet, vulnerability_type, semgrep_message, rule_id, openai_key, source_detected, sanitizer_type)
        elif base_url:
            return _call_ollama(code_snippet, vulnerability_type, semgrep_message, rule_id, base_url, source_detected, sanitizer_type)

    return _mock_analyze(code_snippet, vulnerability_type, semgrep_message, rule_id)

def _call_claude(code_snippet, vulnerability_type, semgrep_message, rule_id, api_key, source_detected, sanitizer_type) -> LLMVerdict:
    try:
        import anthropic
        claude_model = os.environ.get("CLAUDE_MODEL", "claude-opus-4-6")
        client = anthropic.Anthropic(api_key=api_key)
        prompt = _build_prompt(code_snippet, vulnerability_type, semgrep_message, rule_id, source_detected, sanitizer_type)
        logger.debug("[Claude:%s] prompt INPUT >>>>\n%s\n<<<<", claude_model, prompt)
        with client.messages.stream(
            model=claude_model,
            max_tokens=1024,
            thinking={"type": "adaptive"},
            messages=[{"role": "user", "content": prompt}],
        ) as stream:
            response = stream.get_final_message()
        # text 블록만 추출 (thinking 블록 제외)
        output = next((b.text for b in response.content if b.type == "text"), "")
        logger.debug("[Claude:%s] prompt OUTPUT >>>>\n%s\n<<<<", claude_model, output)
        return _parse_llm_response(output, vulnerability_type)
    except Exception as e:
        print(f"WARNING: Claude API 호출 실패: {e}. Mock 모드로 폴백")
        return _mock_analyze(code_snippet, vulnerability_type, semgrep_message, rule_id)

def _call_openai(code_snippet, vulnerability_type, semgrep_message, rule_id, api_key, source_detected, sanitizer_type) -> LLMVerdict:
    try:
        import openai
        client = openai.OpenAI(api_key=api_key, timeout=300.0)
        prompt = _build_prompt(code_snippet, vulnerability_type, semgrep_message, rule_id, source_detected, sanitizer_type)
        logger.debug("[OpenAI] prompt INPUT >>>>\n%s\n<<<<", prompt)
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1,
        )
        output = response.choices[0].message.content
        logger.debug("[OpenAI] prompt OUTPUT >>>>\n%s\n<<<<", output)
        return _parse_llm_response(output, vulnerability_type)
    except Exception as e:
        print(f"WARNING: OpenAI API 호출 실패: {e}. Mock 모드로 폴백")
        return _mock_analyze(code_snippet, vulnerability_type, semgrep_message, rule_id)

def _call_ollama(code_snippet, vulnerability_type, semgrep_message, rule_id, base_url, source_detected, sanitizer_type) -> LLMVerdict:
    try:
        import openai
        llm_model = os.environ.get("LLM_MODEL", "deepseek-coder")
        # base_url already contains the full path (e.g. http://host:11434/v1)
        client = openai.OpenAI(base_url=base_url, api_key="ollama", timeout=300.0)
        prompt = _build_prompt(code_snippet, vulnerability_type, semgrep_message, rule_id, source_detected, sanitizer_type)
        logger.debug("[Ollama:%s] prompt INPUT >>>>\n%s\n<<<<", llm_model, prompt)
        response = client.chat.completions.create(
            model=llm_model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1,
        )
        output = response.choices[0].message.content
        logger.debug("[Ollama:%s] prompt OUTPUT >>>>\n%s\n<<<<", llm_model, output)
        return _parse_llm_response(output, vulnerability_type)
    except Exception as e:
        print(f"WARNING: Ollama API 호출 실패: {e}. Mock 모드로 폴백")
        return _mock_analyze(code_snippet, vulnerability_type, semgrep_message, rule_id)

def _build_prompt(code_snippet, vulnerability_type, semgrep_message, rule_id,
                  source_detected: bool = False, sanitizer_type: Optional[str] = None) -> str:
    # ---------------------------------------------------------------------------
    # [이전 한국어 프롬프트 — 참고용]
    #
    # """당신은 Java 소스코드 보안 전문가입니다. 다음 코드가 실제 {vulnerability_type} 취약점인지 분석하세요.
    #
    # Semgrep이 탐지한 잠재적 취약점:
    # - 규칙: {rule_id}
    # - 메시지: {semgrep_message}
    #
    # 정적 분석 사전 결과 (참고용):
    # - Source 탐지: {source_info}
    # - Sanitizer 탐지: {sanitizer_info}
    #
    # ※ 위 사전 결과는 단순 패턴 매칭 결과입니다. 실제 코드 흐름을 직접 분석하여 최종 판정하세요.
    #
    # 취약 코드:
    # ```java
    # {code_snippet}
    # ```
    #
    # 분석 요청:
    # 1. 사용자 입력(Source)이 실제로 이 코드에 도달하는가?
    # 2. Source에서 위험한 연산(Sink)까지 경로에 Sanitizer(검증/이스케이프)가 존재하는가?
    # 3. Sanitizer가 있다면 올바르게 적용되었는가? (같은 변수에 적용되었는지 확인)
    # 4. 이것이 실제 취약점(True Positive)인가, 오탐(False Positive)인가?
    #
    # 다음 JSON 형식으로만 답변하세요:
    # {
    #   "verdict": "CONFIRMED|FALSE_POSITIVE|UNCERTAIN",
    #   "confidence": 0.0~1.0,
    #   "source_detected": true|false,
    #   "sanitizer_detected": true|false,
    #   "sanitizer_type": "설명 또는 null",
    #   "reasoning": "한국어로 판정 근거 2~3문장"
    # }
    # """
    # ---------------------------------------------------------------------------

    # 소스 탐지 여부 문자열 (영문)
    source_info = "Detected (user-controlled input flows into the code)" if source_detected else "Not detected"
    # Sanitizer 탐지 여부 문자열 (영문)
    sanitizer_info = f"Detected - {sanitizer_type}" if sanitizer_type else "Not detected"

    # 취약점 유형을 읽기 좋은 형태로 변환 (e.g. sql_injection → SQL Injection)
    vuln_display = vulnerability_type.replace("_", " ").title()

    return f"""You are a Java application security expert. Analyze whether the following code contains a real {vuln_display} vulnerability.

## Semgrep Finding
- Rule   : {rule_id}
- Message: {semgrep_message}

## Static Analysis Pre-results (pattern-matching hints — verify manually)
- Source   : {source_info}
- Sanitizer: {sanitizer_info}

## Code Under Review
```java
{code_snippet}
```

## Analysis Tasks
1. Does user-controlled input (Source) actually reach this code?
2. Is there a sanitizer or validator on the path from Source to the dangerous operation (Sink)?
3. If a sanitizer exists, is it correctly applied to the SAME variable that reaches the Sink?
4. Final verdict: is this a True Positive (real vulnerability) or a False Positive?

## Response Format
Reply with ONLY a JSON object — no markdown fences, no extra text:
{{
  "verdict": "CONFIRMED|FALSE_POSITIVE|UNCERTAIN",
  "confidence": <float 0.0-1.0>,
  "source_detected": <true|false>,
  "sanitizer_detected": <true|false>,
  "sanitizer_type": "<name or null>",
  "reasoning": "<2-3 sentences in Korean explaining the decision>"
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
