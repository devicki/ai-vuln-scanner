"""LLM assistant for reachability analysis (Mock, Ollama, or Claude)."""
import json
import logging
import os
from dataclasses import dataclass
from typing import List, Literal

logger = logging.getLogger(__name__)

REFLECTION_PATTERNS = ["Class.forName", "Method.invoke", "getDeclaredMethod", "getMethod", "newInstance"]

# LLM 프로바이더 상수
PROVIDER_MOCK = "mock"
PROVIDER_CLAUDE = "claude"
PROVIDER_OLLAMA = "ollama"


@dataclass
class LLMReachabilityResult:
    verdict: Literal["Reachable", "Unreachable", "Conditional"]
    confidence: float
    reasoning: str


class LLMAssistant:
    """LLM-based reachability analyzer. Supports Mock, Ollama, Claude."""

    def __init__(self, use_mock: bool = None):
        # LLM_PROVIDER: 명시적 프로바이더 지정 (claude | ollama | mock)
        # 미설정 시 ANTHROPIC_API_KEY → LLM_BASE_URL → mock 순으로 자동 감지
        llm_provider = os.environ.get("LLM_PROVIDER", "").lower()
        anthropic_api_key = os.environ.get("ANTHROPIC_API_KEY")
        llm_base_url = os.environ.get("LLM_BASE_URL")

        if use_mock is True:
            self.provider = PROVIDER_MOCK
        elif llm_provider == PROVIDER_CLAUDE:
            self.provider = PROVIDER_CLAUDE
            self.anthropic_api_key = anthropic_api_key
            self.model = os.environ.get("CLAUDE_MODEL", "claude-sonnet-4-6")
        elif llm_provider == PROVIDER_OLLAMA:
            self.provider = PROVIDER_OLLAMA
            self.base_url = llm_base_url or "http://localhost:11434/v1"
            self.model = os.environ.get("LLM_MODEL", "codellama")
        elif llm_provider == PROVIDER_MOCK:
            self.provider = PROVIDER_MOCK
        elif anthropic_api_key:
            # LLM_PROVIDER 미설정 시 자동 감지: ANTHROPIC_API_KEY 우선
            self.provider = PROVIDER_CLAUDE
            self.anthropic_api_key = anthropic_api_key
            self.model = os.environ.get("CLAUDE_MODEL", "claude-sonnet-4-6")
        elif llm_base_url:
            # LLM_PROVIDER 미설정 시 자동 감지: LLM_BASE_URL
            self.provider = PROVIDER_OLLAMA
            self.base_url = llm_base_url
            self.model = os.environ.get("LLM_MODEL", "codellama")
        else:
            self.provider = PROVIDER_MOCK

        # 하위 호환성을 위한 use_mock 속성 유지
        self.use_mock = self.provider == PROVIDER_MOCK
        logger.info(f"LLMAssistant init: provider={self.provider}")

    def analyze_reachability(
        self,
        code_snippet: str,
        entry_point: str,
        vulnerable_method: str,
        call_chain_so_far: List[str],
    ) -> LLMReachabilityResult:
        """Analyze reachability using LLM or Mock."""
        if self.provider == PROVIDER_MOCK:
            return self._mock_analyze(code_snippet)
        if self.provider == PROVIDER_CLAUDE:
            return self._claude_analyze(code_snippet, entry_point, vulnerable_method, call_chain_so_far)
        return self._llm_analyze(code_snippet, entry_point, vulnerable_method, call_chain_so_far)

    def _mock_analyze(self, code_snippet: str) -> LLMReachabilityResult:
        for pattern in REFLECTION_PATTERNS:
            if pattern in code_snippet:
                return LLMReachabilityResult(
                    verdict="Conditional",
                    confidence=0.4,
                    reasoning=f"리플렉션 패턴 '{pattern}' 감지 - 동적 호출 가능성 있음",
                )
        return LLMReachabilityResult(
            verdict="Unreachable",
            confidence=0.6,
            reasoning="Mock 분석: 정적 호출 경로에서 취약 메서드 도달 불가",
        )

    def _claude_analyze(
        self,
        code_snippet: str,
        entry_point: str,
        vulnerable_method: str,
        call_chain_so_far: List[str],
    ) -> LLMReachabilityResult:
        """Anthropic Claude API를 이용한 도달 가능성 분석."""
        import anthropic

        prompt = self._build_prompt(code_snippet, entry_point, vulnerable_method, call_chain_so_far)
        logger.info(f"[Claude >>>] model={self.model}")
        logger.info(f"[Claude >>>] prompt=\n{prompt}")

        try:
            client = anthropic.Anthropic(api_key=self.anthropic_api_key)
            message = client.messages.create(
                model=self.model,
                max_tokens=512,
                messages=[{"role": "user", "content": prompt}],
            )
            content = message.content[0].text
            logger.info(f"[Claude <<<] response={content}")
            start = content.find("{")
            end = content.rfind("}") + 1
            if start >= 0 and end > start:
                result = json.loads(content[start:end])
                return LLMReachabilityResult(
                    verdict=result["verdict"],
                    confidence=float(result["confidence"]),
                    reasoning=result["reasoning"],
                )
        except Exception as e:
            logger.warning(f"[Claude !!!] call failed: {e}, falling back to mock")

        return self._mock_analyze(code_snippet)

    def _build_prompt(
        self,
        code_snippet: str,
        entry_point: str,
        vulnerable_method: str,
        call_chain_so_far: List[str],
    ) -> str:
        # [프롬프트 설명 - 한글 번역]
        # 당신은 Java 소스 코드 보안 분석 전문가입니다.
        # 아래 코드를 분석하여 취약한 메서드에 도달 가능한지 판단하세요.
        #
        # 소스 코드: {code_snippet}
        #
        # 진입점(Entry point): {entry_point}
        # 취약 메서드(Vulnerable method): {vulnerable_method}
        # 현재까지의 호출 체인(Call chain so far): {call_chain_so_far}
        #
        # 리플렉션(Class.forName, Method.invoke), 동적 프록시, Spring AOP 사용 여부를 확인하세요.
        # 진입점으로부터 취약 메서드에 도달 가능한지 판단하세요.
        #
        # 중요: 반드시 JSON 객체 하나만 응답하세요. 설명, 마크다운, 추가 텍스트 없이 출력하세요.
        # 출력 형식: {"verdict": "Reachable", "confidence": 0.9, "reasoning": "이유"}
        #
        # verdict는 반드시 Reachable(도달 가능), Unreachable(도달 불가), Conditional(조건부) 중 하나여야 합니다.
        # confidence는 0.0 ~ 1.0 사이의 실수여야 합니다.
        return f"""You are a Java source code security analysis expert.
Analyze the following code and determine if the vulnerable method is reachable.

Source code:
{code_snippet}

Entry point: {entry_point}
Vulnerable method: {vulnerable_method}
Call chain so far: {call_chain_so_far}

Check for reflection (Class.forName, Method.invoke), dynamic proxy, Spring AOP usage.
Determine if the vulnerable method is reachable from the entry point.

IMPORTANT: You MUST respond with ONLY a single JSON object. No explanation, no markdown, no extra text.
Output format:
{{"verdict": "Reachable", "confidence": 0.9, "reasoning": "reason here"}}

verdict must be exactly one of: Reachable, Unreachable, Conditional
confidence must be a float between 0.0 and 1.0"""

    def _llm_analyze(
        self,
        code_snippet: str,
        entry_point: str,
        vulnerable_method: str,
        call_chain_so_far: List[str],
    ) -> LLMReachabilityResult:
        import httpx

        prompt = self._build_prompt(code_snippet, entry_point, vulnerable_method, call_chain_so_far)
        url = f"{self.base_url}/chat/completions"
        payload = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
        }
        logger.info(f"[LLM >>>] POST {url}")
        logger.info(f"[LLM >>>] model={self.model}")
        logger.info(f"[LLM >>>] prompt=\n{prompt}")

        try:
            resp = httpx.post(url, json=payload, timeout=120.0)
            logger.info(f"[LLM <<<] status={resp.status_code}")
            logger.info(f"[LLM <<<] body={resp.text}")
            data = resp.json()
            content = data["choices"][0]["message"]["content"]
            # Extract JSON from response
            start = content.find("{")
            end = content.rfind("}") + 1
            if start >= 0 and end > start:
                result = json.loads(content[start:end])
                return LLMReachabilityResult(
                    verdict=result["verdict"],
                    confidence=float(result["confidence"]),
                    reasoning=result["reasoning"],
                )
        except Exception as e:
            logger.warning(f"[LLM !!!] call failed: {e}, falling back to mock")

        return self._mock_analyze(code_snippet)
