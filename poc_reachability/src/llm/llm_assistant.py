"""LLM assistant for reachability analysis (Mock or real Ollama)."""
import json
import logging
import os
from dataclasses import dataclass
from typing import List, Literal

logger = logging.getLogger(__name__)

REFLECTION_PATTERNS = ["Class.forName", "Method.invoke", "getDeclaredMethod", "getMethod", "newInstance"]


@dataclass
class LLMReachabilityResult:
    verdict: Literal["Reachable", "Unreachable", "Conditional"]
    confidence: float
    reasoning: str


class LLMAssistant:
    """LLM-based reachability analyzer. Defaults to Mock mode."""

    def __init__(self, use_mock: bool = None):
        llm_base_url = os.environ.get("LLM_BASE_URL")
        if use_mock is None:
            self.use_mock = llm_base_url is None
        else:
            self.use_mock = use_mock
        self.base_url = llm_base_url or "http://localhost:11434/v1"
        self.model = os.environ.get("LLM_MODEL", "codellama")
        logger.info(f"LLMAssistant init: use_mock={self.use_mock}, base_url={self.base_url}")

    def analyze_reachability(
        self,
        code_snippet: str,
        entry_point: str,
        vulnerable_method: str,
        call_chain_so_far: List[str],
    ) -> LLMReachabilityResult:
        """Analyze reachability using LLM or Mock."""
        if self.use_mock:
            return self._mock_analyze(code_snippet)
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

    def _llm_analyze(
        self,
        code_snippet: str,
        entry_point: str,
        vulnerable_method: str,
        call_chain_so_far: List[str],
    ) -> LLMReachabilityResult:
        import httpx

        prompt = f"""You are a Java source code security analysis expert.
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
