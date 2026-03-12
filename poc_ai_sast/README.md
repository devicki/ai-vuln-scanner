# AI SAST POC

Semgrep + LLM Taint Analysis 2단계 파이프라인으로 Java Spring Boot 코드의 보안 취약점을 탐지하는 POC 프로젝트입니다.

## 개요

AEZIZ의 SCA(Software Composition Analysis) 기능을 보완하여, 개발자가 직접 작성한 코드의 보안 결함(SQL Injection, XSS, Path Traversal)을 탐지합니다.

**2단계 파이프라인:**

1. **Semgrep (1차)** — 커스텀 규칙 기반 패턴 매칭으로 취약점 후보 탐지
2. **LLM Taint Analysis (2차)** — Source → Sanitizer → Sink 흐름을 분석하여 오탐 필터링

## 아키텍처

```
Java Source Code
       │
       ▼
┌─────────────────┐
│  Semgrep Runner  │  ← rules/*.yaml (sqli, xss, path_traversal)
│  (1차 패턴매칭)   │
└────────┬────────┘
         │ SemgrepFinding[]
         ▼
┌─────────────────┐
│  Taint Analyzer  │  ← config/source_sink.yaml
│  (정적 분석)      │
└────────┬────────┘
         │ UNCERTAIN인 경우
         ▼
┌─────────────────┐
│   LLM Taint      │  ← OpenAI API 또는 Mock
│  (2차 오탐필터)   │
└────────┬────────┘
         │ TaintAnalysisResult[]
         ▼
┌─────────────────┐
│  Reporter        │  → JSON + HTML 리포트
└─────────────────┘
```

### 지원 취약점 유형

| 취약점 | CWE | Source 예시 | Sink 예시 |
|--------|-----|-------------|-----------|
| SQL Injection | CWE-89 | `request.getParameter()`, `@RequestParam` | `jdbcTemplate.query()`, `Statement.execute()` |
| XSS | CWE-79 | `request.getParameter()`, `@RequestParam` | `response.getWriter().write()`, `@ResponseBody` |
| Path Traversal | CWE-22 | `request.getParameter()`, `@RequestParam` | `new File()`, `Paths.get()`, `Files.readAllBytes()` |

## 프로젝트 구조

```
poc_ai_sast/
├── main.py                          # CLI 진입점
├── requirements.txt
├── config/
│   └── source_sink.yaml             # Source/Sink/Sanitizer 정의
├── rules/
│   ├── sqli.yaml                    # Semgrep SQL Injection 규칙
│   ├── xss.yaml                     # Semgrep XSS 규칙
│   └── path_traversal.yaml          # Semgrep Path Traversal 규칙
├── src/
│   ├── scanner/semgrep_runner.py    # Semgrep 실행 및 결과 파싱
│   ├── taint/
│   │   ├── source_sink.py           # Source/Sink/Sanitizer 정의 로드
│   │   └── taint_analyzer.py        # Taint Flow 추적
│   ├── llm/llm_taint.py            # LLM 분석 (Mock + OpenAI + Ollama)
│   ├── report/
│   │   ├── reporter.py              # JSON 결과 구조화
│   │   └── html_reporter.py         # HTML 리포트 생성
│   └── api/server.py               # FastAPI REST API
├── tests/
│   ├── sample_code/
│   │   ├── vulnerable/              # 취약한 Java 코드 샘플 (3개)
│   │   └── safe/                    # 안전한 Java 코드 샘플 (3개)
│   ├── test_semgrep.py
│   ├── test_taint.py
│   └── test_pipeline.py
└── benchmark/
    ├── ground_truth.json            # 정답 레이블
    ├── run_benchmark.py             # Precision/Recall 측정
    └── benchmark_result.json        # 벤치마크 결과
```

## 설치

### 요구사항

- Python 3.10+
- Semgrep >= 1.60.0

### 설치 방법

```bash
cd poc_ai_sast

# 가상환경 생성 및 활성화
python3 -m venv .venv
source .venv/bin/activate

# 의존성 설치
pip install -r requirements.txt

# Semgrep 설치 확인
semgrep --version
```

## 실행 방법

### 취약한 코드 스캔

```bash
python main.py --source-dir tests/sample_code/vulnerable
```

### 안전한 코드 스캔 (오탐 0건 확인)

```bash
python main.py --source-dir tests/sample_code/safe
```

### 특정 취약점 유형만 스캔

```bash
python main.py --source-dir tests/sample_code/vulnerable --types sqli xss
```

### HTML 리포트 생성

```bash
python main.py --source-dir tests/sample_code/vulnerable --html-report
```

### LLM 모드 활성화 (OpenAI API 키 필요)

```bash
python main.py --source-dir tests/sample_code/vulnerable --use-llm
```

### 정확도 벤치마크 실행

```bash
python main.py --benchmark
```

### FastAPI 서버 시작

```bash
python main.py --serve --port 8001
```

서버 시작 후:
- `POST http://localhost:8001/scan` — 스캔 실행
- `GET http://localhost:8001/health` — 헬스체크

#### API 사용 예시

```bash
curl -X POST http://localhost:8001/scan \
  -H "Content-Type: application/json" \
  -d '{"source_dir": "tests/sample_code/vulnerable", "output_html": true}'
```

### 테스트 실행

```bash
pytest tests/ -v
```

## 환경변수

| 변수 | 설명 | 기본값 |
|------|------|--------|
| `OPENAI_API_KEY` | OpenAI API 키 (설정 시 실제 LLM 사용) | _(없으면 Mock 모드)_ |
| `LLM_BASE_URL` | OpenAI-compatible API 엔드포인트 (Ollama 등) | _(없으면 OpenAI 사용)_ |
| `LLM_MODEL` | LLM_BASE_URL 사용 시 모델명 | `deepseek-coder` |

- 환경변수가 모두 없으면 규칙 기반 Mock 모드로 동작합니다 (외부 의존성 없음).
- `OPENAI_API_KEY` 설정 시 `gpt-4o-mini` 모델을 사용합니다.
- `LLM_BASE_URL` 설정 시 해당 엔드포인트의 OpenAI-compatible API를 사용합니다.

## Docker 대안 (Semgrep 미설치 환경)

Semgrep을 직접 설치하기 어려운 경우 Docker를 사용할 수 있습니다:

```bash
# Semgrep Docker 실행
docker run --rm -v $(pwd):/src returntocorp/semgrep \
  semgrep --config /src/rules --json /src/tests/sample_code/vulnerable
```

## 벤치마크 결과

```
전체 파이프라인 정확도 리포트
===============================
[1단계] Semgrep 단독 성능:
  - Semgrep 탐지 건수: 5건
  - True Positive: 3건 / False Positive: 2건
  - Precision: 60.0% / Recall: 100.0%

[2단계] LLM 필터링 후 성능:
  - CONFIRMED: 3건 / FALSE_POSITIVE: 2건 / UNCERTAIN: 0건
  - Precision: 100.0% / Recall: 100.0%
  - 오탐 감소율: 100.0%

[성공 기준 달성 여부]
  - Precision ≥ 70%: ✅
  - Recall ≥ 75%: ✅
  - 오탐 감소율 ≥ 30%: ✅
```

## 라이선스

COONTEC AEZIZ 내부 기술 검증용 POC
