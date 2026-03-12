# Reachability-Aware SCA POC

COONTEC AEZIZ AI 기능 04 — Reachability-Aware SCA POC  
Tree-sitter Java AST 파싱 + NetworkX BFS Call Graph 탐색 기반 CVE 도달성 판정

---

## 개요

SBOM에 포함된 CVE 중 **실제 코드에서 호출되는 취약 함수**만 선별하여 오탐을 줄입니다.

- **Reachable** : 엔트리포인트 → 취약 메서드까지 호출 경로 존재
- **Unreachable** : 호출 경로 없음
- **Conditional** : 리플렉션 등 정적 분석 한계 케이스

## 지원 CVE

| CVE ID         | Library           | 취약 메서드                             | CVSS |
| -------------- | ----------------- | --------------------------------------- | ---- |
| CVE-2021-44228 | log4j-core        | JndiLookup.lookup                       | 10.0 |
| CVE-2022-22965 | spring-webmvc     | MutablePropertyValues.addPropertyValues | 9.8  |
| CVE-2022-42889 | commons-text      | StringSubstitutor.replace               | 9.8  |
| CVE-2021-22096 | spring-web        | UriUtils.decode                         | 4.3  |
| CVE-2022-22950 | spring-expression | SpelExpressionParser.parseExpression    | 6.5  |

---

## 설치

```bash
cd poc_reachability
pip install --break-system-packages -r requirements.txt
```

---

## 사용법

```bash
# 단일 CVE 분석
python3 main.py --source-dir tests/sample_projects/reachable --cve CVE-2021-44228

# 전체 CVE 분석
python3 main.py --source-dir tests/sample_projects/reachable --all-cves

# LLM 보조 분석 (Ollama 필요)
export LLM_BASE_URL=http://localhost:11434/v1
export LLM_MODEL=codellama
python3 main.py --source-dir tests/sample_projects/reachable --all-cves --use-llm

# JSON 출력
python3 main.py --source-dir tests/sample_projects/reachable --json

# API 서버 시작
python3 main.py --serve
```

## API 서버

```bash
python3 main.py --serve
# http://localhost:8000/docs
```

```bash
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"source_dir": "tests/sample_projects/reachable", "cve_ids": ["CVE-2021-44228"]}'

curl http://localhost:8000/health
```

---

## 테스트

```bash
python3 -m pytest tests/ -v
```

## 벤치마크

```bash
python3 benchmark/run_benchmark.py
```

---

## 샘플 출력

```
Reachability-Aware SCA Report
Source Dir: tests/sample_projects/reachable
Files: 2 | Methods: 2
Summary: {'reachable_count': 1, ...}

╭────────────────┬────────────┬──────┬───────────┬────────────┬──────────────────────────────────╮
│ CVE ID         │ Library    │ CVSS │ Verdict   │ Confidence │ Call Path                        │
├────────────────┼────────────┼──────┼───────────┼────────────┼──────────────────────────────────┤
│ CVE-2021-44228 │ log4j-core │ 10.0 │ Reachable │        70% │ UserController.getUser           │
│                │            │      │           │            │ -> LogService.log                │
│                │            │      │           │            │ -> JndiLookup.lookup             │
╰────────────────┴────────────┴──────┴───────────┴────────────┴──────────────────────────────────╯
```

---

## Benchmark Results

```
=================================================================================
  Reachability-Aware SCA — Benchmark Results
=================================================================================
  Project    CVE ID            Expected     Actual       Conf  OK
---------------------------------------------------------------------------------
  reachable  CVE-2021-44228   Reachable    Reachable    70%   ✓
  unreachable CVE-2021-44228  Unreachable  Unreachable  95%   ✓
=================================================================================
  Accuracy : 100.0%  (2/2)
  SUCCESS: Accuracy 100.0% >= 80% threshold ✓
```

---

_작성일: 2026-03-11 | COONTEC AEZIZ AI 기능 04_
