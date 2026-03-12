#!/usr/bin/env python3
"""AI SAST POC - CLI entry point."""
import argparse
import json
import os
import sys
import time

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)
from dotenv import load_dotenv

load_dotenv()

from src.report.html_reporter import generate_html_report
from src.report.reporter import generate_report, report_to_dict
from src.scanner.semgrep_runner import check_semgrep_installed, run_semgrep
from src.taint.taint_analyzer import analyze_taint


def scan(
    source_dir: str,
    vuln_types: list = None,
    use_llm: bool = False,
    use_mock: bool = True,
    html_report: bool = False,
):
    """Run the full SAST pipeline."""
    rules_dir = os.path.join(PROJECT_ROOT, "rules")

    try:
        from rich.console import Console
        from rich.table import Table

        console = Console()
        use_rich = True
    except ImportError:
        console = None
        use_rich = False

    # 1. Run Semgrep
    if use_rich:
        console.print("[bold blue]1단계:[/] Semgrep 스캔 실행 중...", end=" ")
    else:
        print("1단계: Semgrep 스캔 실행 중...", end=" ")

    start = time.time()
    findings = run_semgrep(source_dir, rules_dir)

    if vuln_types:
        type_map = {
            "sqli": "sql_injection",
            "xss": "xss",
            "path": "path_traversal",
            "sql_injection": "sql_injection",
            "path_traversal": "path_traversal",
        }
        allowed = {type_map.get(t, t) for t in vuln_types}
        findings = [f for f in findings if f.vulnerability_type in allowed]

    if use_rich:
        console.print(f"[green]{len(findings)}건 탐지[/]")
    else:
        print(f"{len(findings)}건 탐지")

    # 2. Count files
    total_files = 0
    for root, _dirs, files in os.walk(source_dir):
        total_files += sum(1 for f in files if f.endswith(".java"))

    semgrep_count = len(findings)

    # 3. Taint analysis
    if use_rich:
        console.print("[bold blue]2단계:[/] Taint Analysis 실행 중...", end=" ")
    else:
        print("2단계: Taint Analysis 실행 중...", end=" ")

    taint_results = []
    error_files = []
    for finding in findings:
        try:
            if os.path.isfile(finding.file_path):
                with open(
                    finding.file_path, "r", encoding="utf-8", errors="ignore"
                ) as fp:
                    source_code = fp.read()
            else:
                source_code = finding.code_snippet
            result = analyze_taint(
                finding, source_code, use_llm=use_llm, use_mock=use_mock
            )
            taint_results.append(result)
        except Exception as e:
            error_files.append(finding.file_path)
            print(f"\n  WARNING: {finding.file_path}: {e}")

    elapsed = time.time() - start

    if use_rich:
        console.print("[green]완료[/]")
    else:
        print("완료")

    # 4. Generate report
    report = generate_report(source_dir, taint_results, total_files, semgrep_count)

    # 5. Display results
    print()
    print("=" * 60)
    print("  AI SAST 분석 결과")
    print("=" * 60)
    print(f"  분석 대상: {source_dir}")
    print(f"  분석 파일: {total_files}개")
    print(f"  Semgrep 탐지: {semgrep_count}건")
    print(f"  분석 시간: {elapsed:.2f}초")
    print()

    confirmed = [r for r in taint_results if r.verdict == "CONFIRMED"]
    fp = [r for r in taint_results if r.verdict == "FALSE_POSITIVE"]
    uncertain = [r for r in taint_results if r.verdict == "UNCERTAIN"]

    if use_rich:
        table = Table(title="분석 결과 요약")
        table.add_column("판정", style="bold")
        table.add_column("건수", justify="right")
        table.add_row("[red]CONFIRMED[/]", str(len(confirmed)))
        table.add_row("[green]FALSE_POSITIVE[/]", str(len(fp)))
        table.add_row("[yellow]UNCERTAIN[/]", str(len(uncertain)))
        console.print(table)
    else:
        print(f"  CONFIRMED: {len(confirmed)}건")
        print(f"  FALSE_POSITIVE: {len(fp)}건")
        print(f"  UNCERTAIN: {len(uncertain)}건")

    print()

    for r in taint_results:
        verdict_mark = {
            "CONFIRMED": "🔴",
            "FALSE_POSITIVE": "🟢",
            "UNCERTAIN": "🟡",
        }.get(r.verdict, "⚪")
        print(
            f"  {verdict_mark} [{r.verdict}] {r.finding.file_path}:{r.finding.start_line}"
        )
        print(
            f"     {r.finding.vulnerability_type.replace('_', ' ').upper()} | confidence={r.confidence}"
        )
        print(f"     {r.reasoning[:100]}")
        if r.fix_suggestion:
            print(f"     Fix: {r.fix_suggestion[:100]}")
        print()

    if error_files:
        print(f"  ⚠️  오류 발생 파일: {', '.join(error_files)}")

    # 6. Save JSON result
    json_path = os.path.join(source_dir, "sast_result.json")
    try:
        report_dict = report_to_dict(report)
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(report_dict, f, indent=2, ensure_ascii=False)
        print(f"  JSON 결과: {json_path}")
    except Exception:
        json_path = os.path.join(PROJECT_ROOT, "sast_result.json")
        report_dict = report_to_dict(report)
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(report_dict, f, indent=2, ensure_ascii=False)
        print(f"  JSON 결과: {json_path}")

    # 7. HTML report
    if html_report:
        try:
            html_path = os.path.join(source_dir, "sast_report.html")
            generate_html_report(report, html_path)
            print(f"  HTML 리포트: {html_path}")
        except Exception:
            html_path = os.path.join(PROJECT_ROOT, "sast_report.html")
            generate_html_report(report, html_path)
            print(f"  HTML 리포트: {html_path}")

    return report


def serve(port: int = 8001):
    """Start the FastAPI server."""
    import uvicorn

    print(f"Starting AI SAST API server on port {port}...")
    uvicorn.run("src.api.server:app", host="0.0.0.0", port=port, reload=False)


def benchmark():
    """Run the accuracy benchmark."""
    from benchmark.run_benchmark import run_benchmark

    run_benchmark()


def main():
    parser = argparse.ArgumentParser(
        description="AI SAST POC - Semgrep + LLM Taint Analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --source-dir tests/sample_code/vulnerable
  python main.py --source-dir tests/sample_code/safe
  python main.py --source-dir tests/sample_code/ --html-report
  python main.py --source-dir tests/sample_code/ --types sqli xss
  python main.py --benchmark
  python main.py --serve --port 8001
""",
    )

    parser.add_argument("--source-dir", type=str, help="Java 소스코드 디렉토리 경로")
    parser.add_argument(
        "--types", nargs="+", help="탐지할 취약점 유형 (sqli, xss, path)"
    )
    parser.add_argument("--use-llm", action="store_true", help="실제 LLM API 사용")
    parser.add_argument("--html-report", action="store_true", help="HTML 리포트 생성")
    parser.add_argument("--benchmark", action="store_true", help="정확도 벤치마크 실행")
    parser.add_argument("--serve", action="store_true", help="FastAPI 서버 시작")
    parser.add_argument("--port", type=int, default=8001, help="서버 포트 (기본: 8001)")

    args = parser.parse_args()

    check_semgrep_installed()

    if args.benchmark:
        benchmark()
    elif args.serve:
        serve(args.port)
    elif args.source_dir:
        if args.use_llm:
            import logging
            logging.basicConfig(
                level=logging.DEBUG,
                format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
            )
        scan(
            source_dir=args.source_dir,
            vuln_types=args.types,
            use_llm=args.use_llm,
            use_mock=not args.use_llm,
            html_report=args.html_report,
        )
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
