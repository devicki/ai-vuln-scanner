#!/usr/bin/env python3
"""CLI entry point for Reachability-Aware SCA POC."""
import argparse
import json
import logging
import sys
from dataclasses import asdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from dotenv import load_dotenv
load_dotenv()

from rich.console import Console
from rich.table import Table
from rich import box

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)
console = Console()


def print_report(report) -> None:
    """Print analysis report with rich formatting."""
    console.print(f"\n[bold cyan]Reachability-Aware SCA Report[/bold cyan]")
    console.print(f"Source Dir: {report.source_dir}")
    console.print(f"Analyzed At: {report.analyzed_at}")
    console.print(f"Files: {report.total_files} | Methods: {report.total_methods}")
    console.print(f"Summary: {report.summary}\n")

    table = Table(box=box.ROUNDED, show_header=True)
    table.add_column("CVE ID", style="bold")
    table.add_column("Library")
    table.add_column("CVSS", justify="right")
    table.add_column("Verdict")
    table.add_column("Confidence", justify="right")
    table.add_column("Call Path / Reasoning")

    verdict_colors = {"Reachable": "red", "Unreachable": "green", "Conditional": "yellow"}

    for r in report.results:
        color = verdict_colors.get(r.verdict, "white")
        path_str = " -> ".join(r.call_path) if r.call_path else r.reasoning[:80]
        table.add_row(
            r.cve_id,
            r.library,
            str(r.cvss),
            f"[{color}]{r.verdict}[/{color}]",
            f"{r.confidence:.0%}",
            path_str,
        )

    console.print(table)


def main():
    parser = argparse.ArgumentParser(
        description="Reachability-Aware SCA POC",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --source-dir tests/sample_projects/reachable
  python main.py --source-dir /path/to/project --cve CVE-2021-44228 CVE-2022-22965
  python main.py --source-dir /path/to/project --all-cves --use-llm
  python main.py --serve
""",
    )
    parser.add_argument("--source-dir", help="Java source directory to analyze")
    parser.add_argument("--cve", nargs="+", metavar="CVE_ID", help="CVE IDs to analyze")
    parser.add_argument("--all-cves", action="store_true", help="Analyze all 5 CVEs")
    parser.add_argument("--use-llm", action="store_true", help="Enable real LLM analysis")
    parser.add_argument("--serve", action="store_true", help="Start FastAPI server on port 8000")
    parser.add_argument("--json", action="store_true", help="Output raw JSON")
    parser.add_argument("--output", help="Save JSON output to file")

    args = parser.parse_args()

    if args.serve:
        import uvicorn
        console.print("[bold green]Starting FastAPI server on http://0.0.0.0:8000[/bold green]")
        uvicorn.run("src.api.server:app", host="0.0.0.0", port=8000, reload=False)
        return

    if not args.source_dir:
        parser.error("--source-dir is required unless using --serve")

    from src.reachability.analyzer import analyze

    cve_ids = None
    if args.cve:
        cve_ids = args.cve
    elif not args.all_cves:
        cve_ids = None  # analyze all by default

    console.print(f"[bold]Analyzing:[/bold] {args.source_dir}")
    if cve_ids:
        console.print(f"[bold]CVEs:[/bold] {', '.join(cve_ids)}")

    report = analyze(
        source_dir=args.source_dir,
        cve_ids=cve_ids,
        use_llm=args.use_llm,
    )

    if args.json:
        print(json.dumps(asdict(report), indent=2, ensure_ascii=False))
    else:
        print_report(report)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(asdict(report), f, indent=2, ensure_ascii=False)
        console.print(f"\n[green]Saved to {args.output}[/green]")


if __name__ == "__main__":
    main()
