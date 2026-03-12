#!/usr/bin/env python3
"""Benchmark script for Reachability-Aware SCA accuracy measurement."""
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.reachability.analyzer import analyze

GROUND_TRUTH = {
    str(Path(__file__).parent.parent / "tests" / "sample_projects" / "reachable"): {
        "CVE-2021-44228": "Reachable"
    },
    str(Path(__file__).parent.parent / "tests" / "sample_projects" / "unreachable"): {
        "CVE-2021-44228": "Unreachable"
    },
}


def run_benchmark():
    results = []
    total = 0
    correct = 0

    for source_dir, expected_map in GROUND_TRUTH.items():
        start = time.time()
        report = analyze(source_dir, cve_ids=list(expected_map.keys()))
        elapsed = time.time() - start

        cve_results = {r.cve_id: r for r in report.results}
        for cve_id, expected_verdict in expected_map.items():
            if cve_id in cve_results:
                actual_verdict = cve_results[cve_id].verdict
                is_correct = actual_verdict == expected_verdict
                total += 1
                if is_correct:
                    correct += 1
                results.append({
                    "source_dir": source_dir,
                    "dir_name": Path(source_dir).name,
                    "cve_id": cve_id,
                    "expected": expected_verdict,
                    "actual": actual_verdict,
                    "correct": is_correct,
                    "confidence": cve_results[cve_id].confidence,
                    "elapsed_seconds": round(elapsed, 3),
                })

    accuracy = correct / total if total > 0 else 0.0

    # Print table
    print("\n" + "=" * 90)
    print("  Reachability-Aware SCA — Benchmark Results")
    print("=" * 90)
    header = f"  {'Project':<20} {'CVE ID':<20} {'Expected':<15} {'Actual':<15} {'Conf':>6}  {'OK'}"
    print(header)
    print("-" * 90)
    for r in results:
        ok_mark = "✓" if r["correct"] else "✗"
        print(
            f"  {r['dir_name']:<20} {r['cve_id']:<20} {r['expected']:<15} {r['actual']:<15} "
            f"{r['confidence']:>5.0%}  {ok_mark}"
        )
    print("=" * 90)
    print(f"\n  Accuracy : {accuracy * 100:.1f}%  ({correct}/{total})")
    print(f"  Elapsed  : {sum(r['elapsed_seconds'] for r in results):.2f}s total")

    # Save JSON
    output_path = Path(__file__).parent / "benchmark_result.json"
    benchmark_data = {
        "accuracy": accuracy,
        "correct": correct,
        "total": total,
        "results": results,
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(benchmark_data, f, indent=2, ensure_ascii=False)
    print(f"\n  Results saved to: {output_path}")

    return accuracy


if __name__ == "__main__":
    accuracy = run_benchmark()
    threshold = 0.8
    if accuracy < threshold:
        print(f"\n  WARNING: Accuracy {accuracy * 100:.1f}% < {threshold * 100:.0f}% threshold!")
        sys.exit(1)
    else:
        print(f"\n  SUCCESS: Accuracy {accuracy * 100:.1f}% >= {threshold * 100:.0f}% threshold ✓")
