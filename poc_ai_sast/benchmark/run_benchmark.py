#!/usr/bin/env python3
"""Benchmark script for AI SAST POC - measures Precision/Recall."""
import json
import os
import sys
import time

# Ensure project root is in path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.scanner.semgrep_runner import run_semgrep
from src.taint.taint_analyzer import analyze_taint


def load_ground_truth(path: str = None) -> dict:
    if path is None:
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ground_truth.json")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def run_benchmark(use_mock: bool = True):
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    rules_dir = os.path.join(base_dir, "rules")
    sample_dir = os.path.join(base_dir, "tests", "sample_code")
    ground_truth = load_ground_truth()

    print("=" * 60)
    print("  전체 파이프라인 정확도 리포트")
    print("=" * 60)
    print()

    start_time = time.time()

    # Run semgrep on all sample code
    findings = run_semgrep(sample_dir, rules_dir)

    # Build ground truth sets
    gt_vuln_files = set()
    gt_safe_files = set()
    for file_key, gt in ground_truth.items():
        full_path = os.path.join(base_dir, file_key)
        if gt["expected_findings"]:
            gt_vuln_files.add(full_path)
        else:
            gt_safe_files.add(full_path)

    # Semgrep standalone metrics
    semgrep_tp = 0
    semgrep_fp = 0
    semgrep_files_detected = set()

    for f in findings:
        abs_path = os.path.abspath(f.file_path)
        semgrep_files_detected.add(abs_path)
        if abs_path in gt_vuln_files:
            semgrep_tp += 1
        else:
            semgrep_fp += 1

    semgrep_fn = len(gt_vuln_files - semgrep_files_detected)
    semgrep_total = len(findings)
    semgrep_precision = semgrep_tp / (semgrep_tp + semgrep_fp) if (semgrep_tp + semgrep_fp) > 0 else 0
    semgrep_recall = semgrep_tp / (semgrep_tp + semgrep_fn) if (semgrep_tp + semgrep_fn) > 0 else 0

    print("[1단계] Semgrep 단독 성능:")
    print(f"  - Semgrep 탐지 건수: {semgrep_total}건")
    print(f"  - True Positive: {semgrep_tp}건 / False Positive: {semgrep_fp}건")
    print(f"  - Precision: {semgrep_precision*100:.1f}% / Recall: {semgrep_recall*100:.1f}%")
    print()

    # Taint analysis
    taint_results = []
    for f in findings:
        try:
            with open(f.file_path, "r", encoding="utf-8") as fp:
                source_code = fp.read()
            result = analyze_taint(f, source_code, use_mock=use_mock)
            taint_results.append(result)
        except Exception as e:
            print(f"  WARNING: Failed to analyze {f.file_path}: {e}")

    # LLM filtering metrics
    confirmed = [r for r in taint_results if r.verdict == "CONFIRMED"]
    false_positive = [r for r in taint_results if r.verdict == "FALSE_POSITIVE"]
    uncertain = [r for r in taint_results if r.verdict == "UNCERTAIN"]

    # Count true positives after LLM filtering
    llm_tp = 0
    llm_fp = 0
    for r in confirmed:
        abs_path = os.path.abspath(r.finding.file_path)
        if abs_path in gt_vuln_files:
            llm_tp += 1
        else:
            llm_fp += 1

    # Missed vulnerabilities (FN) = vuln files not confirmed
    confirmed_files = {os.path.abspath(r.finding.file_path) for r in confirmed}
    llm_fn = len(gt_vuln_files - confirmed_files)

    llm_precision = llm_tp / (llm_tp + llm_fp) if (llm_tp + llm_fp) > 0 else 0
    llm_recall = llm_tp / (llm_tp + llm_fn) if (llm_tp + llm_fn) > 0 else 0

    # FP reduction rate
    fp_reduction = ((semgrep_fp - llm_fp) / semgrep_fp * 100) if semgrep_fp > 0 else 0

    elapsed = time.time() - start_time
    total_files = len(ground_truth)
    per_file = elapsed / total_files if total_files > 0 else 0

    print("[2단계] LLM 필터링 후 성능:")
    print(f"  - CONFIRMED: {len(confirmed)}건 / FALSE_POSITIVE: {len(false_positive)}건 / UNCERTAIN: {len(uncertain)}건")
    print(f"  - Precision: {llm_precision*100:.1f}% / Recall: {llm_recall*100:.1f}%")
    print(f"  - 오탐 감소율: {fp_reduction:.1f}%")
    print()

    print("[처리 시간]")
    print(f"  - 총 분석 시간: {elapsed:.2f}초")
    print(f"  - 파일당 평균: {per_file:.2f}초")
    print()

    # Success criteria
    precision_ok = llm_precision >= 0.70
    recall_ok = llm_recall >= 0.75
    fp_ok = fp_reduction >= 30

    print("[성공 기준 달성 여부]")
    print(f"  - Precision >= 70%: {'✅' if precision_ok else '❌'} ({llm_precision*100:.1f}%)")
    print(f"  - Recall >= 75%: {'✅' if recall_ok else '❌'} ({llm_recall*100:.1f}%)")
    print(f"  - 오탐 감소율 >= 30%: {'✅' if fp_ok else '❌'} ({fp_reduction:.1f}%)")
    print()

    # Save result
    result = {
        "semgrep_standalone": {
            "total_findings": semgrep_total,
            "true_positive": semgrep_tp,
            "false_positive": semgrep_fp,
            "precision": round(semgrep_precision, 4),
            "recall": round(semgrep_recall, 4),
        },
        "llm_filtered": {
            "confirmed": len(confirmed),
            "false_positive": len(false_positive),
            "uncertain": len(uncertain),
            "true_positive": llm_tp,
            "false_positive_actual": llm_fp,
            "precision": round(llm_precision, 4),
            "recall": round(llm_recall, 4),
            "fp_reduction_rate": round(fp_reduction, 2),
        },
        "timing": {
            "total_seconds": round(elapsed, 2),
            "per_file_seconds": round(per_file, 2),
        },
        "success_criteria": {
            "precision_70": precision_ok,
            "recall_75": recall_ok,
            "fp_reduction_30": fp_ok,
            "all_passed": precision_ok and recall_ok and fp_ok,
        },
    }

    result_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "benchmark_result.json")
    with open(result_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    print(f"결과 저장: {result_path}")

    return result


if __name__ == "__main__":
    run_benchmark()
