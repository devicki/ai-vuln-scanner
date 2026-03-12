"""Reachability analysis engine."""
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Literal, Optional

import networkx as nx

from src.parser.java_ast_parser import FileAST, parse_directory
from src.parser.pom_parser import find_dependencies, is_version_affected
from src.graph.call_graph import build_call_graph, find_paths_to_target, get_entry_points
from src.cve.cve_mapper import load_cve_mapping, get_all_cve_ids, get_vulnerable_method
from src.llm.llm_assistant import LLMAssistant

logger = logging.getLogger(__name__)

REFLECTION_PATTERNS = ["Class.forName", "Method.invoke", "getDeclaredMethod", "getMethod", "newInstance"]


@dataclass
class CVEReachabilityResult:
    cve_id: str
    library: str
    cvss: float
    verdict: Literal["Reachable", "Unreachable", "Conditional"]
    confidence: float
    call_path: List[str] = field(default_factory=list)
    entry_point: Optional[str] = None
    reasoning: str = ""


@dataclass
class ReachabilityReport:
    source_dir: str
    analyzed_at: str
    total_files: int
    total_methods: int
    results: List[CVEReachabilityResult] = field(default_factory=list)
    summary: dict = field(default_factory=dict)


def _has_reflection(file_asts: List[FileAST]) -> bool:
    for fa in file_asts:
        for mc in fa.method_calls:
            if mc.callee_method in ("forName", "invoke", "getDeclaredMethod", "getMethod", "newInstance"):
                return True
    return False


def _get_all_source_code(file_asts: List[FileAST]) -> str:
    snippets = []
    for fa in file_asts:
        try:
            snippets.append(Path(fa.file_path).read_text(encoding="utf-8", errors="replace"))
        except Exception:
            pass
    return "\n".join(snippets)


def _add_cve_targets(
    graph: nx.DiGraph,
    file_asts: List[FileAST],
    cve_info: dict,
) -> str:
    """Add CVE target node and edges from method calls that invoke the vulnerable method."""
    simple_class = cve_info["simple_class_name"]
    vuln_method = cve_info["vulnerable_method"]
    target_node = f"{simple_class}.{vuln_method}"

    graph.add_node(target_node, is_vulnerable=True)

    # Find files that import the vulnerable library
    vuln_class_parts = cve_info["vulnerable_class"].lower().split(".")
    lib_package = ".".join(vuln_class_parts[:-1]) if len(vuln_class_parts) > 1 else ""

    for fa in file_asts:
        imports_vuln = any(
            simple_class.lower() in imp.lower() or (lib_package and lib_package in imp.lower())
            for imp in fa.imports
        )
        if not imports_vuln:
            continue
        for mc in fa.method_calls:
            if mc.callee_method == vuln_method:
                caller = f"{mc.caller_class}.{mc.caller_method}"
                if caller not in graph:
                    graph.add_node(caller)
                graph.add_edge(
                    caller,
                    target_node,
                    file_path=mc.file_path,
                    line_number=mc.line_number,
                )
                logger.debug(f"CVE edge: {caller} -> {target_node}")

    return target_node


def _check_imports_vulnerable_lib(file_asts: List[FileAST], cve_info: dict) -> bool:
    simple_class = cve_info["simple_class_name"]
    lib_package = ".".join(cve_info["vulnerable_class"].lower().split(".")[:-1])
    for fa in file_asts:
        for imp in fa.imports:
            if simple_class.lower() in imp.lower() or (lib_package and lib_package in imp.lower()):
                return True
    return False


def analyze(
    source_dir: str,
    cve_ids: List[str] = None,
    use_llm: bool = False,
) -> ReachabilityReport:
    """Run reachability analysis on a Java project directory."""
    logger.info(f"Analyzing: {source_dir}")

    # 1. Parse source files
    file_asts = parse_directory(source_dir)
    total_files = len(file_asts)
    total_methods = sum(len(fa.methods) for fa in file_asts)
    logger.info(f"Parsed {total_files} files, {total_methods} methods")
    if total_files == 0:
        logger.warning(f"[!] '{source_dir}' 에서 .java 파일을 찾지 못했습니다. 경로를 확인하세요.")

    # 2. Parse build files (pom.xml / build.gradle) for dependency versions
    dependencies = find_dependencies(source_dir)
    dep_index = {(d.group_id, d.artifact_id): d for d in dependencies}
    if dependencies:
        logger.info(f"의존성 {len(dependencies)}개 발견: {[str(d) for d in dependencies]}")
    else:
        logger.warning("pom.xml / build.gradle 없음 → import 기반 fallback 사용")

    # 3. Build base call graph
    graph = build_call_graph(file_asts)

    # 4. Detect entry points
    entry_points = get_entry_points(graph, file_asts)
    logger.info(f"Entry points ({len(entry_points)}): {entry_points[:5]}")

    # 5. Load CVE mapping
    mapping = load_cve_mapping()
    if not cve_ids:
        cve_ids = get_all_cve_ids(mapping)

    # 6. LLM assistant
    llm = LLMAssistant(use_mock=not use_llm)

    # 6. Analyze each CVE
    results = []
    for cve_id in cve_ids:
        cve_info = get_vulnerable_method(cve_id, mapping)
        if not cve_info:
            logger.warning(f"Unknown CVE: {cve_id}")
            continue

        # 의존성 버전 체크 (pom.xml / build.gradle 기반)
        group_id = cve_info.get("group_id", "")
        artifact_id = cve_info.get("artifact_id", "")
        dep = dep_index.get((group_id, artifact_id))

        if dependencies:
            # 빌드 파일이 있으면 의존성 기반으로 판단
            if dep is None:
                logger.info(f"[{cve_id}] {artifact_id} 의존성 없음 → Unreachable 확정")
                results.append(CVEReachabilityResult(
                    cve_id=cve_id,
                    library=cve_info["library"],
                    cvss=cve_info["cvss"],
                    verdict="Unreachable",
                    confidence=0.97,
                    reasoning=f"빌드 파일에 {artifact_id} 의존성이 없습니다.",
                ))
                continue

            affected_versions = cve_info.get("affected_versions", [])
            if dep.version and len(affected_versions) == 2:
                affected = is_version_affected(dep.version, affected_versions[0], affected_versions[1])
                if affected is False:
                    logger.info(f"[{cve_id}] {artifact_id}:{dep.version} 는 영향받는 버전 범위 밖 → Unreachable")
                    results.append(CVEReachabilityResult(
                        cve_id=cve_id,
                        library=cve_info["library"],
                        cvss=cve_info["cvss"],
                        verdict="Unreachable",
                        confidence=0.92,
                        reasoning=(
                            f"{artifact_id} 버전 {dep.version}은 "
                            f"영향받는 버전 범위({affected_versions[0]} ~ {affected_versions[1]})에 해당하지 않습니다."
                        ),
                    ))
                    continue
                elif affected is True:
                    logger.info(f"[{cve_id}] {artifact_id}:{dep.version} 영향받는 버전 범위 내 → 정적 분석 진행")
                else:
                    logger.info(f"[{cve_id}] {artifact_id}:{dep.version} 버전 비교 불가 → 정적 분석 진행")
            else:
                logger.info(f"[{cve_id}] {artifact_id} 버전 정보 없음 → 정적 분석 진행")
        else:
            # 빌드 파일 없으면 기존 import 기반 fallback
            has_import_fallback = _check_imports_vulnerable_lib(file_asts, cve_info)
            if not has_import_fallback:
                logger.info(f"[{cve_id}] import 없음(빌드파일 없음) → Unreachable 확정")
                results.append(CVEReachabilityResult(
                    cve_id=cve_id,
                    library=cve_info["library"],
                    cvss=cve_info["cvss"],
                    verdict="Unreachable",
                    confidence=0.80,
                    reasoning=f"빌드 파일 없음. 소스코드 import에서 {cve_info['library']} 미발견.",
                ))
                continue

        # Add target node and edges to graph
        target_node = _add_cve_targets(graph, file_asts, cve_info)

        # BFS path search
        paths = find_paths_to_target(graph, entry_points, target_node)

        has_reflection = _has_reflection(file_asts)

        code_snippet = _get_all_source_code(file_asts)
        ep = entry_points[0] if entry_points else "unknown"
        logger.info(f"[{cve_id}] code_snippet length={len(code_snippet)}, entry_point={ep}")

        if paths:
            best_path = min(paths, key=len)
            depth = len(best_path)
            confidence = 0.90 if depth <= 2 else 0.70
            static_reasoning = (
                f"엔트리포인트 {best_path[0]}에서 "
                f"{' -> '.join(best_path[1:])}를 거쳐 "
                f"{cve_info['simple_class_name']}.{cve_info['vulnerable_method']}에 "
                f"{'직접' if depth <= 2 else str(depth-1) + '단계를 거쳐'} 도달하는 경로가 존재합니다."
            )
            if use_llm:
                llm_result = llm.analyze_reachability(
                    code_snippet=code_snippet[:3000],
                    entry_point=ep,
                    vulnerable_method=f"{cve_info['simple_class_name']}.{cve_info['vulnerable_method']}",
                    call_chain_so_far=best_path,
                )
                verdict = llm_result.verdict
                confidence = llm_result.confidence
                reasoning = f"[정적분석] {static_reasoning} / [LLM] {llm_result.reasoning}"
            else:
                verdict = "Reachable"
                reasoning = static_reasoning
            result = CVEReachabilityResult(
                cve_id=cve_id,
                library=cve_info["library"],
                cvss=cve_info["cvss"],
                verdict=verdict,
                confidence=confidence,
                call_path=best_path,
                entry_point=best_path[0] if best_path else None,
                reasoning=reasoning,
            )
        elif has_reflection:
            if use_llm:
                llm_result = llm.analyze_reachability(
                    code_snippet=code_snippet[:3000],
                    entry_point=ep,
                    vulnerable_method=f"{cve_info['simple_class_name']}.{cve_info['vulnerable_method']}",
                    call_chain_so_far=[],
                )
                verdict = llm_result.verdict
                confidence = llm_result.confidence
                reasoning = f"리플렉션 패턴 감지. LLM 분석: {llm_result.reasoning}"
            else:
                verdict = "Conditional"
                confidence = 0.4
                reasoning = "리플렉션 패턴 감지 - 동적 호출 가능성 있음"
            result = CVEReachabilityResult(
                cve_id=cve_id,
                library=cve_info["library"],
                cvss=cve_info["cvss"],
                verdict=verdict,
                confidence=confidence,
                reasoning=reasoning,
            )
        else:
            # import는 있으나 정적 경로 없음 → LLM으로 보완 분석
            if use_llm:
                imports_info = ", ".join(
                    imp for fa in file_asts for imp in fa.imports
                )
                llm_result = llm.analyze_reachability(
                    code_snippet=code_snippet[:3000],
                    entry_point=ep,
                    vulnerable_method=f"{cve_info['simple_class_name']}.{cve_info['vulnerable_method']}",
                    call_chain_so_far=[],
                )
                reasoning = f"정적 경로 없음(임포트 존재). LLM 분석: {llm_result.reasoning}"
                verdict = llm_result.verdict
                confidence = llm_result.confidence
            else:
                verdict = "Unreachable"
                confidence = 0.75
                reasoning = (
                    f"취약 라이브러리 {cve_info['library']}가 임포트되어 있으나 "
                    f"{cve_info['simple_class_name']}.{cve_info['vulnerable_method']}까지 "
                    "도달하는 호출 경로가 없습니다."
                )
            result = CVEReachabilityResult(
                cve_id=cve_id,
                library=cve_info["library"],
                cvss=cve_info["cvss"],
                verdict=verdict,
                confidence=confidence,
                reasoning=reasoning,
            )

        logger.info(f"{cve_id}: {result.verdict} (confidence={result.confidence:.2f})")
        results.append(result)

    summary = {
        "reachable_count": sum(1 for r in results if r.verdict == "Reachable"),
        "unreachable_count": sum(1 for r in results if r.verdict == "Unreachable"),
        "conditional_count": sum(1 for r in results if r.verdict == "Conditional"),
    }

    return ReachabilityReport(
        source_dir=source_dir,
        analyzed_at=datetime.now(timezone.utc).isoformat(),
        total_files=total_files,
        total_methods=total_methods,
        results=results,
        summary=summary,
    )
