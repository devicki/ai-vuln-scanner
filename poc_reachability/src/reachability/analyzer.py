"""Reachability analysis engine."""
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Literal, Optional

import networkx as nx

from src.parser.java_ast_parser import FileAST, parse_directory
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

    # 2. Build base call graph
    graph = build_call_graph(file_asts)

    # 3. Detect entry points
    entry_points = get_entry_points(graph, file_asts)

    # 4. Load CVE mapping
    mapping = load_cve_mapping()
    if not cve_ids:
        cve_ids = get_all_cve_ids(mapping)

    # 5. LLM assistant
    llm = LLMAssistant(use_mock=not use_llm)

    # 6. Analyze each CVE
    results = []
    for cve_id in cve_ids:
        cve_info = get_vulnerable_method(cve_id, mapping)
        if not cve_info:
            logger.warning(f"Unknown CVE: {cve_id}")
            continue

        # Add target node and edges to graph
        target_node = _add_cve_targets(graph, file_asts, cve_info)

        # BFS path search
        paths = find_paths_to_target(graph, entry_points, target_node)

        has_import = _check_imports_vulnerable_lib(file_asts, cve_info)
        has_reflection = _has_reflection(file_asts)

        if paths:
            best_path = min(paths, key=len)
            depth = len(best_path)
            confidence = 0.90 if depth <= 2 else 0.70
            result = CVEReachabilityResult(
                cve_id=cve_id,
                library=cve_info["library"],
                cvss=cve_info["cvss"],
                verdict="Reachable",
                confidence=confidence,
                call_path=best_path,
                entry_point=best_path[0] if best_path else None,
                reasoning=(
                    f"엔트리포인트 {best_path[0]}에서 "
                    f"{' -> '.join(best_path[1:])}를 거쳐 "
                    f"{cve_info['simple_class_name']}.{cve_info['vulnerable_method']}에 "
                    f"{'직접' if depth <= 2 else str(depth-1) + '단계를 거쳐'} 도달하는 경로가 존재합니다."
                ),
            )
        elif has_reflection:
            # LLM assist for conditional case
            code_snippet = _get_all_source_code(file_asts)
            ep = entry_points[0] if entry_points else "unknown"
            llm_result = llm.analyze_reachability(
                code_snippet=code_snippet[:3000],
                entry_point=ep,
                vulnerable_method=f"{cve_info['simple_class_name']}.{cve_info['vulnerable_method']}",
                call_chain_so_far=[],
            )
            result = CVEReachabilityResult(
                cve_id=cve_id,
                library=cve_info["library"],
                cvss=cve_info["cvss"],
                verdict="Conditional",
                confidence=0.4,
                reasoning=f"리플렉션 패턴 감지. LLM 분석: {llm_result.reasoning}",
            )
        elif not has_import:
            result = CVEReachabilityResult(
                cve_id=cve_id,
                library=cve_info["library"],
                cvss=cve_info["cvss"],
                verdict="Unreachable",
                confidence=0.95,
                reasoning=f"취약 라이브러리 {cve_info['library']}의 임포트가 소스코드에 없습니다.",
            )
        else:
            result = CVEReachabilityResult(
                cve_id=cve_id,
                library=cve_info["library"],
                cvss=cve_info["cvss"],
                verdict="Unreachable",
                confidence=0.75,
                reasoning=(
                    f"취약 라이브러리 {cve_info['library']}가 임포트되어 있으나 "
                    f"{cve_info['simple_class_name']}.{cve_info['vulnerable_method']}까지 "
                    "도달하는 호출 경로가 없습니다."
                ),
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
