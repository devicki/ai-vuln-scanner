"""Call Graph builder and BFS path finder using NetworkX."""
import logging
from typing import List, Optional

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import networkx as nx

from src.parser.java_ast_parser import FileAST

logger = logging.getLogger(__name__)

# Spring entry point annotations
SPRING_ANNOTATIONS = {"@GetMapping", "@PostMapping", "@PutMapping", "@DeleteMapping", "@RequestMapping"}
SPRING_IMPORT_PATTERNS = ["springframework.web.bind.annotation"]


def build_call_graph(file_asts: List[FileAST]) -> nx.DiGraph:
    """Build a directed call graph from parsed FileASTs."""
    graph = nx.DiGraph()

    # Add all known method nodes first
    for file_ast in file_asts:
        for method in file_ast.methods:
            graph.add_node(method, file_path=file_ast.file_path)

    # Add edges from method calls
    for file_ast in file_asts:
        for mc in file_ast.method_calls:
            caller = f"{mc.caller_class}.{mc.caller_method}"
            # Try to resolve callee with object type
            if mc.callee_object_type:
                callee = f"{mc.callee_object_type}.{mc.callee_method}"
            else:
                callee = mc.callee_method

            # Ensure caller node exists
            if caller not in graph:
                graph.add_node(caller, file_path=mc.file_path)

            # Try to find matching callee node
            resolved = _resolve_callee(graph, callee, mc.callee_method)
            if resolved not in graph:
                graph.add_node(resolved)

            graph.add_edge(
                caller,
                resolved,
                file_path=mc.file_path,
                line_number=mc.line_number,
            )
            logger.debug(f"Edge: {caller} -> {resolved}")

    return graph


def _resolve_callee(graph: nx.DiGraph, callee: str, method_name: str) -> str:
    """Try to resolve callee to an existing graph node."""
    if callee in graph:
        return callee
    # Try finding by method name suffix
    for node in graph.nodes:
        if node.endswith(f".{method_name}"):
            return node
    return callee


def find_paths_to_target(
    graph: nx.DiGraph,
    entry_points: List[str],
    target_method: str,
    max_depth: int = 10,
) -> List[List[str]]:
    """BFS search for all paths from entry_points to target_method."""
    # Resolve target node
    target = _resolve_callee(graph, target_method, target_method.split(".")[-1] if "." in target_method else target_method)
    if target not in graph:
        # Try partial match
        method_part = target_method.split(".")[-1] if "." in target_method else target_method
        candidates = [n for n in graph.nodes if n.endswith(f".{method_part}") or n == method_part]
        if not candidates:
            logger.debug(f"Target '{target_method}' not in graph. Nodes: {list(graph.nodes)[:10]}")
            return []
        target = candidates[0]

    all_paths = []
    for ep in entry_points:
        if ep not in graph:
            continue
        try:
            for path in nx.all_simple_paths(graph, ep, target, cutoff=max_depth):
                all_paths.append(path)
        except nx.NetworkXNoPath:
            pass
        except Exception as e:
            logger.debug(f"Path search error from {ep} to {target}: {e}")

    return all_paths


def get_entry_points(graph: nx.DiGraph, file_asts: List[FileAST]) -> List[str]:
    """Detect Spring entry points from file ASTs."""
    entry_points = []
    seen = set()

    for file_ast in file_asts:
        is_spring = any(
            any(pat in imp for pat in SPRING_IMPORT_PATTERNS)
            for imp in file_ast.imports
        )

        for method in file_ast.methods:
            # main method
            if method.endswith(".main"):
                if method not in seen:
                    entry_points.append(method)
                    seen.add(method)

            # Spring controller methods (heuristic: class is a controller)
            if is_spring:
                cls_name = method.split(".")[0] if "." in method else ""
                if cls_name and ("Controller" in cls_name or "Resource" in cls_name):
                    if method not in seen:
                        entry_points.append(method)
                        seen.add(method)

    # If no entry points found, use all public methods as fallback
    if not entry_points:
        for file_ast in file_asts:
            for method in file_ast.methods:
                if method not in seen:
                    entry_points.append(method)
                    seen.add(method)

    logger.info(f"Entry points detected: {entry_points}")
    return entry_points


def visualize_graph(
    graph: nx.DiGraph,
    highlight_path: List[str],
    output_path: str,
) -> None:
    """Save call graph visualization to file."""
    plt.figure(figsize=(12, 8))
    pos = nx.spring_layout(graph, seed=42)

    highlight_set = set(highlight_path)
    highlight_edges = list(zip(highlight_path[:-1], highlight_path[1:])) if len(highlight_path) > 1 else []

    node_colors = ["red" if n in highlight_set else "lightblue" for n in graph.nodes]
    edge_colors = ["red" if (u, v) in highlight_edges else "gray" for u, v in graph.edges]

    nx.draw(
        graph,
        pos,
        with_labels=True,
        node_color=node_colors,
        edge_color=edge_colors,
        node_size=800,
        font_size=7,
        arrows=True,
    )
    plt.title("Call Graph (red = reachable path)")
    plt.tight_layout()
    plt.savefig(output_path, dpi=100, bbox_inches="tight")
    plt.close()
    logger.info(f"Graph saved to {output_path}")
