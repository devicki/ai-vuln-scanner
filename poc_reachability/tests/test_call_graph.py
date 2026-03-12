"""Tests for Call Graph builder."""
import sys
from pathlib import Path

import networkx as nx
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.parser.java_ast_parser import parse_directory
from src.graph.call_graph import build_call_graph, find_paths_to_target, get_entry_points

REACHABLE_DIR = Path(__file__).parent / "sample_projects" / "reachable"
UNREACHABLE_DIR = Path(__file__).parent / "sample_projects" / "unreachable"


def test_build_call_graph_is_digraph():
    file_asts = parse_directory(str(REACHABLE_DIR))
    graph = build_call_graph(file_asts)
    assert isinstance(graph, nx.DiGraph)


def test_build_call_graph_has_nodes():
    file_asts = parse_directory(str(REACHABLE_DIR))
    graph = build_call_graph(file_asts)
    assert len(graph.nodes) > 0


def test_call_graph_contains_known_methods():
    file_asts = parse_directory(str(REACHABLE_DIR))
    graph = build_call_graph(file_asts)
    nodes = list(graph.nodes)
    assert any("getUser" in n for n in nodes)
    assert any("log" in n for n in nodes)


def test_call_graph_has_edges():
    file_asts = parse_directory(str(REACHABLE_DIR))
    graph = build_call_graph(file_asts)
    assert len(graph.edges) > 0


def test_find_paths_no_target():
    file_asts = parse_directory(str(REACHABLE_DIR))
    graph = build_call_graph(file_asts)
    paths = find_paths_to_target(graph, ["UserController.getUser"], "NonExistent.nowhere")
    assert paths == []


def test_find_paths_empty_entry_points():
    file_asts = parse_directory(str(REACHABLE_DIR))
    graph = build_call_graph(file_asts)
    paths = find_paths_to_target(graph, [], "LogService.log")
    assert paths == []


def test_get_entry_points_returns_list():
    file_asts = parse_directory(str(REACHABLE_DIR))
    graph = build_call_graph(file_asts)
    eps = get_entry_points(graph, file_asts)
    assert isinstance(eps, list)
    assert len(eps) > 0


def test_get_entry_points_contains_controller():
    file_asts = parse_directory(str(REACHABLE_DIR))
    graph = build_call_graph(file_asts)
    eps = get_entry_points(graph, file_asts)
    assert any("UserController" in ep for ep in eps)
