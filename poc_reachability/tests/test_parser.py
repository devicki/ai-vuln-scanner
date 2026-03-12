"""Tests for Java AST parser."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.parser.java_ast_parser import parse_file, parse_directory, FileAST

REACHABLE_DIR = Path(__file__).parent / "sample_projects" / "reachable"
UNREACHABLE_DIR = Path(__file__).parent / "sample_projects" / "unreachable"


def test_parse_file_returns_file_ast():
    java_file = REACHABLE_DIR / "UserController.java"
    result = parse_file(str(java_file))
    assert isinstance(result, FileAST)
    assert result.file_path == str(java_file)


def test_parse_file_extracts_classes():
    result = parse_file(str(REACHABLE_DIR / "UserController.java"))
    assert len(result.classes) > 0
    assert "UserController" in result.classes


def test_parse_file_extracts_methods():
    result = parse_file(str(REACHABLE_DIR / "UserController.java"))
    assert len(result.methods) > 0
    assert any("getUser" in m for m in result.methods)


def test_parse_file_extracts_log4j_imports():
    result = parse_file(str(REACHABLE_DIR / "LogService.java"))
    assert len(result.imports) > 0
    assert any("log4j" in imp for imp in result.imports)


def test_parse_file_extracts_jndi_import():
    result = parse_file(str(REACHABLE_DIR / "LogService.java"))
    assert any("JndiLookup" in imp for imp in result.imports)


def test_parse_file_extracts_method_calls():
    result = parse_file(str(REACHABLE_DIR / "LogService.java"))
    assert len(result.method_calls) > 0
    callee_methods = [mc.callee_method for mc in result.method_calls]
    assert "lookup" in callee_methods


def test_parse_directory_reachable():
    results = parse_directory(str(REACHABLE_DIR))
    assert len(results) >= 2
    all_classes = [c for fa in results for c in fa.classes]
    assert "UserController" in all_classes
    assert "LogService" in all_classes


def test_parse_directory_unreachable():
    results = parse_directory(str(UNREACHABLE_DIR))
    assert len(results) >= 2
    all_classes = [c for fa in results for c in fa.classes]
    assert "UserController" in all_classes
    assert "UserService" in all_classes


def test_parse_nonexistent_file():
    result = parse_file("/nonexistent/file.java")
    assert isinstance(result, FileAST)
    assert result.classes == []
