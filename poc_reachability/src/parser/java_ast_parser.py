"""Java AST Parser using tree-sitter."""
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from tree_sitter import Language, Parser, Node
import tree_sitter_java as tsjava

logger = logging.getLogger(__name__)

JAVA_LANGUAGE = Language(tsjava.language())
_parser = Parser(JAVA_LANGUAGE)


@dataclass
class MethodCall:
    caller_class: str
    caller_method: str
    callee_method: str
    callee_object_type: Optional[str]
    line_number: int
    file_path: str


@dataclass
class FileAST:
    file_path: str
    classes: List[str] = field(default_factory=list)
    methods: List[str] = field(default_factory=list)       # "ClassName.methodName"
    method_calls: List[MethodCall] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)


def _get_text(node: Node, source: bytes) -> str:
    return source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _collect_nodes(node: Node, kind: str) -> List[Node]:
    results = []
    if node.type == kind:
        results.append(node)
    for child in node.children:
        results.extend(_collect_nodes(child, kind))
    return results


def _collect_nodes_multi(node: Node, kinds: set) -> List[Node]:
    results = []
    if node.type in kinds:
        results.append(node)
    for child in node.children:
        results.extend(_collect_nodes_multi(child, kinds))
    return results


def _find_child_by_type(node: Node, kind: str) -> Optional[Node]:
    for child in node.children:
        if child.type == kind:
            return child
    return None


def _find_children_by_type(node: Node, kind: str) -> List[Node]:
    return [c for c in node.children if c.type == kind]


def parse_file(file_path: str) -> FileAST:
    """Parse a Java source file and return FileAST."""
    path = Path(file_path)
    try:
        source = path.read_bytes()
    except Exception as e:
        logger.warning(f"Cannot read {file_path}: {e}")
        return FileAST(file_path=file_path)

    try:
        tree = _parser.parse(source)
    except Exception as e:
        logger.warning(f"Parse failed for {file_path}: {e}")
        return FileAST(file_path=file_path)

    ast = FileAST(file_path=file_path)
    root = tree.root_node

    # --- imports ---
    for imp_node in _collect_nodes(root, "import_declaration"):
        ast.imports.append(_get_text(imp_node, source).strip().rstrip(";"))

    # --- classes ---
    class_nodes = _collect_nodes_multi(root, {"class_declaration", "interface_declaration", "enum_declaration"})
    class_map: dict[int, str] = {}  # node id -> class name

    for cls_node in class_nodes:
        name_node = _find_child_by_type(cls_node, "identifier")
        if name_node:
            cls_name = _get_text(name_node, source)
            ast.classes.append(cls_name)
            class_map[id(cls_node)] = cls_name

    # --- methods and calls ---
    # For each class, collect method declarations
    def get_enclosing_class(node: Node) -> Optional[str]:
        p = node.parent
        while p is not None:
            if p.type in ("class_declaration", "interface_declaration", "enum_declaration"):
                n = _find_child_by_type(p, "identifier")
                if n:
                    return _get_text(n, source)
            p = p.parent
        return None

    def get_enclosing_method(node: Node) -> Optional[str]:
        p = node.parent
        while p is not None:
            if p.type == "method_declaration":
                n = _find_child_by_type(p, "identifier")
                if n:
                    return _get_text(n, source)
            p = p.parent
        return None

    method_nodes = _collect_nodes(root, "method_declaration")
    for meth_node in method_nodes:
        meth_name_node = _find_child_by_type(meth_node, "identifier")
        if not meth_name_node:
            continue
        meth_name = _get_text(meth_name_node, source)
        cls_name = get_enclosing_class(meth_node) or "Unknown"
        qualified = f"{cls_name}.{meth_name}"
        if qualified not in ast.methods:
            ast.methods.append(qualified)

        # collect method invocations inside this method
        invocations = _collect_nodes(meth_node, "method_invocation")
        for inv in invocations:
            # method_invocation: [object "." ] name "(" args ")"
            children = inv.children
            callee_method = None
            callee_obj_type = None

            # find identifier for method name
            # structure: (object . name (args)) or (name (args))
            ids = [c for c in children if c.type == "identifier"]
            if ids:
                callee_method = _get_text(ids[-1], source)
                # object might be field_access or identifier before "."
                if len(ids) >= 2:
                    callee_obj_type = _get_text(ids[0], source)
                elif children and children[0].type in ("identifier", "field_access", "this"):
                    obj_node = children[0]
                    if obj_node.type != "identifier" or _get_text(obj_node, source) != callee_method:
                        callee_obj_type = _get_text(obj_node, source)

            if callee_method:
                mc = MethodCall(
                    caller_class=cls_name,
                    caller_method=meth_name,
                    callee_method=callee_method,
                    callee_object_type=callee_obj_type,
                    line_number=inv.start_point[0] + 1,
                    file_path=file_path,
                )
                ast.method_calls.append(mc)

    return ast


def parse_directory(dir_path: str) -> List[FileAST]:
    """Recursively parse all .java files in directory."""
    results = []
    base = Path(dir_path)
    for java_file in sorted(base.rglob("*.java")):
        try:
            file_ast = parse_file(str(java_file))
            results.append(file_ast)
            logger.debug(f"Parsed: {java_file} ({len(file_ast.methods)} methods, {len(file_ast.method_calls)} calls)")
        except Exception as e:
            logger.warning(f"Skipping {java_file}: {e}")
    return results
