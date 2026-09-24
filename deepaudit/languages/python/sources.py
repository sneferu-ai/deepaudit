from __future__ import annotations
"""Untrusted-input taxonomy and source detection for Python."""

import ast
from typing import Iterable
from deepaudit.languages.base import SourceNode
from deepaudit.models.taint import ProgramPoint


def _node_text(node: ast.AST) -> str:
    return ast.unparse(node)


def _root_name(node: ast.AST) -> str | None:
    """Return the leftmost Name identifier in an attribute/subscript chain."""
    while isinstance(node, (ast.Attribute, ast.Subscript)):
        node = node.value
    if isinstance(node, ast.Name):
        return node.id
    return None


def _is_parameter(root: str | None, params: set[str]) -> bool:
    return root is not None and root in params


def _make_point(node: ast.AST, expression: str, function: str, filename: str) -> ProgramPoint:
    return ProgramPoint(
        file=filename,
        line=getattr(node, "lineno", 1),
        column=getattr(node, "col_offset", 0),
        expression=expression,
        function=function,
    )


def _detect_request_source(expr_text: str, root: str | None, params: set[str]) -> SourceNode | None:
    """Detect Flask/Django-style request parameter sources."""
    is_http = False
    if ".args.get(" in expr_text or ".form.get(" in expr_text or ".args[" in expr_text or ".form[" in expr_text:
        is_http = True
    elif ".json" in expr_text or ".data" in expr_text or ".GET" in expr_text or ".POST" in expr_text:
        is_http = True
    if not is_http:
        return None
    kind = "http_param_func" if _is_parameter(root, params) else "http_param_flask"
    return SourceNode(
        point=None,  # type: ignore[arg-type]
        kind=kind,
        root_identifier=root or "request",
        is_parameter=_is_parameter(root, params),
    )


def _detect_specific_source(node: ast.AST, params: set[str]) -> SourceNode | None:
    """Detect a single source expression; returns None with point unset if no match."""
    # Only expression-shaped nodes can be sources.
    if not isinstance(node, (ast.Call, ast.Subscript, ast.Attribute, ast.Name)):
        return None

    expr_text = _node_text(node)
    # For calls, the root identifier is in the function being called.
    if isinstance(node, ast.Call):
        root = _root_name(node.func)
    else:
        root = _root_name(node)

    # CLI args (only direct sys.argv indexing)
    if "sys.argv" in expr_text:
        return SourceNode(point=None, kind="cli_arg", root_identifier="sys.argv", is_parameter=False)  # type: ignore[arg-type]

    # Environment variables
    if "os.environ" in expr_text or "os.getenv" in expr_text:
        return SourceNode(point=None, kind="env_var", root_identifier=root or "os.environ", is_parameter=False)  # type: ignore[arg-type]

    # User input
    if isinstance(node, ast.Call) and _node_text(node.func) == "input":
        return SourceNode(point=None, kind="user_input", root_identifier="input", is_parameter=False)  # type: ignore[arg-type]

    # File read (v1: only module-level reads; parameters handled as generic_param)
    if isinstance(node, ast.Call) and _node_text(node.func) == "open":
        # Skip if the path is a bare function parameter; the parameter is already a generic_param source.
        args = node.args
        if len(args) >= 1 and isinstance(args[0], ast.Name):
            return None
        return SourceNode(point=None, kind="file_read", root_identifier=root or "open", is_parameter=False)  # type: ignore[arg-type]

    # HTTP request patterns (Flask/Django request.args/form/json/GET/POST)
    req = _detect_request_source(expr_text, root, params)
    if req is not None:
        return req

    # Raw / framework-agnostic HTTP request surfaces. Real apps take untrusted
    # input a hundred ways that aren't Flask's request.args.get — a stdlib
    # http.server handler (self.path / self.rfile / self.headers), WSGI (environ),
    # aiohttp/Django (request.query / match_info / rel_url / query_string).
    # Recognising these is what lets the taint engine SEE the input on a real app
    # like DSVW (whose SQLi originates at `self.path`). Heuristic by design: it
    # trades a little precision for recall, which is the correct direction when the
    # failure mode is MISSING real bugs — and the reality gate's false-positive
    # check is the backstop if it ever over-fires.
    raw = _detect_raw_request_source(expr_text)
    if raw is not None:
        return raw

    return None


_RAW_REQUEST_PATTERNS = (
    "self.path", "self.rfile", "self.requestline", "self.headers",
    "request.query", "request.match_info", "request.rel_url",
    "request.query_string", "request.GET", "request.POST",
)


def _detect_raw_request_source(expr_text: str) -> SourceNode | None:
    if any(p in expr_text for p in _RAW_REQUEST_PATTERNS):
        root_id = expr_text.split(".", 1)[0] or "request"
        return SourceNode(point=None, kind="http_param_func", root_identifier=root_id, is_parameter=False)  # type: ignore[arg-type]
    if "environ[" in expr_text or "environ.get(" in expr_text:
        return SourceNode(point=None, kind="http_param_func", root_identifier="environ", is_parameter=False)  # type: ignore[arg-type]
    return None


def extract_sources(tree: ast.AST, filename: str) -> list[SourceNode]:
    """Extract source nodes from a Python AST."""
    module = _module_name(filename)
    sources: list[SourceNode] = []

    for func in _functions(tree):
        func_name = f"{module}.{func.name}"
        params = {a.arg for a in func.args.args}

        # Generic function-parameter fallback for every parameter.
        for param in func.args.args:
            if param.arg in ("self", "cls"):
                continue
            sources.append(
                SourceNode(
                    point=ProgramPoint(
                        file=filename,
                        line=param.lineno,
                        column=param.col_offset,
                        expression=param.arg,
                        function=func_name,
                    ),
                    kind="generic_param",
                    root_identifier=param.arg,
                    is_parameter=True,
                )
            )

        # Specific source expressions inside the function.
        for node in ast.walk(func):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            specific = _detect_specific_source(node, params)
            if specific is not None:
                point = ProgramPoint(
                    file=filename,
                    line=getattr(node, "lineno", 1),
                    column=getattr(node, "col_offset", 0),
                    expression=_node_text(node),
                    function=func_name,
                )
                sources.append(
                    SourceNode(
                        point=point,
                        kind=specific.kind,
                        root_identifier=specific.root_identifier,
                        is_parameter=specific.is_parameter,
                    )
                )

    return sources


def _module_name(filename: str) -> str:
    from deepaudit.languages.python.modnames import module_name_from_path
    return module_name_from_path(filename)


def _functions(tree: ast.AST) -> list[ast.FunctionDef]:
    return [node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)]
