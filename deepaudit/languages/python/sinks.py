#!/usr/bin/env python3
from __future__ import annotations
"""Dangerous sink taxonomy and sink metadata extraction for Python."""

import ast
import re
from deepaudit.languages.base import SinkNode
from deepaudit.models.candidate import SinkMetadata
from deepaudit.models.taint import ProgramPoint


SELECT_RE = re.compile(r"\bSELECT\b", re.IGNORECASE)
INSERT_RE = re.compile(r"\bINSERT\b", re.IGNORECASE)
UPDATE_RE = re.compile(r"\bUPDATE\b", re.IGNORECASE)
DELETE_RE = re.compile(r"\bDELETE\b", re.IGNORECASE)


def _node_text(node: ast.AST) -> str:
    return ast.unparse(node)


def _function_name(node: ast.AST) -> str:
    """Return a dotted name for a call function, e.g., 'subprocess.call'."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return _function_name(node.value) + "." + node.attr
    return ""


def _is_shell_true(node: ast.Call) -> bool:
    for keyword in node.keywords:
        if keyword.arg == "shell":
            if isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                return True
            if isinstance(keyword.value, ast.NameConstant) and keyword.value.value is True:  # type: ignore[attr-defined]
                return True
    return False


def _query_type(arg: ast.AST) -> str | None:
    text = _node_text(arg)
    if SELECT_RE.search(text):
        return "SELECT"
    if INSERT_RE.search(text):
        return "INSERT"
    if UPDATE_RE.search(text):
        return "UPDATE"
    if DELETE_RE.search(text):
        return "DELETE"
    return None


def _is_literal(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant)


def _extract_literal_value(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant):
        return str(node.value)
    return None


def _extract_sql_sink(node: ast.Call, func_name: str, filename: str, function: str) -> SinkNode | None:
    if not (func_name.endswith(".execute") or func_name == "execute"):
        return None
    if not node.args:
        return None
    query_arg = node.args[0]
    query_type = _query_type(query_arg)
    return SinkNode(
        point=ProgramPoint(
            file=filename,
            line=node.lineno,
            column=node.col_offset,
            expression=_node_text(node),
            function=function,
        ),
        exploit_class="sql_injection",
        metadata=SinkMetadata(query_type=query_type),
    )


def _extract_command_sink(node: ast.Call, func_name: str, filename: str, function: str) -> SinkNode | None:
    shell_enabled: bool | None = None
    if func_name in ("os.system", "os.popen"):
        shell_enabled = True
    elif func_name in ("subprocess.call", "subprocess.Popen", "subprocess.run", "subprocess.check_output"):
        shell_enabled = _is_shell_true(node)
    if shell_enabled is None:
        return None
    return SinkNode(
        point=ProgramPoint(
            file=filename,
            line=node.lineno,
            column=node.col_offset,
            expression=_node_text(node),
            function=function,
        ),
        exploit_class="command_injection",
        metadata=SinkMetadata(shell_enabled=shell_enabled, is_code_exec=False),
    )


def _extract_code_exec_sink(node: ast.Call, func_name: str, filename: str, function: str) -> SinkNode | None:
    if func_name not in ("eval", "exec"):
        return None
    return SinkNode(
        point=ProgramPoint(
            file=filename,
            line=node.lineno,
            column=node.col_offset,
            expression=_node_text(node),
            function=function,
        ),
        exploit_class="code_injection",
        metadata=SinkMetadata(shell_enabled=True, is_code_exec=True),
    )


def _extract_deserialization_sink(node: ast.Call, func_name: str, filename: str, function: str) -> SinkNode | None:
    if func_name == "pickle.loads":
        return SinkNode(
            point=ProgramPoint(
                file=filename,
                line=node.lineno,
                column=node.col_offset,
                expression=_node_text(node),
                function=function,
            ),
            exploit_class="unsafe_deserialization",
            metadata=SinkMetadata(),
        )
    if func_name in ("yaml.load", "yaml.unsafe_load"):
        for keyword in node.keywords:
            if keyword.arg == "Loader":
                if isinstance(keyword.value, ast.Name) and keyword.value.id.endswith("SafeLoader"):
                    return None
        return SinkNode(
            point=ProgramPoint(
                file=filename,
                line=node.lineno,
                column=node.col_offset,
                expression=_node_text(node),
                function=function,
            ),
            exploit_class="unsafe_deserialization",
            metadata=SinkMetadata(),
        )
    if func_name == "marshal.loads":
        return SinkNode(
            point=ProgramPoint(
                file=filename,
                line=node.lineno,
                column=node.col_offset,
                expression=_node_text(node),
                function=function,
            ),
            exploit_class="unsafe_deserialization",
            metadata=SinkMetadata(),
        )
    return None


def _extract_template_sink(node: ast.Call, func_name: str, filename: str, function: str) -> SinkNode | None:
    if func_name in ("render_template_string", "jinja2.Environment.from_string", "jinja2.Template"):
        return SinkNode(
            point=ProgramPoint(
                file=filename,
                line=node.lineno,
                column=node.col_offset,
                expression=_node_text(node),
                function=function,
            ),
            exploit_class="template_injection",
            metadata=SinkMetadata(template_engine="jinja2"),
        )
    return None


def _extract_path_traversal_sink(node: ast.Call, func_name: str, filename: str, function: str) -> SinkNode | None:
    if func_name not in ("open", "Path"):
        return None
    if not node.args:
        return None
    path_arg = node.args[0]
    # Skip open(path) where path is a bare variable to avoid false positives on
    # file-reading parameters that are not path-traversal sinks.
    if isinstance(path_arg, ast.Name):
        return None
    return SinkNode(
        point=ProgramPoint(
            file=filename,
            line=node.lineno,
            column=node.col_offset,
            expression=_node_text(node),
            function=function,
        ),
        exploit_class="path_traversal",
        metadata=SinkMetadata(),
    )


def _extract_auth_bypass_sink(node: ast.Compare, filename: str, function: str) -> SinkNode | None:
    if not any(isinstance(op, ast.Eq) for op in node.ops):
        return None
    left, right = node.left, node.comparators[0]
    if _is_literal(left) and isinstance(right, ast.Name):
        constant = _extract_literal_value(left)
        tainted_side = right
    elif _is_literal(right) and isinstance(left, ast.Name):
        constant = _extract_literal_value(right)
        tainted_side = left
    else:
        return None
    return SinkNode(
        point=ProgramPoint(
            file=filename,
            line=node.lineno,
            column=node.col_offset,
            expression=_node_text(node),
            function=function,
        ),
        exploit_class="auth_bypass",
        metadata=SinkMetadata(constant_value=constant),
    )


def extract_sinks(tree: ast.AST, filename: str) -> list[SinkNode]:
    """Extract sink nodes from a Python AST."""
    module = _module_name(filename)
    sinks: list[SinkNode] = []

    for func in _functions(tree):
        func_name = f"{module}.{func.name}"
        for node in ast.walk(func):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if isinstance(node, ast.Call):
                call_name = _function_name(node.func)
                for extractor in (
                    _extract_sql_sink,
                    _extract_command_sink,
                    _extract_code_exec_sink,
                    _extract_deserialization_sink,
                    _extract_template_sink,
                    _extract_path_traversal_sink,
                ):
                    sink = extractor(node, call_name, filename, func_name)
                    if sink is not None:
                        sinks.append(sink)
                        break
            elif isinstance(node, ast.Compare):
                sink = _extract_auth_bypass_sink(node, filename, func_name)
                if sink is not None:
                    sinks.append(sink)

    return sinks


def _module_name(filename: str) -> str:
    from deepaudit.languages.python.modnames import module_name_from_path
    return module_name_from_path(filename)


def _functions(tree: ast.AST) -> list[ast.FunctionDef]:
    return [node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)]
