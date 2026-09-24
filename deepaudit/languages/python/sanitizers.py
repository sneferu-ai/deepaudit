#!/usr/bin/env python3
from __future__ import annotations
"""Sanitization-function taxonomy for Python."""

import ast
from typing import Iterable
from deepaudit.languages.base import SanitizerNode
from deepaudit.models.taint import ProgramPoint


# Names that are recognised as barriers in v1. The value is the exploit class for
# which the function is treated as a sanitizer; None means "applies to all".
SANITIZER_NAMES: dict[str, str | None] = {
    "escape_query": "sql_injection",
    "sqlescape": "sql_injection",
    "mogrify": "sql_injection",
    "html.escape": "template_injection",
    "markupsafe.escape": "template_injection",
    "bleach.clean": "template_injection",
    "shlex.quote": "command_injection",
    "quote": "command_injection",  # urllib.parse.quote, shlex.quote alias
    "os.path.realpath": "path_traversal",
    "os.path.abspath": "path_traversal",
    "Path.resolve": "path_traversal",
    "hmac.compare_digest": "auth_bypass",
    "re.escape": None,
    "int": None,
    "str": None,
    "bool": None,
}


def _function_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return _function_name(node.value) + "." + node.attr
    return ""


def extract_sanitizers(tree: ast.AST, filename: str) -> list[SanitizerNode]:
    module = _module_name(filename)
    sanitizers: list[SanitizerNode] = []
    for func in _functions(tree):
        func_name = f"{module}.{func.name}"
        for node in ast.walk(func):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if isinstance(node, ast.Call):
                name = _function_name(node.func)
                if name in SANITIZER_NAMES:
                    sanitizers.append(
                        SanitizerNode(
                            point=ProgramPoint(
                                file=filename,
                                line=node.lineno,
                                column=node.col_offset,
                                expression=ast.unparse(node),
                                function=func_name,
                            ),
                            exploit_class=SANITIZER_NAMES[name] or "all",
                        )
                    )
    return sanitizers


def _module_name(filename: str) -> str:
    from deepaudit.languages.python.modnames import module_name_from_path
    return module_name_from_path(filename)


def _functions(tree: ast.AST) -> list[ast.FunctionDef]:
    return [node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)]
