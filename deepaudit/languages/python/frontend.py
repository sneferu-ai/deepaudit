#!/usr/bin/env python3
from __future__ import annotations
"""Python language frontend — AST-based implementation for v1."""

import ast
from pathlib import Path
from typing import Any
from deepaudit.languages.base import (
    LanguageFrontend,
    FunctionSignature,
    ImportEdge,
    CallEdge,
    SourceNode,
    SinkNode,
    SanitizerNode,
)
from deepaudit.languages.python import sources, sinks, sanitizers


class PythonLanguageFrontend:
    """AST-based Python frontend."""

    name: str = "python"

    def parse_file(self, source: str, filename: str) -> ast.AST:
        return ast.parse(source, filename=filename)

    def extract_sources(self, tree: ast.AST, filename: str) -> list[SourceNode]:
        return sources.extract_sources(tree, filename)

    def extract_sinks(self, tree: ast.AST, filename: str) -> list[SinkNode]:
        return sinks.extract_sinks(tree, filename)

    def extract_sanitizers(self, tree: ast.AST, filename: str) -> list[SanitizerNode]:
        return sanitizers.extract_sanitizers(tree, filename)

    def extract_function_signatures(self, tree: ast.AST, filename: str) -> list[FunctionSignature]:
        module = self._module_name(filename)
        sigs = []
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                sigs.append(
                    FunctionSignature(
                        qualified_name=f"{module}.{node.name}",
                        module=module,
                        name=node.name,
                        parameters=[a.arg for a in node.args.args],
                    )
                )
        return sigs

    def extract_imports(self, tree: ast.AST, filename: str) -> list[ImportEdge]:
        edges = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    local = alias.asname or alias.name
                    edges.append(ImportEdge(local_name=local, module_path=alias.name, imported_name=None))
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                for alias in node.names:
                    local = alias.asname or alias.name
                    edges.append(ImportEdge(local_name=local, module_path=module, imported_name=alias.name))
        return edges

    def extract_call_edges(self, tree: ast.AST, filename: str) -> list[CallEdge]:
        """Return call edges with resolved callee qualified names where possible."""
        module = self._module_name(filename)
        imports = self._import_map(tree)
        same_module_funcs = {n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
        edges = []
        for func in self._functions(tree):
            caller = f"{module}.{func.name}"
            for node in ast.walk(func):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                if not isinstance(node, ast.Call):
                    continue
                callee = self._resolve_call(node.func, module, imports, same_module_funcs)
                if callee is None:
                    continue
                for i, arg in enumerate(node.args):
                    edges.append(
                        CallEdge(
                            caller=caller,
                            callee=callee,
                            arg_index=i,
                            arg_expression=ast.unparse(arg),
                        )
                    )
        return edges

    @staticmethod
    def _module_name(filename: str) -> str:
        from deepaudit.languages.python.modnames import module_name_from_path
        return module_name_from_path(filename)

    @staticmethod
    def _functions(tree: ast.AST) -> list[ast.FunctionDef]:
        return [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]

    @staticmethod
    def _import_map(tree: ast.AST) -> dict[str, ImportEdge]:
        m = {}
        frontend = PythonLanguageFrontend()
        for edge in frontend.extract_imports(tree, ""):
            m[edge.local_name] = edge
        return m

    @staticmethod
    def _resolve_call(func: ast.AST, module: str, imports: dict[str, ImportEdge], same_module_funcs: set[str]) -> str | None:
        if isinstance(func, ast.Name):
            name = func.id
            if name in imports:
                edge = imports[name]
                if edge.imported_name:
                    return f"{edge.module_path}.{edge.imported_name}"
                return f"{edge.module_path}.{name}"
            if name in same_module_funcs:
                return f"{module}.{name}"
            return None
        if isinstance(func, ast.Attribute):
            if isinstance(func.value, ast.Name):
                base = func.value.id
                if base in imports:
                    edge = imports[base]
                    return f"{edge.module_path}.{func.attr}"
                if base == module or base in same_module_funcs:
                    return f"{module}.{func.attr}"
            # Heuristic: a.b.c where a is an imported module
            root = func.value
            while isinstance(root, ast.Attribute):
                root = root.value
            if isinstance(root, ast.Name) and root.id in imports:
                edge = imports[root.id]
                suffix = ast.unparse(func.value).split(".", 1)[1] if "." in ast.unparse(func.value) else ""
                if suffix:
                    return f"{edge.module_path}.{suffix}.{func.attr}"
                return f"{edge.module_path}.{func.attr}"
        return None

    def resolve_call(self, func: ast.AST, filename: str, tree: ast.AST) -> str | None:
        """Public helper used by repo_map."""
        module = self._module_name(filename)
        imports = self._import_map(tree)
        same_module_funcs = {n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
        return self._resolve_call(func, module, imports, same_module_funcs)
