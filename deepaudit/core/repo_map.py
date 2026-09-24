#!/usr/bin/env python3
from __future__ import annotations
"""Stage 1: parse repository and build a cross-file program model."""

import ast
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from deepaudit.languages.base import (
    LanguageFrontend,
    SourceNode,
    SinkNode,
    SanitizerNode,
    FunctionSignature,
)
from deepaudit.models.taint import ProgramPoint


SKIP_DIRS = {"__pycache__", ".git", ".venv", "venv", "env", "node_modules", "dist", "build"}


@dataclass
class CallSite:
    ast_call: ast.Call
    callee: str | None
    arg_exprs: list[ast.expr]
    caller: str
    point: ProgramPoint


@dataclass
class FunctionInfo:
    qualified_name: str
    module: str
    name: str
    ast_node: ast.FunctionDef
    params: list[str]
    sources: list[SourceNode] = field(default_factory=list)
    sinks: list[SinkNode] = field(default_factory=list)
    sanitizers: list[SanitizerNode] = field(default_factory=list)
    call_sites: list[CallSite] = field(default_factory=list)
    returns: list[ast.Return] = field(default_factory=list)


@dataclass
class RepoModel:
    root: Path
    functions: dict[str, FunctionInfo]
    files: list[str]
    parse_failures: list[tuple[str, str]]
    module_to_files: dict[str, list[str]]


def _module_name_from_rel(rel: Path) -> str:
    # Canonical, shared with the frontend/sources/sinks/sanitizers so qualified
    # names always match (the __init__.py mismatch that crashed real-repo scans).
    from deepaudit.languages.python.modnames import module_name_from_path
    return module_name_from_path(str(rel))


def build_repo_model(repo_path: Path, frontend: LanguageFrontend) -> RepoModel:
    """Parse every .py file under repo_path and build a RepoModel."""
    repo_path = Path(repo_path)
    parsed_files: list[tuple[Path, Path, str, ast.AST]] = []
    parse_failures: list[tuple[str, str]] = []
    module_to_files: dict[str, list[str]] = {}

    for path in sorted(repo_path.rglob("*.py")):
        rel_parts = path.relative_to(repo_path).parts
        if any(part in SKIP_DIRS for part in rel_parts):
            continue
        rel = path.relative_to(repo_path)
        module = _module_name_from_rel(rel)
        module_to_files.setdefault(module, []).append(str(rel))
        try:
            source = path.read_text(encoding="utf-8")
            tree = frontend.parse_file(source, str(rel))
            parsed_files.append((path, rel, module, tree))
        except Exception as exc:
            parse_failures.append((str(rel), f"{type(exc).__name__}: {exc}"))

    all_sigs: dict[str, FunctionSignature] = {}
    for _, rel, module, tree in parsed_files:
        for sig in frontend.extract_function_signatures(tree, str(rel)):
            all_sigs[sig.qualified_name] = sig

    # Map qualified name -> AST node. Include AsyncFunctionDef — a real codebase
    # is full of `async def` handlers, and the signature extractor yields them, so
    # omitting them here KeyError'd the lookup below on real code.
    func_nodes: dict[str, ast.AST] = {}
    for _, rel, module, tree in parsed_files:
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                qual = f"{module}.{node.name}"
                func_nodes[qual] = node

    functions: dict[str, FunctionInfo] = {}
    for _, rel, module, tree in parsed_files:
        imports = {edge.local_name: edge for edge in frontend.extract_imports(tree, str(rel))}
        all_sources = frontend.extract_sources(tree, str(rel))
        all_sinks = frontend.extract_sinks(tree, str(rel))
        all_sanitizers = frontend.extract_sanitizers(tree, str(rel))

        for sig in frontend.extract_function_signatures(tree, str(rel)):
            # Defensive: a security tool must never CRASH the whole scan because one
            # function's node couldn't be mapped (overloads, conditional/duplicate
            # defs, exotic layouts). Skip it and keep auditing the rest of the repo.
            func_node = func_nodes.get(sig.qualified_name)
            if func_node is None:
                continue
            func_sinks = [s for s in all_sinks if s.point.function == sig.qualified_name]
            func_sources = [s for s in all_sources if s.point.function == sig.qualified_name]
            func_sanitizers = [s for s in all_sanitizers if s.point.function == sig.qualified_name]

            call_sites: list[CallSite] = []
            for child in ast.walk(func_node):
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                if isinstance(child, ast.Call):
                    callee = frontend.resolve_call(child.func, str(rel), tree)
                    if callee is not None:
                        call_sites.append(
                            CallSite(
                                ast_call=child,
                                callee=callee,
                                arg_exprs=list(child.args),
                                caller=sig.qualified_name,
                                point=ProgramPoint(
                                    file=str(rel),
                                    line=child.lineno,
                                    column=child.col_offset,
                                    expression=ast.unparse(child),
                                    function=sig.qualified_name,
                                ),
                            )
                        )

            returns = [n for n in ast.walk(func_node) if isinstance(n, ast.Return) and n.value is not None]

            functions[sig.qualified_name] = FunctionInfo(
                qualified_name=sig.qualified_name,
                module=sig.module,
                name=sig.name,
                ast_node=func_node,
                params=sig.parameters,
                sources=func_sources,
                sinks=func_sinks,
                sanitizers=func_sanitizers,
                call_sites=call_sites,
                returns=returns,
            )

    return RepoModel(
        root=repo_path,
        functions=functions,
        files=[str(rel) for _, rel, _, _ in parsed_files],
        parse_failures=parse_failures,
        module_to_files=module_to_files,
    )
