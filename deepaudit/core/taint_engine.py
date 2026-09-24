#!/usr/bin/env python3
from __future__ import annotations
"""Cross-file taint propagation and candidate generation."""

import ast
import uuid
from dataclasses import dataclass, field
from typing import Any
from deepaudit.core.repo_map import RepoModel, FunctionInfo
from deepaudit.languages.python import sanitizers
from deepaudit.models.candidate import VulnerabilityCandidate, SinkMetadata
from deepaudit.models.taint import ProgramPoint


@dataclass
class TaintState:
    tainted_vars: dict[str, set[str]] = field(default_factory=dict)
    return_tainted: set[str] = field(default_factory=set)


def _add_taint(target: dict[str, set[str]], key: str, sources: set[str]) -> bool:
    before = len(target.get(key, set()))
    current = target.setdefault(key, set())
    current.update(sources)
    return len(current) > before


def _node_text(node: ast.AST) -> str:
    return ast.unparse(node)


def _is_sanitizer_call(node: ast.AST) -> bool:
    if not isinstance(node, ast.Call):
        return False
    name = ""
    func = node.func
    if isinstance(func, ast.Name):
        name = func.id
    elif isinstance(func, ast.Attribute):
        name = _node_text(func)
    return name in sanitizers.SANITIZER_NAMES


def _build_source_maps(model: RepoModel) -> tuple[dict[str, str], dict[str, SourceNode], dict[str, dict[str, set[str]]]]:
    """Return (source_node -> id, id -> SourceNode, function -> expression -> source ids)."""
    source_to_id: dict[str, str] = {}
    source_map: dict[str, SourceNode] = {}
    func_expr_sources: dict[str, dict[str, set[str]]] = {}

    for fn, func in model.functions.items():
        expr_map: dict[str, set[str]] = {}
        for src in func.sources:
            sid = f"{src.point.file}:{src.point.line}:{src.point.column}:{src.kind}"
            source_to_id[src] = sid
            source_map[sid] = src
            expr_map.setdefault(src.point.expression, set()).add(sid)
        func_expr_sources[fn] = expr_map

    return source_to_id, source_map, func_expr_sources


def _taint_sources_for_expr(
    expr: ast.AST,
    func_name: str,
    taint: dict[str, TaintState],
    func_returns: dict[str, set[str]],
    model: RepoModel,
    func_expr_sources: dict[str, dict[str, set[str]]],
) -> set[str]:
    """Return the set of source ids that taint expr."""
    sources: set[str] = set()

    # Exact source-expression match (e.g., request.args.get(...)).
    expr_text = _node_text(expr)
    _fes = func_expr_sources.get(func_name, {})
    if expr_text in _fes:
        sources.update(_fes[expr_text])

    # A registered source expression nested ANYWHERE in this expression taints it
    # — `self.path` inside `self.path.split('?',1) if ... else (self.path,'')`, a
    # source passed as a call argument, etc. Without this a source only counted
    # when it WAS the entire expression (too literal for real code): it is exactly
    # why DSVW's `self.path`-derived SQL injection was invisible. Sound: it only
    # adds taint for expressions the source detector already deemed untrusted.
    if _fes:
        for _sub in ast.walk(expr):
            if _sub is expr:
                continue
            _sub_text = _node_text(_sub)
            if _sub_text in _fes:
                sources.update(_fes[_sub_text])

    # Recursive inspection of names, calls, f-strings, concatenation.
    if isinstance(expr, ast.JoinedStr):
        for value in expr.values:
            if isinstance(value, ast.FormattedValue):
                sources.update(
                    _taint_sources_for_expr(value.value, func_name, taint, func_returns, model, func_expr_sources)
                )
        return sources if sources else set()

    if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
        sources.update(
            _taint_sources_for_expr(expr.left, func_name, taint, func_returns, model, func_expr_sources)
        )
        sources.update(
            _taint_sources_for_expr(expr.right, func_name, taint, func_returns, model, func_expr_sources)
        )
        return sources if sources else set()

    for node in ast.walk(expr):
        if isinstance(node, ast.Name):
            if node.id in taint[func_name].tainted_vars:
                sources.update(taint[func_name].tainted_vars[node.id])
        elif isinstance(node, ast.Call):
            # If the call resolves to a function whose return is tainted, the call is tainted.
            callee = _resolve_call(node.func, func_name, model)
            if callee and callee in func_returns:
                sources.update(func_returns[callee])

    return sources if sources else set()


def _resolve_call(func: ast.AST, caller_func: str, model: RepoModel) -> str | None:
    """Resolve a call AST to a qualified function name using import maps."""
    caller = model.functions.get(caller_func)
    if caller is None:
        return None
    imports = {edge.local_name: edge for edge in _imports_for_module(caller.module, model)}
    module = caller.module
    same_module_funcs = {name.split(".", 1)[1] for name in model.functions if name.startswith(module + ".")}

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
        return None

    return None


def _imports_for_module(module: str, model: RepoModel) -> list:
    # Imports are not stored per module in RepoModel; recompute from trees via frontend.
    # This is a slow fallback; repo_map should ideally cache imports. For v1 fixtures this is fine.
    from deepaudit.languages.python.frontend import PythonLanguageFrontend

    frontend = PythonLanguageFrontend()
    imports: list = []
    for rel in model.module_to_files.get(module, []):
        path = model.root / rel
        try:
            tree = frontend.parse_file(path.read_text(encoding="utf-8"), rel)
            imports.extend(frontend.extract_imports(tree, rel))
        except Exception:
            pass
    return imports


def _seed_taint(model: RepoModel, taint: dict[str, TaintState], func_expr_sources: dict[str, dict[str, set[str]]]) -> None:
    """Seed initial taint from source expressions and generic parameters."""
    for fn, func in model.functions.items():
        state = taint[fn]
        # Generic parameters
        for src in func.sources:
            if src.kind == "generic_param" and src.root_identifier in func.params:
                sid = f"{src.point.file}:{src.point.line}:{src.point.column}:{src.kind}"
                _add_taint(state.tainted_vars, src.root_identifier, {sid})
        # Specific source expressions that appear as assignment RHS / with context.
        for node in ast.walk(func.ast_node):
            if isinstance(node, ast.Assign):
                rhs_sources = _taint_sources_for_expr(node.value, fn, taint, {fn: set() for fn in model.functions}, model, func_expr_sources)
                if rhs_sources and not _is_sanitizer_call(node.value):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            _add_taint(state.tainted_vars, target.id, rhs_sources)
                        elif isinstance(target, ast.Tuple):
                            for elt in target.elts:
                                if isinstance(elt, ast.Name):
                                    _add_taint(state.tainted_vars, elt.id, rhs_sources)
            elif isinstance(node, ast.AnnAssign) and node.value is not None and isinstance(node.target, ast.Name):
                rhs_sources = _taint_sources_for_expr(node.value, fn, taint, {fn: set() for fn in model.functions}, model, func_expr_sources)
                if rhs_sources and not _is_sanitizer_call(node.value):
                    _add_taint(state.tainted_vars, node.target.id, rhs_sources)
            elif isinstance(node, ast.With):
                for item in node.items:
                    rhs_sources = _taint_sources_for_expr(item.context_expr, fn, taint, {fn: set() for fn in model.functions}, model, func_expr_sources)
                    if rhs_sources and not _is_sanitizer_call(item.context_expr):
                        target = item.optional_vars
                        if isinstance(target, ast.Name):
                            _add_taint(state.tainted_vars, target.id, rhs_sources)
                        elif isinstance(target, ast.Tuple):
                            for elt in target.elts:
                                if isinstance(elt, ast.Name):
                                    _add_taint(state.tainted_vars, elt.id, rhs_sources)


def analyze(model: RepoModel) -> list[VulnerabilityCandidate]:
    """Run cross-file taint analysis and return vulnerability candidates."""
    source_to_id, source_map, func_expr_sources = _build_source_maps(model)

    taint: dict[str, TaintState] = {fn: TaintState() for fn in model.functions}
    func_returns: dict[str, set[str]] = {fn: set() for fn in model.functions}

    _seed_taint(model, taint, func_expr_sources)

    changed = True
    while changed:
        changed = False
        for fn, func in model.functions.items():
            state = taint[fn]

            # Local propagation: assignments, with, returns.
            for node in ast.walk(func.ast_node):
                if isinstance(node, ast.Assign):
                    rhs_sources = _taint_sources_for_expr(node.value, fn, taint, func_returns, model, func_expr_sources)
                    if rhs_sources and not _is_sanitizer_call(node.value):
                        for target in node.targets:
                            if isinstance(target, ast.Name):
                                if _add_taint(state.tainted_vars, target.id, rhs_sources):
                                    changed = True
                            elif isinstance(target, ast.Tuple):
                                for elt in target.elts:
                                    if isinstance(elt, ast.Name):
                                        if _add_taint(state.tainted_vars, elt.id, rhs_sources):
                                            changed = True
                elif isinstance(node, ast.AnnAssign) and node.value is not None and isinstance(node.target, ast.Name):
                    rhs_sources = _taint_sources_for_expr(node.value, fn, taint, func_returns, model, func_expr_sources)
                    if rhs_sources and not _is_sanitizer_call(node.value):
                        if _add_taint(state.tainted_vars, node.target.id, rhs_sources):
                            changed = True
                elif isinstance(node, ast.With):
                    for item in node.items:
                        rhs_sources = _taint_sources_for_expr(item.context_expr, fn, taint, func_returns, model, func_expr_sources)
                        if rhs_sources and not _is_sanitizer_call(item.context_expr):
                            target = item.optional_vars
                            if isinstance(target, ast.Name):
                                if _add_taint(state.tainted_vars, target.id, rhs_sources):
                                    changed = True
                            elif isinstance(target, ast.Tuple):
                                for elt in target.elts:
                                    if isinstance(elt, ast.Name):
                                        if _add_taint(state.tainted_vars, elt.id, rhs_sources):
                                            changed = True
                elif isinstance(node, ast.Return) and node.value is not None:
                    rhs_sources = _taint_sources_for_expr(node.value, fn, taint, func_returns, model, func_expr_sources)
                    if rhs_sources:
                        before = len(func_returns[fn])
                        func_returns[fn].update(rhs_sources)
                        if len(func_returns[fn]) > before:
                            changed = True

            # Inter-procedural propagation: arguments -> callee parameters.
            for site in func.call_sites:
                if site.callee is None:
                    continue
                callee_func = model.functions.get(site.callee)
                if callee_func is None:
                    continue
                callee_state = taint[site.callee]
                for i, arg in enumerate(site.arg_exprs):
                    if i >= len(callee_func.params):
                        break
                    arg_sources = _taint_sources_for_expr(arg, fn, taint, func_returns, model, func_expr_sources)
                    if arg_sources:
                        if _add_taint(callee_state.tainted_vars, callee_func.params[i], arg_sources):
                            changed = True

    # Generate candidates from sinks.
    candidates: list[VulnerabilityCandidate] = []
    seen: set[tuple[str, str, tuple[str, ...]]] = set()

    for fn, func in model.functions.items():
        for sink in func.sinks:
            sink_node = sink.point
            operand = _sink_operand(sink, model)
            if operand is None:
                continue
            tainted_sources = _taint_sources_for_expr(operand, fn, taint, func_returns, model, func_expr_sources)
            if not tainted_sources:
                continue

            # Prefer a non-generic source id.
            chosen_sid = _pick_source(tainted_sources, source_map)
            source_node = source_map[chosen_sid]

            path = _build_taint_path(source_node, sink, func, model)
            path_key = (source_node.point.as_str(), sink_node.as_str(), tuple(p.as_str() for p in path))
            if path_key in seen:
                continue
            seen.add(path_key)

            source_module, source_function = _split_qual(source_node.point.function)
            sink_module, sink_function = _split_qual(sink_node.function)

            candidates.append(
                VulnerabilityCandidate(
                    id=uuid.uuid4().hex,
                    exploit_class=sink.exploit_class,
                    source=source_node.point,
                    sink=sink_node,
                    taint_path=path,
                    sanitizers_on_path=_collect_sanitizers(source_node, sink_node, path, model),
                    sanitizer_bypassed=False,
                    cross_file=source_module != sink_module,
                    sink_metadata=sink.metadata,
                    source_kind=source_node.kind,
                    source_is_parameter=source_node.is_parameter,
                    source_module=source_module,
                    source_function=source_function,
                    sink_module=sink_module,
                    sink_function=sink_function,
                )
            )

    return candidates


def _split_qual(qualified: str) -> tuple[str, str]:
    if "." in qualified:
        module, func = qualified.rsplit(".", 1)
        return module, func
    return qualified, "<module>"


def _sink_operand(sink, model: RepoModel) -> ast.AST | None:
    """Return the tainted operand of a sink expression."""
    node = sink.point  # type: ignore[attr-defined]
    # We have the AST node stored on the sink node? No, only point. Reconstruct from function.
    func = model.functions.get(node.function)
    if func is None:
        return None
    for child in ast.walk(func.ast_node):
        if isinstance(child, (ast.Call, ast.Compare)):
            if getattr(child, "lineno", None) == node.line and getattr(child, "col_offset", None) == node.column:
                if isinstance(child, ast.Call) and child.args:
                    return child.args[0]
                if isinstance(child, ast.Compare) and child.comparators:
                    # Return the tainted name side; use the left operand if it is a Name.
                    if isinstance(child.left, ast.Name):
                        return child.left
                    return child.comparators[0]
    return None


def _pick_source(source_ids: set[str], source_map: dict[str, SourceNode]) -> str:
    """Choose the most specific source id."""
    order = [
        "http_param_func",
        "http_param_flask",
        "http_body_flask",
        "cli_arg",
        "env_var",
        "user_input",
        "file_read",
        "generic_param",
    ]
    by_kind = {source_map[sid].kind: sid for sid in source_ids}
    for kind in order:
        if kind in by_kind:
            return by_kind[kind]
    return next(iter(source_ids))


def _build_taint_path(source_node: SourceNode, sink: Any, sink_func: FunctionInfo, model: RepoModel) -> list[ProgramPoint]:
    source_point = source_node.point
    sink_point = sink.point
    path = [source_point]
    if source_point.function == sink_point.function:
        path.append(sink_point)
        return path

    source_func_name = source_point.function
    # Find a direct call from source function to sink function.
    source_func = model.functions.get(source_func_name)
    if source_func is not None:
        for site in source_func.call_sites:
            if site.callee == sink_point.function:
                path.append(site.point)
                break
    path.append(sink_point)
    return path


def _collect_sanitizers(source_node: SourceNode, sink: Any, path: list[ProgramPoint], model: RepoModel) -> list[ProgramPoint]:
    """Collect sanitizer points on the path."""
    funcs = {p.function for p in path}
    points = []
    for fn in funcs:
        func = model.functions.get(fn)
        if func is None:
            continue
        for san in func.sanitizers:
            points.append(san.point)
    return points



