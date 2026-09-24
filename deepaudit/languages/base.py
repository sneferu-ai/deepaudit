#!/usr/bin/env python3
from __future__ import annotations
from typing import Protocol, NamedTuple, Any
from deepaudit.models.taint import ProgramPoint
from deepaudit.models.candidate import SinkMetadata


class SourceNode(NamedTuple):
    point: ProgramPoint
    kind: str
    root_identifier: str
    is_parameter: bool


class SinkNode(NamedTuple):
    point: ProgramPoint
    exploit_class: str
    metadata: SinkMetadata


class SanitizerNode(NamedTuple):
    point: ProgramPoint
    exploit_class: str


class CallEdge(NamedTuple):
    caller: str
    callee: str
    arg_index: int
    arg_expression: str


class ImportEdge(NamedTuple):
    local_name: str
    module_path: str
    imported_name: str | None


class FunctionSignature(NamedTuple):
    qualified_name: str
    module: str
    name: str
    parameters: list[str]


class LanguageFrontend(Protocol):
    """Pluggable language parser. v1 ships PythonFrontend only."""

    name: str

    def parse_file(self, source: str, filename: str) -> Any: ...
    def extract_sources(self, tree: Any, filename: str) -> list[SourceNode]: ...
    def extract_sinks(self, tree: Any, filename: str) -> list[SinkNode]: ...
    def extract_sanitizers(self, tree: Any, filename: str) -> list[SanitizerNode]: ...
    def extract_call_edges(self, tree: Any, filename: str) -> list[CallEdge]: ...
    def extract_imports(self, tree: Any, filename: str) -> list[ImportEdge]: ...
    def extract_function_signatures(self, tree: Any, filename: str) -> list[FunctionSignature]: ...
