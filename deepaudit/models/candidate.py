#!/usr/bin/env python3
from __future__ import annotations
from dataclasses import dataclass
from deepaudit.models.taint import ProgramPoint


@dataclass
class SinkMetadata:
    """Structured metadata extracted from a sink expression."""

    shell_enabled: bool | None = None
    query_type: str | None = None
    template_engine: str | None = None
    is_code_exec: bool | None = None
    constant_value: str | None = None  # For auth-bypass hardcoded literals.


@dataclass
class VulnerabilityCandidate:
    """A potential vulnerability with a source→sink taint path."""

    id: str
    exploit_class: str
    source: ProgramPoint
    sink: ProgramPoint
    taint_path: list[ProgramPoint]
    sanitizers_on_path: list[ProgramPoint]
    sanitizer_bypassed: bool
    cross_file: bool
    sink_metadata: SinkMetadata
    source_kind: str
    source_is_parameter: bool
    source_module: str
    source_function: str
    sink_module: str
    sink_function: str
