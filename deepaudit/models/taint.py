#!/usr/bin/env python3
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class ProgramPoint:
    """A location in source code plus a short expression snippet."""

    file: str
    line: int
    column: int
    expression: str
    function: str

    def as_dict(self) -> dict:
        return {
            "file": self.file,
            "line": self.line,
            "column": self.column,
            "expression": self.expression,
            "function": self.function,
        }

    def as_str(self) -> str:
        return f"{self.file}:{self.line}:{self.column}:{self.expression}"


@dataclass
class TaintPath:
    points: list[ProgramPoint] = field(default_factory=list)
