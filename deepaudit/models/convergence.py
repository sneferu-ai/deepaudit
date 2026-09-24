#!/usr/bin/env python3
from __future__ import annotations
from dataclasses import dataclass


@dataclass
class LineageVerdict:
    lineage_id: str
    judgment: str  # "exploitable", "not_exploitable", "abstain"
    confidence: float
    reasoning: str


@dataclass
class ConvergenceResult:
    candidate_id: str
    agreed: bool
    lineages_judged: tuple[str, ...]
    per_lineage: dict[str, LineageVerdict]
    rationale: str
    trace: TraceRecord | None = None


@dataclass
class TraceRecord:
    lineage: str
    steps: tuple
    inputs_hash: str
    outputs_hash: str
