#!/usr/bin/env python3
from __future__ import annotations
"""Deterministic mock convergence client for local testing."""

from typing import Any
from deepaudit.models.convergence import ConvergenceResult, LineageVerdict, TraceRecord
from deepaudit.sdk.client import ConvergenceClient


class MockConvergenceClient(ConvergenceClient):
    """Returns a unanimous exploitable verdict for every candidate.

    A separate RejectingMockConvergenceClient can be used to test the
    unverified path.
    """

    def judge(
        self,
        candidate: dict[str, Any],
        *,
        lineages: list[str],
        require_agreement: str,
        on_disagreement: str,
    ) -> ConvergenceResult:
        per_lineage = {
            lineage: LineageVerdict(lineage, "exploitable", 1.0, "mock-agreement")
            for lineage in lineages
        }
        return ConvergenceResult(
            candidate_id=candidate.get("id", "unknown"),
            agreed=True,
            lineages_judged=tuple(lineages),
            per_lineage=per_lineage,
            rationale="mock convergence: unanimous exploitable",
        )

    def trace_last(self, verdict: ConvergenceResult) -> TraceRecord:
        return TraceRecord(
            lineage="mock",
            steps=(),
            inputs_hash="",
            outputs_hash="",
        )


class RejectingMockConvergenceClient(ConvergenceClient):
    """Always disagrees, so candidates move to the unverified list."""

    def judge(
        self,
        candidate: dict[str, Any],
        *,
        lineages: list[str],
        require_agreement: str,
        on_disagreement: str,
    ) -> ConvergenceResult:
        per_lineage = {}
        for i, lineage in enumerate(lineages):
            judgment = "exploitable" if i == 0 else "not_exploitable"
            per_lineage[lineage] = LineageVerdict(lineage, judgment, 0.8, "mock-disagreement")
        return ConvergenceResult(
            candidate_id=candidate.get("id", "unknown"),
            agreed=False,
            lineages_judged=tuple(lineages),
            per_lineage=per_lineage,
            rationale="mock convergence: disagreement",
        )

    def trace_last(self, verdict: ConvergenceResult) -> TraceRecord:
        return TraceRecord(lineage="mock", steps=(), inputs_hash="", outputs_hash="")
