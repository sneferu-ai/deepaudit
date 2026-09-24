#!/usr/bin/env python3
from __future__ import annotations
"""Thin shim over the claudopus convergence SDK."""

from deepaudit.models.candidate import VulnerabilityCandidate
from deepaudit.models.convergence import ConvergenceResult, TraceRecord
from deepaudit.sdk.client import ConvergenceClient


def taint_candidate_dict(candidate: VulnerabilityCandidate) -> dict:
    """Serialize a candidate into the SDK input schema."""
    return {
        "id": candidate.id,
        "exploit_class": candidate.exploit_class,
        "source": candidate.source.as_dict(),
        "sink": candidate.sink.as_dict(),
        "taint_path": [p.as_dict() for p in candidate.taint_path],
        "sanitizers_on_path": [p.as_dict() for p in candidate.sanitizers_on_path],
        "sanitizer_bypassed": candidate.sanitizer_bypassed,
        "cross_file": candidate.cross_file,
    }


def judge_candidate(candidate: VulnerabilityCandidate, client: ConvergenceClient, lineages: list[str] | None = None) -> ConvergenceResult:
    """Submit a candidate to the convergence client and return the verdict with trace."""
    payload = taint_candidate_dict(candidate)
    lineages = lineages or ["lineage-A", "lineage-B"]
    result = client.judge(
        payload,
        lineages=lineages,
        require_agreement="all",
        on_disagreement="reject",
    )
    if result.agreed:
        result.trace = trace_for_verdict(result, client)
    return result


def trace_for_verdict(verdict: ConvergenceResult, client: ConvergenceClient) -> TraceRecord:
    """Capture the trace record for a convergence verdict."""
    return client.trace_last(verdict)
