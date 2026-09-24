#!/usr/bin/env python3
from __future__ import annotations
"""Source→sink candidate enumeration and deterministic ordering."""

from deepaudit.core.repo_map import RepoModel
from deepaudit.core.taint_engine import analyze
from deepaudit.models.candidate import VulnerabilityCandidate


def generate_candidates(
    model: RepoModel, max_candidates: int = 200, skip_single_file: bool = True,
) -> list[VulnerabilityCandidate]:
    """Run taint analysis, order deterministically, truncate.

    ``skip_single_file`` keeps ONLY cross-file flows when True. This was a hardcoded
    filter — but a single-file taint flow found by real inter-procedural analysis
    (untrusted source → dangerous sink in the same handler, e.g. DSVW's SQLi) is a
    LEGITIMATE finding, not the "single-file regex linter" the spec warned against.
    Dropping it unconditionally made DeepAudit blind to the most common real-world
    bug shape. It is now caller-controlled; ``cross_file`` survives as a label."""
    candidates = analyze(model)
    if skip_single_file:
        candidates = [c for c in candidates if c.cross_file]
    candidates.sort(
        key=lambda c: (
            c.source.file,
            c.source.line,
            c.source.column,
            c.sink.file,
            c.sink.line,
            c.sink.column,
        )
    )
    if len(candidates) > max_candidates:
        candidates = candidates[:max_candidates]
    return candidates
