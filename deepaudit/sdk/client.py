#!/usr/bin/env python3
from __future__ import annotations
"""Claudopus convergence SDK interface.

The convergence step is DeepAudit's core thesis: distinct trainer-lineage models
must AGREE a candidate is genuinely exploitable before it advances to the proof
oracle. ``RealConvergenceClient`` calls the claudopus public SDK's POST /sdk/judge
(``claudopus.Client.judge``) to do exactly that. When the SDK is unimportable or
the orchestrator is unreachable, the pipeline degrades HONESTLY to the in-process
mock (the signed bundle's ``sdk_info`` records ``convergence_is_mock``) — the proof
oracle remains the real false-positive gate either way.
"""

from typing import Protocol, Any

from deepaudit.models.convergence import ConvergenceResult, TraceRecord


class ConvergenceClient(Protocol):
    """External convergence judgment client."""

    def judge(
        self,
        candidate: dict[str, Any],
        *,
        lineages: list[str],
        require_agreement: str,
        on_disagreement: str,
    ) -> ConvergenceResult: ...

    def trace_last(self, verdict: ConvergenceResult) -> TraceRecord: ...


# ── claim/context rendering ──────────────────────────────────────────────

def _loc(d: Any) -> str:
    if not isinstance(d, dict):
        return str(d)
    f = d.get("file") or d.get("path") or "?"
    line = d.get("line")
    func = d.get("function") or d.get("func")
    expr = d.get("expression") or d.get("expr")
    out = str(f)
    if line is not None:
        out += f":{line}"
    if func:
        out += f" (in {func})"
    if expr:
        out += f"  ->  {expr}"
    return out


def candidate_claim(payload: dict[str, Any]) -> str:
    cls = payload.get("exploit_class", "vulnerability")
    cross = " (cross-file)" if payload.get("cross_file") else ""
    return (
        f"The following is a GENUINELY EXPLOITABLE {cls} vulnerability{cross}: "
        f"untrusted input flows from the source to the dangerous sink along the "
        f"taint path with no effective sanitizer neutralising it."
    )


def candidate_context(payload: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append(f"Exploit class: {payload.get('exploit_class', '?')}")
    lines.append(f"Cross-file: {bool(payload.get('cross_file'))}")
    lines.append(f"SOURCE (untrusted input): {_loc(payload.get('source'))}")
    lines.append(f"SINK (dangerous operation): {_loc(payload.get('sink'))}")
    tp = payload.get("taint_path") or []
    if tp:
        lines.append("Taint path:")
        for i, p in enumerate(tp):
            lines.append(f"  {i + 1}. {_loc(p)}")
    sans = payload.get("sanitizers_on_path") or []
    if sans:
        lines.append("Sanitizers seen on path: " + "; ".join(_loc(s) for s in sans))
        lines.append(f"Sanitizer bypassed: {bool(payload.get('sanitizer_bypassed'))}")
    else:
        lines.append("Sanitizers seen on path: NONE")
    return "\n".join(lines)


_JUDGE_QUESTION = (
    "Is this a genuinely exploitable vulnerability — a real, reachable taint flow "
    "from an untrusted source to a dangerous sink, with no effective sanitizer on "
    "the path? Affirm ONLY if a concrete attacker-controlled value can reach the "
    "sink and cause harm; deny if the flow is infeasible, already sanitized, or not "
    "attacker-controlled."
)

# DeepAudit's require_agreement vocabulary -> the SDK's.
_AGREEMENT_MAP = {"all": "unanimous", "unanimous": "unanimous", "majority": "majority"}


class RealConvergenceClient:
    """Cross-lineage convergence via the claudopus public SDK (POST /sdk/judge)."""

    def __init__(self, base_url: str = "http://127.0.0.1:7420", timeout: int = 600):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._last_per_lineage: dict[str, Any] = {}
        # What the ENGINE reported about its own judges. A Sneferu server in mock
        # or codegen mode answers with is_mock=true; a panel with fewer than two
        # distinct lineages answers degraded=true. The bundle's sdk block reads
        # these, so a scan against a mock engine can never pass as real convergence.
        self.engine_reported_mock = False
        self.engine_reported_degraded = False

    @staticmethod
    def available(base_url: str, timeout: float = 2.0) -> bool:
        """True iff the claudopus SDK imports AND the orchestrator answers.

        A fast liveness probe (GET /cast-presets) so the pipeline can decide ONCE
        whether to use real convergence or degrade honestly to mock — rather than
        discovering unreachability per-candidate mid-scan.
        """
        try:
            import importlib
            importlib.import_module("claudopus")
        except Exception:
            return False
        try:
            import urllib.request
            url = base_url.rstrip("/") + "/cast-presets"
            with urllib.request.urlopen(url, timeout=timeout) as resp:
                return 200 <= resp.status < 500
        except Exception:
            return False

    def judge(
        self,
        candidate: dict[str, Any],
        *,
        lineages: list[str],
        require_agreement: str,
        on_disagreement: str,
    ) -> ConvergenceResult:
        cid = candidate.get("id", "unknown")
        try:
            from claudopus import Client  # generated SDK

            client = Client(self.base_url)
            # The generated judge() validates a plain dict into JudgeRequest, so we
            # avoid importing the internal request model.
            jr = client.judge({
                "claim": candidate_claim(candidate),
                "context": candidate_context(candidate),
                "question": _JUDGE_QUESTION,
                "require_agreement": _AGREEMENT_MAP.get(require_agreement, "unanimous"),
                "claim_id": cid,
            })
            per_lineage = dict(getattr(jr, "per_lineage", {}) or {})
            self._last_per_lineage = per_lineage
            if getattr(jr, "is_mock", False) is True:
                self.engine_reported_mock = True
            if getattr(jr, "degraded", False) is True:
                self.engine_reported_degraded = True
            return ConvergenceResult(
                candidate_id=cid,
                agreed=bool(getattr(jr, "agreed", False)),
                lineages_judged=tuple(getattr(jr, "lineages_judged", []) or []),
                per_lineage=per_lineage,
                rationale=str(getattr(jr, "rationale", "")),
            )
        except Exception as exc:
            # NEVER affirm on error — a failed judge is a non-agreement (the
            # candidate stays unverified), honestly labelled.
            self._last_per_lineage = {}
            return ConvergenceResult(
                candidate_id=cid,
                agreed=False,
                lineages_judged=tuple(),
                per_lineage={},
                rationale=f"convergence SDK error (not a model verdict): {exc}",
            )

    def trace_last(self, verdict: ConvergenceResult) -> TraceRecord:
        return TraceRecord(
            lineage=",".join(verdict.lineages_judged) or "unknown",
            steps=tuple(self._last_per_lineage.keys()),
            inputs_hash="",
            outputs_hash="",
        )
