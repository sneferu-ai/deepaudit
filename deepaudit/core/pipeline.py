#!/usr/bin/env python3
from __future__ import annotations
"""End-to-end DeepAudit scan pipeline."""

import datetime
import json
import uuid
from pathlib import Path
from typing import Any
from deepaudit.config.defaults import DeepAuditConfig
from deepaudit.core.convergence import judge_candidate
from deepaudit.core.findings import (
    assemble_bundle,
    build_scan_result,
    bundle_to_json,
    candidate_to_proven,
)
from deepaudit.core.proof_oracle import run_proof
from deepaudit.core.repo_map import RepoModel, build_repo_model
from deepaudit.core.candidate_gen import generate_candidates
from deepaudit.core.static_scan import scan_repository
from deepaudit.languages.python.frontend import PythonLanguageFrontend
from deepaudit.models.candidate import VulnerabilityCandidate
from deepaudit.models.convergence import ConvergenceResult
from deepaudit.models.finding import DifferentialProof, FindingsBundle, ProvenFinding, ScanResult
from deepaudit.sdk.client import ConvergenceClient
from deepaudit.sandbox.runner import SandboxRunner, LocalRunner
from deepaudit.sandbox.env_probe import EnvironmentProbe, probe_current_environment


def _describe_sandbox(runner: SandboxRunner, config: DeepAuditConfig) -> dict[str, Any]:
    """Authoritative isolation descriptor for the bundle: ask the runner itself.

    Falls back to the config descriptor only for runners that predate
    ``describe()`` (e.g. test doubles). Always carries the configured timeout.
    """
    describe = getattr(runner, "describe", None)
    base = describe() if callable(describe) else config.sandbox_config()
    base = dict(base)
    base.setdefault("timeout", config.sandbox_timeout)
    return base


def _sdk_info(client: Any) -> dict[str, Any]:
    """Honest record of the convergence client that actually ran."""
    import importlib.util

    inner = getattr(client, "_client", client)
    cls = type(inner)
    name = f"{cls.__module__}.{cls.__qualname__}"
    is_mock = "mock" in cls.__module__.lower() or "mock" in cls.__qualname__.lower()
    # A real client talking to a mock/codegen engine is still mock convergence.
    engine_mock = bool(getattr(inner, "engine_reported_mock", False))
    claudopus_available = importlib.util.find_spec("claudopus") is not None
    return {
        "convergence_client": name,
        "claudopus_available": claudopus_available,
        "convergence_is_mock": is_mock or engine_mock,
        "engine_reported_mock": engine_mock,
        "engine_reported_degraded": bool(getattr(inner, "engine_reported_degraded", False)),
    }


def _build_convergence_client(config: DeepAuditConfig):
    """Real cross-lineage convergence (claudopus SDK) when reachable; HONEST mock
    fallback otherwise. The proof oracle stays the real false-positive gate either
    way, and ``_sdk_info`` records which client actually ran (convergence_is_mock).
    """
    from deepaudit.sdk.client import RealConvergenceClient

    base = getattr(config, "claudopus_base_url", "") or "http://127.0.0.1:7420"
    if RealConvergenceClient.available(base):
        return RealConvergenceClient(
            base_url=base, timeout=getattr(config, "convergence_timeout", 600)
        )
    return MockClient()


def run_deepaudit_scan(
    repo_path: Path | str,
    config: DeepAuditConfig | None = None,
    convergence_client: ConvergenceClient | None = None,
    runner: SandboxRunner | None = None,
    dry_run: bool = False,
    *,
    authorized: bool = False,
    mock_sdk: bool = False,
) -> ScanResult:
    """Run the full DeepAudit scan pipeline."""
    repo_path = Path(repo_path)
    config = config or DeepAuditConfig()
    if mock_sdk or getattr(config, "convergence_mode", "real") == "mock":
        convergence_client = MockClient()
    elif convergence_client is None:
        # Real cross-lineage convergence via the claudopus SDK when reachable;
        # HONEST mock fallback otherwise (sdk_info records convergence_is_mock).
        convergence_client = _build_convergence_client(config)
    compat_patch = config.compat_patch.read_text() if config.compat_patch else None
    runner = runner or LocalRunner(repo_path, compat_patch=compat_patch)
    env = probe_current_environment()

    started_at = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    scan_id = uuid.uuid4().hex
    errors: list[str] = []

    frontend = PythonLanguageFrontend()
    repo_model = build_repo_model(repo_path, frontend)
    errors.extend(f"parse failure: {rel}: {err}" for rel, err in repo_model.parse_failures)

    candidates = generate_candidates(
        repo_model, max_candidates=config.max_candidates,
        skip_single_file=getattr(config, "skip_single_file", True),
    )

    static_findings: list[ProvenFinding] = []
    if config.static_scan:
        static_findings = scan_repository(repo_path)

    proven: list[ProvenFinding] = []
    unverified: list[dict[str, Any]] = []
    converged_count = 0

    for candidate in candidates:
        convergence = judge_candidate(candidate, convergence_client, lineages=config.convergence_lineages)
        if not convergence.agreed:
            unverified.append({
                "candidate_id": candidate.id,
                "exploit_class": candidate.exploit_class,
                "reason": f"convergence disagreement: {convergence.rationale}",
                "convergence": convergence,
            })
            continue

        converged_count += 1

        if dry_run:
            unverified.append({
                "candidate_id": candidate.id,
                "exploit_class": candidate.exploit_class,
                "reason": "dry_run",
                "convergence": convergence,
            })
            continue

        proof = run_proof(candidate, runner, repo_model, env=env, timeout=config.sandbox_timeout)
        if proof is None or proof.verdict != "proven":
            reason = proof.unverified_reason if proof else "no template/adapter"
            unverified.append({
                "candidate_id": candidate.id,
                "exploit_class": candidate.exploit_class,
                "reason": reason,
                "proof": proof,
                "convergence": convergence,
            })
            continue

        proven.append(candidate_to_proven(candidate, convergence, proof, repo_model))

    finished_at = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    bundle = assemble_bundle(
        repo_path=repo_path,
        repo_model=repo_model,
        proven_findings=proven,
        static_findings=static_findings,
        unverified=unverified,
        scan_id=scan_id,
        started_at=started_at,
        finished_at=finished_at,
        sandbox_config=_describe_sandbox(runner, config),
        signing_key=config.signing_key,
        sdk_info=_sdk_info(convergence_client),
    )

    bundle_path: str | None = None
    if config.write_bundle:
        config.output_dir.mkdir(parents=True, exist_ok=True)
        bundle_path = str(config.output_dir / f"{scan_id}.bundle.json")
        with open(bundle_path, "w", encoding="utf-8") as f:
            json.dump(bundle_to_json(bundle), f, indent=2, default=str)

    return build_scan_result(bundle, bundle_path, repo_model, errors, converged_count=converged_count)


class MockClient:
    """Placeholder; real import happens in pipeline to avoid cycles."""

    def __init__(self):
        from deepaudit.sdk.mock import MockConvergenceClient

        self._client = MockConvergenceClient()

    def judge(self, candidate, *, lineages, require_agreement, on_disagreement):
        return self._client.judge(candidate, lineages=lineages, require_agreement=require_agreement, on_disagreement=on_disagreement)

    def trace_last(self, verdict):
        return self._client.trace_last(verdict)
