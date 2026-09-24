#!/usr/bin/env python3
from __future__ import annotations
"""Assemble proven findings, static findings, and the final bundle."""

import dataclasses
import datetime
import json
import uuid
from pathlib import Path
from typing import Any

from deepaudit.core.repo_map import RepoModel
from deepaudit.crypto.signing import sign_bundle, verify_signature
from deepaudit.models.candidate import VulnerabilityCandidate
from deepaudit.models.convergence import ConvergenceResult
from deepaudit.models.finding import (
    DifferentialProof,
    FindingsBundle,
    ProvenFinding,
    ScanResult,
    ScanSummary,
    StaticProof,
)
from deepaudit.models.taint import ProgramPoint
from deepaudit.sandbox.sentinel import sentinel_in_source


def _iso_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def to_plain(obj: Any) -> Any:
    """Recursively convert dataclasses, Paths, and tuples into JSON-safe primitives."""
    if dataclasses.is_dataclass(obj):
        return {k: to_plain(v) for k, v in dataclasses.asdict(obj).items()}
    if isinstance(obj, dict):
        return {str(k): to_plain(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [to_plain(v) for v in obj]
    if isinstance(obj, Path):
        return str(obj)
    return obj


def bundle_to_json(bundle: FindingsBundle) -> dict[str, Any]:
    """Return a JSON-serializable dict for the bundle."""
    return to_plain(bundle)


def resign_bundle(bundle: FindingsBundle, signing_key: Path | None = None) -> None:
    """Recompute the signature on an already-assembled bundle.

    Used by the CLI after post-filtering (severity, unverified removal) so the
    written bundle remains internally consistent.
    """
    bundle_dict = to_plain(bundle)
    bundle_dict_without_sig = {k: v for k, v in bundle_dict.items() if k != "signature"}
    bundle.signature = sign_bundle(bundle_dict_without_sig, signing_key)


def _verify_sentinels(bundle_data: dict[str, Any]) -> bool:
    """Check that every differential proof has a matching embedded sentinel."""
    for finding in bundle_data.get("findings", []):
        reproduction = finding.get("reproduction", {})
        if reproduction.get("kind") != "differential":
            continue
        sentinel_hash = reproduction.get("sentinel_hash")
        if not sentinel_hash:
            return False
        if not sentinel_in_source(reproduction.get("poc_exploit", ""), sentinel_hash):
            return False
    return True


def verify_bundle(bundle_or_path: dict[str, Any] | str | Path | FindingsBundle) -> bool:
    """Verify a signed bundle: Ed25519 signature + embedded sentinel consistency.

    Accepts a FindingsBundle, a bundle dict, or a path to a JSON bundle file.
    """
    if isinstance(bundle_or_path, (str, Path)):
        path = Path(bundle_or_path)
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    elif isinstance(bundle_or_path, FindingsBundle):
        data = bundle_to_json(bundle_or_path)
    else:
        data = dict(bundle_or_path)

    signature = data.pop("signature", {})
    if not verify_signature(data, signature):
        return False
    return _verify_sentinels(data)


def _fix_suggestion(exploit_class: str) -> str:
    suggestions = {
        "sql_injection": "Use parameterized queries or an ORM; never interpolate user input into SQL.",
        "command_injection": "Avoid shell=True; pass argument lists and use shlex.quote if a shell is unavoidable.",
        "code_injection": "Avoid eval/exec on untrusted input; use a safe parser or whitelist.",
        "unsafe_deserialization": "Use safe formats (e.g., JSON) or signed/verified messages; avoid pickle/yaml on untrusted data.",
        "path_traversal": "Canonicalize paths with realpath/abspath and enforce a whitelist directory.",
        "template_injection": "Use Jinja2 autoescape/sandboxed environments and never render user input as templates.",
        "auth_bypass": "Compare secrets with hmac.compare_digest or a constant-time comparison, not ==.",
        "secrets_in_code": "Move secret to an environment variable or secret manager.",
    }
    return suggestions.get(exploit_class, "Review and harden the affected code path.")


def _severity(exploit_class: str) -> str:
    severities = {
        "sql_injection": "high",
        "command_injection": "critical",
        "code_injection": "critical",
        "unsafe_deserialization": "critical",
        "path_traversal": "high",
        "template_injection": "high",
        "auth_bypass": "high",
        "secrets_in_code": "medium",
    }
    return severities.get(exploit_class, "high")


def candidate_to_proven(
    candidate: VulnerabilityCandidate,
    convergence: ConvergenceResult,
    proof: DifferentialProof,
    repo_model: RepoModel,
) -> ProvenFinding:
    return ProvenFinding(
        finding_id=uuid.uuid4().hex,
        exploit_class=candidate.exploit_class,
        severity=_severity(candidate.exploit_class),
        source=candidate.source,
        sink=candidate.sink,
        cross_file_path=candidate.taint_path,
        sanitizers_on_path=candidate.sanitizers_on_path,
        cross_file=candidate.cross_file,
        convergence=convergence,
        reproduction=proof,
        fix_suggestion=_fix_suggestion(candidate.exploit_class),
        provenance={
            "source_module": candidate.source_module,
            "source_function": candidate.source_function,
            "sink_module": candidate.sink_module,
            "sink_function": candidate.sink_function,
            "repo_root": str(repo_model.root),
        },
    )


def assemble_bundle(
    repo_path: Path,
    repo_model: RepoModel,
    proven_findings: list[ProvenFinding],
    static_findings: list[ProvenFinding],
    unverified: list[dict[str, Any]],
    scan_id: str,
    started_at: str,
    finished_at: str,
    sandbox_config: dict[str, Any],
    signing_key: Path | None = None,
    sdk_info: dict[str, Any] | None = None,
) -> FindingsBundle:
    repo_info = {
        "path": str(repo_path),
        "files_parsed": len(repo_model.files),
        "files_failed": len(repo_model.parse_failures),
    }
    # sdk_info must reflect the convergence client that ACTUALLY ran (threaded in
    # by the pipeline). The honest default below is used only when no info is
    # supplied; it never silently claims the real claudopus engine was used.
    if sdk_info is None:
        sdk_info = {
            "convergence_client": "deepaudit.sdk.mock.MockConvergenceClient",
            "claudopus_available": False,
            "convergence_is_mock": True,
        }
    bundle = FindingsBundle(
        schema_version="1.0.0",
        scan_id=scan_id,
        started_at=started_at,
        finished_at=finished_at,
        repo=repo_info,
        sdk=sdk_info,
        sandbox=sandbox_config,
        findings=proven_findings,
        static_findings=static_findings,
        unverified=unverified,
        signature={},
    )
    bundle_dict = to_plain(bundle)
    bundle_dict_without_sig = {k: v for k, v in bundle_dict.items() if k != "signature"}
    bundle.signature = sign_bundle(bundle_dict_without_sig, signing_key)
    return bundle


def build_scan_result(
    bundle: FindingsBundle,
    bundle_path: str | None,
    repo_model: RepoModel,
    errors: list[str],
    converged_count: int = 0,
) -> ScanResult:
    summary = ScanSummary(
        files_parsed=len(repo_model.files),
        files_failed=len(repo_model.parse_failures),
        candidates=len(bundle.findings) + len(bundle.unverified),
        converged=converged_count,
        proven=len(bundle.findings),
        unverified=len(bundle.unverified),
        static_findings=len(bundle.static_findings),
        bundle_path=bundle_path,
        signature_fingerprint=bundle.signature.get("fingerprint"),
    )
    return ScanResult(
        exit_code=0,
        bundle=bundle,
        bundle_path=bundle_path,
        summary=summary,
        errors=errors,
    )
