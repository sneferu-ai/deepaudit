from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional
from deepaudit.models.taint import ProgramPoint
from deepaudit.models.convergence import ConvergenceResult, TraceRecord


@dataclass
class SandboxRunResult:
    """Result of a single exploit or control harness execution."""

    run_kind: str
    status: str
    exit_code: int
    stdout: str
    stderr: str
    sentinel_observed: bool
    duration_ms: int
    files_written: list[str]
    image_digest: str


@dataclass
class DifferentialProof:
    """Proof produced by a sandboxed differential run."""

    verdict: str
    unverified_reason: Optional[str]
    exploit_run: Optional[SandboxRunResult]
    control_run: Optional[SandboxRunResult]
    sentinel_hash: str
    poc_exploit: str
    poc_control: str
    template_name: str
    adapter_name: str
    channels: list[str] = field(default_factory=list)
    kind: str = "differential"


@dataclass
class StaticProof:
    """Proof for a static finding (e.g., secrets in code)."""

    evidence_description: str
    evidence_location: ProgramPoint
    pattern_matched: str
    pattern_id: str
    kind: str = "static"
    verdict: str = "proven"


@dataclass
class ProvenFinding:
    """A shipped finding in the bundle."""

    finding_id: str
    exploit_class: str
    severity: str
    source: ProgramPoint
    sink: ProgramPoint
    cross_file_path: list[ProgramPoint]
    sanitizers_on_path: list[ProgramPoint]
    cross_file: bool
    convergence: ConvergenceResult | None
    reproduction: DifferentialProof | StaticProof
    fix_suggestion: str
    provenance: dict


@dataclass
class FindingsBundle:
    schema_version: str
    scan_id: str
    started_at: str
    finished_at: str
    repo: dict
    sdk: dict
    sandbox: dict
    findings: list[ProvenFinding]
    static_findings: list[ProvenFinding]
    unverified: list[dict]
    signature: dict


@dataclass
class ScanSummary:
    files_parsed: int
    files_failed: int
    candidates: int
    converged: int
    proven: int
    unverified: int
    static_findings: int
    bundle_path: Optional[str]
    signature_fingerprint: Optional[str]


@dataclass
class ScanResult:
    exit_code: int
    bundle: Optional[FindingsBundle]
    bundle_path: Optional[str]
    summary: ScanSummary
    errors: list[str]
