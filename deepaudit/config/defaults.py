#!/usr/bin/env python3
from __future__ import annotations
"""Default configuration for DeepAudit scans."""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class DeepAuditConfig:
    max_candidates: int = 200
    convergence_lineages: list[str] = field(default_factory=lambda: ["lineage-A", "lineage-B"])
    sandbox_timeout: int = 60
    sandbox_mode: str = "local"  # local | docker
    sandbox_image: str = "python:3.11-slim"
    enable_signatures: bool = True
    signing_key: Path | None = None
    output_dir: Path = field(default_factory=lambda: Path("deepaudit-results"))
    static_scan: bool = True
    skip_single_file: bool = True
    write_bundle: bool = True
    compat_patch: Path | None = None

    # ── Convergence (the cross-lineage SDK judge) ───────────────────────────
    # "real" calls the claudopus SDK's POST /sdk/judge — distinct trainer-lineage
    # models must AGREE a candidate is genuinely exploitable before it advances to
    # the proof oracle. "mock" uses the deterministic in-process stub. The CLI's
    # --mock-sdk forces "mock". Base URL is env-driven (never hardcoded); when the
    # SDK is unimportable or the orchestrator is unreachable the pipeline degrades
    # HONESTLY to mock and the signed bundle's sdk_info records convergence_is_mock.
    convergence_mode: str = "real"  # real | mock
    claudopus_base_url: str = field(
        default_factory=lambda: os.environ.get("CLAUDOPUS_BASE_URL", "http://127.0.0.1:7420")
    )
    convergence_require_agreement: str = "unanimous"  # unanimous | majority
    convergence_timeout: int = 600

    def sandbox_config(self) -> dict[str, Any]:
        """Fallback isolation descriptor when the runner cannot self-describe.

        The authoritative descriptor in the signed bundle comes from
        ``runner.describe()`` (see ``core.pipeline``). This fallback must still
        be HONEST: v1 has no working container isolation, so it never claims an
        isolation level that was not applied.
        """
        if self.sandbox_mode == "docker":
            return {
                "mode": "docker",
                "timeout": self.sandbox_timeout,
                "image": self.sandbox_image,
                "network": "none",
                "repo_mount": "copy",
                "isolation_applied": False,
                "note": "docker requested; Docker sandbox is a v1 stub (no container executed).",
            }
        return {
            "mode": "local",
            "timeout": self.sandbox_timeout,
            "image": None,
            "network": "host",
            "repo_mount": "in-place",
            "isolation_applied": False,
            "note": "local execution: host subprocess, no container isolation.",
        }


def load_config(path: Path | None = None) -> DeepAuditConfig:
    """Load configuration; currently returns defaults."""
    return DeepAuditConfig()
