#!/usr/bin/env python3
from __future__ import annotations
"""Docker-based sandbox runner (stub)."""

from pathlib import Path
from deepaudit.models.finding import SandboxRunResult


class DockerRunner:
    """Run a harness inside a Docker container (v1 stub)."""

    def __init__(self, repo_path: Path, image_digest: str | None = None, compat_patch: str | None = None):
        self.repo_path = Path(repo_path)
        self.image_digest = image_digest
        # Stored (not dropped) so a future real implementation can inject it
        # before the harness import, matching LocalRunner's behaviour.
        self.compat_patch = compat_patch

    def run_harness(
        self,
        source_code: str,
        is_exploit: bool,
        sentinel: str,
        channels: list[str] | None = None,
        timeout: int = 30,
    ) -> SandboxRunResult:
        return SandboxRunResult(
            run_kind="exploit" if is_exploit else "control",
            status="crash",
            exit_code=1,
            stdout="",
            stderr="Docker sandbox not available in v1.",
            sentinel_observed=False,
            duration_ms=0,
            files_written=[],
            image_digest=self.image_digest or "",
        )
