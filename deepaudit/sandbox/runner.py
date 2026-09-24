#!/usr/bin/env python3
from __future__ import annotations
"""Sandbox runners: local subprocess and Docker container."""

import os
import sys
import subprocess
import tempfile
import time
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Protocol
from deepaudit.models.finding import SandboxRunResult
from deepaudit.sandbox.docker_runner import DockerRunner as _DockerRunnerImpl
from deepaudit.sandbox.sentinel import check_sentinel


class SandboxRunner(ABC):
    """Abstract interface for harness execution."""

    @abstractmethod
    def run_harness(
        self,
        source_code: str,
        is_exploit: bool,
        sentinel: str,
        channels: list[str] | None = None,
        timeout: int = 30,
    ) -> SandboxRunResult: ...


class LocalRunner(SandboxRunner):
    """Run the harness in a local subprocess.

    SECURITY NOTE: this runner provides NO container isolation. The harness
    executes the target's (potentially attacker-influenced) code path as an
    ordinary host subprocess with unrestricted network and filesystem access.
    It is the v1 proof environment; the Docker runner that supplies real
    isolation (``--network none``, ``--cap-drop ALL``) is not available in v1.
    ``describe()`` reports this honestly so the signed bundle never claims an
    isolation level it did not apply.
    """

    _MAX_CAPTURE = 1_048_576  # 1 MB stdout/stderr truncation

    # Only these host env vars are forwarded into the harness subprocess.
    # Everything else (cloud credentials, tokens, CI secrets, ...) is dropped
    # so a proof run cannot exfiltrate host secrets through the target code.
    # PATH must stay: shell-based exploits (e.g. command injection) need it to
    # resolve ``sh``/``echo``. Any var prefixed ``LC_`` is also forwarded.
    _ENV_ALLOWLIST = ("PATH", "HOME", "TMPDIR", "TMP", "TEMP", "LANG", "TERM")

    def __init__(self, repo_path: Path, compat_patch: str | None = None, env_passthrough: bool = False):
        self.repo_path = Path(repo_path).resolve()
        self.compat_patch = compat_patch
        # When True, inherit the full host environment (legacy behaviour).
        # Default False: the harness gets a scrubbed allowlist only.
        self.env_passthrough = env_passthrough

    def _harness_env(self) -> dict[str, str]:
        """Build the (scrubbed by default) environment for the harness subprocess."""
        if self.env_passthrough:
            env = os.environ.copy()
        else:
            env = {
                k: v
                for k, v in os.environ.items()
                if k in self._ENV_ALLOWLIST or k.startswith("LC_")
            }
        env["PYTHONHASHSEED"] = "0"
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        env["PYTHONIOENCODING"] = "utf-8"
        return env

    def describe(self) -> dict:
        """Honest isolation descriptor recorded in the signed bundle."""
        return {
            "mode": "local",
            "runner": "LocalRunner",
            "isolation": "none",
            "isolation_applied": False,
            "network": "host",
            "repo_mount": "in-place",
            "env": "host-inherited" if self.env_passthrough else "scrubbed-allowlist",
            "note": (
                "Harnesses ran as host subprocesses WITHOUT container isolation; "
                "network access was not restricted. 'proven' findings were "
                "reproduced on this host, not inside a sealed sandbox."
            ),
        }

    def run_harness(
        self,
        source_code: str,
        is_exploit: bool,
        sentinel: str,
        channels: list[str] | None = None,
        timeout: int = 30,
    ) -> SandboxRunResult:
        channels = channels or ["stdout"]
        # Inject the real repository path for imports.
        repo_path_line = f'sys.path.insert(0, {str(self.repo_path)!r})'
        if self.compat_patch:
            repo_path_line += f'\n\n{self.compat_patch}'
        code = source_code.replace(
            'sys.path.insert(0, "/repo")',
            repo_path_line,
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            harness_path = Path(tmpdir) / "harness.py"
            harness_path.write_text(code, encoding="utf-8")
            env = self._harness_env()
            start = time.perf_counter()
            try:
                proc = subprocess.run(
                    [sys.executable, "-u", str(harness_path)],
                    cwd=self.repo_path,
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                )
                status = "ok"
            except subprocess.TimeoutExpired:
                proc = subprocess.CompletedProcess(args=[], returncode=-1, stdout="", stderr="")
                status = "timeout"
            except OSError:
                proc = subprocess.CompletedProcess(args=[], returncode=-1, stdout="", stderr="")
                status = "crash"
            duration_ms = int((time.perf_counter() - start) * 1000)

        stdout = (proc.stdout or "")[:self._MAX_CAPTURE]
        stderr = (proc.stderr or "")[:self._MAX_CAPTURE]
        sentinel_observed = check_sentinel(stdout, sentinel, channels, stderr=stderr)

        # Best-effort list of files created in /tmp that contain the sentinel.
        files_written = []
        if sentinel_observed:
            for f in Path("/tmp").glob("sentinel-*"):
                try:
                    if f.is_file() and sentinel in f.read_text(errors="ignore"):
                        files_written.append(str(f))
                except Exception:
                    pass

        return SandboxRunResult(
            run_kind="exploit" if is_exploit else "control",
            status=status,
            exit_code=proc.returncode,
            stdout=stdout,
            stderr=stderr,
            sentinel_observed=sentinel_observed,
            duration_ms=duration_ms,
            files_written=files_written,
            image_digest="",
        )


class DockerRunner(SandboxRunner):
    """Thin wrapper around the Docker runner implementation.

    NOTE: the underlying implementation is a v1 stub — no container is actually
    launched, so every harness is reported as crashed and proofs requested in
    docker mode come back UNVERIFIED. ``describe()`` reports this honestly.
    """

    def __init__(self, repo_path: Path, image_digest: str | None = None, compat_patch: str | None = None):
        # Forward compat_patch instead of silently dropping it (kills the
        # silent-drop class even though the impl is a stub today).
        self._impl = _DockerRunnerImpl(repo_path, image_digest=image_digest, compat_patch=compat_patch)
        self.compat_patch = compat_patch

    def run_harness(
        self,
        source_code: str,
        is_exploit: bool,
        sentinel: str,
        channels: list[str] | None = None,
        timeout: int = 30,
    ) -> SandboxRunResult:
        return self._impl.run_harness(source_code, is_exploit, sentinel, channels=channels, timeout=timeout)

    def describe(self) -> dict:
        """Honest isolation descriptor recorded in the signed bundle."""
        return {
            "mode": "docker",
            "runner": "DockerRunner",
            "isolation": "container",
            "isolation_applied": False,  # v1 impl is a stub; nothing actually ran
            "network": "none",
            "repo_mount": "copy",
            "image_digest": getattr(self._impl, "image_digest", "") or "",
            "note": (
                "Docker sandbox is a v1 stub; no container executed. Proofs "
                "requested in docker mode are reported UNVERIFIED, never 'proven'."
            ),
        }
