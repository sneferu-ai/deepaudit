from __future__ import annotations
"""Stage 3: differential proof-of-concept execution."""

import hashlib
import os
from pathlib import Path
from deepaudit.core.repo_map import RepoModel
from deepaudit.models.candidate import VulnerabilityCandidate
from deepaudit.models.finding import DifferentialProof
from deepaudit.poc_gen import generate_harnesses
from deepaudit.sandbox.env_probe import EnvironmentProbe, probe_current_environment
from deepaudit.sandbox.runner import SandboxRunner
from deepaudit.sandbox.sentinel import check_sentinel, hash_sentinel


def _clean_channels(channels: list[str]) -> None:
    """Remove any file-based sentinel artifacts from previous runs."""
    for channel in channels:
        if channel.startswith("file:"):
            path = Path(channel.split(":", 1)[1])
            try:
                if path.exists():
                    path.unlink()
            except Exception:
                pass


def run_proof(
    candidate: VulnerabilityCandidate,
    runner: SandboxRunner,
    repo_model: RepoModel,
    env: EnvironmentProbe | None = None,
    timeout: int = 60,
) -> DifferentialProof | None:
    """Generate and run exploit/control harnesses; return a DifferentialProof or None."""
    env = env or probe_current_environment()
    generated = generate_harnesses(candidate, env=env, repo_model=repo_model)
    exploit_code, control_code, template_name, adapter_name, sentinel, channels = generated
    if exploit_code is None or control_code is None or sentinel is None or channels is None:
        return None

    _clean_channels(channels)
    control_run = runner.run_harness(control_code, is_exploit=False, sentinel=sentinel, channels=channels, timeout=timeout)
    control_observed = control_run.sentinel_observed or check_sentinel(control_run.stdout, sentinel, channels)

    if control_observed:
        return _unverified(
            None,
            control_run,
            template_name,
            adapter_name,
            sentinel,
            exploit_code,
            control_code,
            channels,
            "sentinel_leak_in_control",
        )

    if control_run.status in ("timeout", "crash") or control_run.exit_code != 0:
        return _unverified(
            None,
            control_run,
            template_name,
            adapter_name,
            sentinel,
            exploit_code,
            control_code,
            channels,
            "control_unexpected_exit",
        )

    _clean_channels(channels)
    exploit_run = runner.run_harness(exploit_code, is_exploit=True, sentinel=sentinel, channels=channels, timeout=timeout)
    exploit_observed = exploit_run.sentinel_observed or check_sentinel(exploit_run.stdout, sentinel, channels)

    if exploit_run.status in ("timeout", "crash"):
        return _unverified(exploit_run, control_run, template_name, adapter_name, sentinel, exploit_code, control_code, channels, f"exploit harness {exploit_run.status}")
    if not exploit_observed:
        return _unverified(exploit_run, control_run, template_name, adapter_name, sentinel, exploit_code, control_code, channels, "sentinel not observed in exploit")

    return DifferentialProof(
        kind="differential",
        verdict="proven",
        unverified_reason=None,
        exploit_run=exploit_run,
        control_run=control_run,
        sentinel_hash=hash_sentinel(sentinel),
        poc_exploit=exploit_code,
        poc_control=control_code,
        template_name=template_name or "unknown",
        adapter_name=adapter_name or "unknown",
        channels=channels,
    )


def _unverified(
    exploit_run,
    control_run,
    template_name: str | None,
    adapter_name: str | None,
    sentinel: str,
    exploit_code: str,
    control_code: str,
    channels: list[str],
    reason: str,
) -> DifferentialProof:
    return DifferentialProof(
        kind="differential",
        verdict="unverified",
        unverified_reason=reason,
        exploit_run=exploit_run,
        control_run=control_run,
        sentinel_hash=hash_sentinel(sentinel),
        poc_exploit=exploit_code,
        poc_control=control_code,
        template_name=template_name or "unknown",
        adapter_name=adapter_name or "unknown",
        channels=channels,
    )
