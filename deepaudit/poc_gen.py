#!/usr/bin/env python3
from __future__ import annotations
"""Proof-of-concept harness selection and generation."""

from typing import Tuple
from deepaudit.core.repo_map import RepoModel
from deepaudit.core.source_adapters import select_adapter
from deepaudit.sandbox.env_probe import EnvironmentProbe, probe_current_environment
from deepaudit.sandbox.sentinel import make_sentinel
from deepaudit.templates import ALL_TEMPLATES
from deepaudit.models.candidate import VulnerabilityCandidate


def _sentinel_id(candidate: VulnerabilityCandidate) -> str:
    return candidate.id[:8]


def get_templates_for(candidate: VulnerabilityCandidate) -> list:
    return [t for t in ALL_TEMPLATES if t.exploit_class == candidate.exploit_class]


def select_template(
    candidate: VulnerabilityCandidate,
    env: EnvironmentProbe,
    repo_model: RepoModel,
):
    """Select the first template whose preconditions and environment are satisfied."""
    for template in get_templates_for(candidate):
        if template.preconditions(candidate, repo_model) and template.environmental_preconditions(candidate, env):
            return template
    return None


def generate_harnesses(
    candidate: VulnerabilityCandidate,
    env: EnvironmentProbe | None = None,
    repo_model: RepoModel | None = None,
) -> Tuple[str | None, str | None, str | None, str | None, str | None, list[str] | None]:
    """Return (exploit_harness, control_harness, template_name, adapter_name, sentinel, channels)."""
    env = env or probe_current_environment()
    adapter = select_adapter(candidate)
    if adapter is None:
        return None, None, None, None, None, None
    template = select_template(candidate, env, repo_model or RepoModel(root=object(), functions={}, files=[], parse_failures=[], module_to_files={}))
    adapter_name = type(adapter).__name__
    if template is None:
        return None, None, None, adapter_name, None, None
    sentinel = make_sentinel()
    exploit = template.generate_exploit(candidate, sentinel, adapter, repo_model)
    control = template.generate_control(candidate, sentinel, adapter, repo_model)
    channels = template.resolved_channels(candidate)
    return exploit, control, template.name, adapter_name, sentinel, channels
