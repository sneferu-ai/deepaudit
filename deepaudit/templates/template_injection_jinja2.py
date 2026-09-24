#!/usr/bin/env python3
from __future__ import annotations
"""Template-injection PoC for Jinja2 sinks."""

from deepaudit.core.repo_map import RepoModel
from deepaudit.core.source_adapters import SourceAdapter
from deepaudit.models.candidate import VulnerabilityCandidate
from deepaudit.templates.base import BaseTemplate


class TemplateInjectionJinja2Template(BaseTemplate):
    name = "template_injection_jinja2"
    exploit_class = "template_injection"
    def sentinel_channels(self) -> list[str]:
        return ["stdout"]

    def preconditions(self, candidate: VulnerabilityCandidate, repo_model: RepoModel) -> bool:
        if not super().preconditions(candidate, repo_model):
            return False
        return candidate.sink_metadata.template_engine == "jinja2"

    def environmental_preconditions(self, candidate, env) -> bool:
        return env.has_jinja2

    def _payload(self, candidate: VulnerabilityCandidate, sentinel: str, is_exploit: bool) -> str:
        if is_exploit:
            return f"{{{{ '{sentinel}' }}}}"
        return "Hello World"

    def generate_exploit(self, candidate, sentinel, adapter: SourceAdapter, repo_model: RepoModel) -> str:
        payload = self._payload(candidate, sentinel, True)
        setup = adapter.generate_setup(candidate.source, sentinel, True, candidate, payload)
        invocation = adapter.generate_invocation(candidate.source, sentinel, True, candidate, payload)
        return f"""{setup}
import sys
sys.path.insert(0, "/repo")

import {candidate.source_module}

{invocation}

if {sentinel!r} in str(result):
    print({sentinel!r})

print("__HARNESS_DONE__")
"""

    def generate_control(self, candidate, sentinel, adapter: SourceAdapter, repo_model: RepoModel) -> str:
        payload = self._payload(candidate, sentinel, False)
        setup = adapter.generate_setup(candidate.source, sentinel, False, candidate, payload)
        invocation = adapter.generate_invocation(candidate.source, sentinel, False, candidate, payload)
        return f"""{setup}
import sys
sys.path.insert(0, "/repo")

import {candidate.source_module}

{invocation}

if {sentinel!r} in str(result):
    print({sentinel!r})

print("__HARNESS_DONE__")
"""
