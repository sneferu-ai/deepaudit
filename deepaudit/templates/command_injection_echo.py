#!/usr/bin/env python3
from __future__ import annotations
"""Command-injection PoC for shell=True / os.system style sinks."""

from deepaudit.core.repo_map import RepoModel
from deepaudit.core.source_adapters import SourceAdapter
from deepaudit.models.candidate import VulnerabilityCandidate
from deepaudit.templates.base import BaseTemplate


class CommandInjectionEchoTemplate(BaseTemplate):
    name = "command_injection_echo"
    exploit_class = "command_injection"
    def sentinel_channels(self) -> list[str]:
        return ["stdout"]

    def preconditions(self, candidate: VulnerabilityCandidate, repo_model: RepoModel) -> bool:
        if not super().preconditions(candidate, repo_model):
            return False
        return candidate.sink_metadata.shell_enabled is True and candidate.sink_metadata.is_code_exec is False

    def _payload(self, candidate: VulnerabilityCandidate, sentinel: str, is_exploit: bool) -> str:
        if is_exploit:
            return f"test; echo {sentinel}"
        return "benign_input"

    def generate_exploit(self, candidate, sentinel, adapter: SourceAdapter, repo_model: RepoModel) -> str:
        payload = self._payload(candidate, sentinel, True)
        setup = adapter.generate_setup(candidate.source, sentinel, True, candidate, payload)
        invocation = adapter.generate_invocation(candidate.source, sentinel, True, candidate, payload)
        return f"""{setup}
import sys
sys.path.insert(0, "/repo")

import {candidate.source_module}

{invocation}

# Sentinel is emitted by the injected shell command; the runner observes stdout.
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

print("__HARNESS_DONE__")
"""
