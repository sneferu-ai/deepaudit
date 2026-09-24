from __future__ import annotations
from typing import Protocol
from deepaudit.core.repo_map import RepoModel
from deepaudit.core.source_adapters import SourceAdapter
from deepaudit.models.candidate import VulnerabilityCandidate


class EnvironmentProbe(Protocol):
    """Sandbox/environment capability probe."""

    has_sqlite: bool
    has_docker: bool
    has_jinja2: bool
    writable_tmp: bool
    installed_packages: set[str]


class PoCTemplate(Protocol):
    """Strategy for generating exploit and control harnesses."""

    name: str
    exploit_class: str

    def preconditions(self, candidate: VulnerabilityCandidate, repo_model: RepoModel) -> bool: ...
    def environmental_preconditions(self, candidate: VulnerabilityCandidate, env: EnvironmentProbe) -> bool: ...
    def generate_exploit(self, candidate: VulnerabilityCandidate, sentinel: str, adapter: SourceAdapter, repo_model: RepoModel) -> str: ...
    def generate_control(self, candidate: VulnerabilityCandidate, sentinel: str, adapter: SourceAdapter, repo_model: RepoModel) -> str: ...
    def sentinel_channels(self) -> list[str]: ...
    def resolved_channels(self, candidate: VulnerabilityCandidate) -> list[str]: ...


class BaseTemplate:
    """Minimal base with common helpers."""

    name: str
    exploit_class: str

    def preconditions(self, candidate: VulnerabilityCandidate, repo_model: RepoModel) -> bool:
        return candidate.exploit_class == self.exploit_class

    def environmental_preconditions(self, candidate: VulnerabilityCandidate, env: EnvironmentProbe) -> bool:
        return True

    def generate_exploit(self, candidate: VulnerabilityCandidate, sentinel: str, adapter: SourceAdapter, repo_model: RepoModel) -> str:
        raise NotImplementedError

    def generate_control(self, candidate: VulnerabilityCandidate, sentinel: str, adapter: SourceAdapter, repo_model: RepoModel) -> str:
        raise NotImplementedError

    def sentinel_channels(self) -> list[str]:
        return ["stdout"]

    def resolved_channels(self, candidate: VulnerabilityCandidate) -> list[str]:
        return self.sentinel_channels()
