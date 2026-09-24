#!/usr/bin/env python3
from __future__ import annotations
"""Source-kind-to-harness-injection mapping."""

import re
from typing import Protocol
from deepaudit.models.candidate import VulnerabilityCandidate
from deepaudit.models.taint import ProgramPoint


class SourceAdapter(Protocol):
    """Maps a detected source to a harness injection strategy."""

    kind: str
    priority: int

    def can_handle(self, source: ProgramPoint, candidate: VulnerabilityCandidate) -> bool: ...
    def generate_setup(self, source: ProgramPoint, sentinel: str, is_exploit: bool, candidate: VulnerabilityCandidate, payload: str) -> str: ...
    def generate_invocation(self, source: ProgramPoint, sentinel: str, is_exploit: bool, candidate: VulnerabilityCandidate, payload: str) -> str: ...


class GenericFunctionParamAdapter:
    """Fallback adapter for any function-parameter source."""

    kind = "generic_param"
    priority = 0

    def can_handle(self, source: ProgramPoint, candidate: VulnerabilityCandidate) -> bool:
        return candidate.source_is_parameter

    def generate_setup(self, source: ProgramPoint, sentinel: str, is_exploit: bool, candidate: VulnerabilityCandidate, payload: str) -> str:
        return ""

    def generate_invocation(self, source: ProgramPoint, sentinel: str, is_exploit: bool, candidate: VulnerabilityCandidate, payload: str) -> str:
        return f"result = {candidate.source_module}.{candidate.source_function}({payload!r})"


class FunctionParamRequestAdapter:
    """Adapter for request objects passed as function parameters (e.g., request.args.get)."""

    kind = "http_param_func"
    priority = 90

    _KEY_RE = re.compile(r"\.(args|GET|POST|form)\.(get|getlist)\([\"\'](\w+)")

    def can_handle(self, source: ProgramPoint, candidate: VulnerabilityCandidate) -> bool:
        expr = source.expression
        return ".args.get(" in expr or ".GET.get(" in expr or ".form.get(" in expr or ".POST.get(" in expr

    def _extract_key(self, source: ProgramPoint) -> str:
        m = self._KEY_RE.search(source.expression)
        return m.group(3) if m else "q"

    def generate_setup(self, source: ProgramPoint, sentinel: str, is_exploit: bool, candidate: VulnerabilityCandidate, payload: str) -> str:
        key = self._extract_key(source)
        return f"""class _MockArgs:
    @staticmethod
    def get(name, default=''):
        if name == {key!r}:
            return {payload!r}
        return default

class _MockRequest:
    args = _MockArgs()
"""

    def generate_invocation(self, source: ProgramPoint, sentinel: str, is_exploit: bool, candidate: VulnerabilityCandidate, payload: str) -> str:
        return f"result = {candidate.source_module}.{candidate.source_function}(_MockRequest())"


class FlaskRequestParamAdapter:
    """Adapter for Flask's module-level request proxy."""

    kind = "http_param_flask"
    priority = 100

    _KEY_RE = re.compile(r"\.(args|form)\.(get|getlist)\([\"\'](\w+)")

    def can_handle(self, source: ProgramPoint, candidate: VulnerabilityCandidate) -> bool:
        if candidate.source_is_parameter:
            return False
        expr = source.expression
        return "request.args" in expr or "request.form" in expr or "flask.request" in expr

    def _extract_key(self, source: ProgramPoint) -> str:
        m = self._KEY_RE.search(source.expression)
        return m.group(3) if m else "q"

    def generate_setup(self, source: ProgramPoint, sentinel: str, is_exploit: bool, candidate: VulnerabilityCandidate, payload: str) -> str:
        return """from flask import Flask
_test_app = Flask(__name__)
_test_app.config['TESTING'] = True
"""

    def generate_invocation(self, source: ProgramPoint, sentinel: str, is_exploit: bool, candidate: VulnerabilityCandidate, payload: str) -> str:
        key = self._extract_key(source)
        # URL-encode the payload naively for the query string.
        import urllib.parse
        encoded = urllib.parse.quote(payload, safe='')
        return f"""with _test_app.test_request_context('/?{key}={encoded}'):
    import {candidate.source_module}
    result = {candidate.source_module}.{candidate.source_function}()
"""


class FlaskRequestBodyAdapter:
    """Adapter for Flask request.json / request.data."""

    kind = "http_body_flask"
    priority = 100

    def can_handle(self, source: ProgramPoint, candidate: VulnerabilityCandidate) -> bool:
        if candidate.source_is_parameter:
            return False
        expr = source.expression
        return "request.json" in expr or "request.data" in expr

    def generate_setup(self, source: ProgramPoint, sentinel: str, is_exploit: bool, candidate: VulnerabilityCandidate, payload: str) -> str:
        return """from flask import Flask
_test_app = Flask(__name__)
_test_app.config['TESTING'] = True
"""

    def generate_invocation(self, source: ProgramPoint, sentinel: str, is_exploit: bool, candidate: VulnerabilityCandidate, payload: str) -> str:
        return f"""with _test_app.test_request_context('/', json={payload!r}):
    import {candidate.source_module}
    result = {candidate.source_module}.{candidate.source_function}()
"""


class CLIArgAdapter:
    """Adapter for direct sys.argv indexing."""

    kind = "cli_arg"
    priority = 80

    def can_handle(self, source: ProgramPoint, candidate: VulnerabilityCandidate) -> bool:
        return "sys.argv" in source.expression

    def generate_setup(self, source: ProgramPoint, sentinel: str, is_exploit: bool, candidate: VulnerabilityCandidate, payload: str) -> str:
        return f"import sys\nsys.argv = ['prog', {payload!r}]"

    def generate_invocation(self, source: ProgramPoint, sentinel: str, is_exploit: bool, candidate: VulnerabilityCandidate, payload: str) -> str:
        return f"import {candidate.source_module}\nresult = {candidate.source_module}.{candidate.source_function}()"


class EnvVarAdapter:
    """Adapter for os.environ / os.getenv sources."""

    kind = "env_var"
    priority = 80

    _VAR_RE = re.compile(r"(?:environ|getenv)\([\"\'](\w+)")

    def can_handle(self, source: ProgramPoint, candidate: VulnerabilityCandidate) -> bool:
        return "os.environ" in source.expression or "os.getenv" in source.expression

    def _extract_var(self, source: ProgramPoint) -> str:
        m = self._VAR_RE.search(source.expression)
        return m.group(1) if m else "VAR"

    def generate_setup(self, source: ProgramPoint, sentinel: str, is_exploit: bool, candidate: VulnerabilityCandidate, payload: str) -> str:
        var = self._extract_var(source)
        return f"import os\nos.environ[{var!r}] = {payload!r}"

    def generate_invocation(self, source: ProgramPoint, sentinel: str, is_exploit: bool, candidate: VulnerabilityCandidate, payload: str) -> str:
        return f"import {candidate.source_module}\nresult = {candidate.source_module}.{candidate.source_function}()"


class FileReadAdapter:
    """Adapter for module-level file reads."""

    kind = "file_read"
    priority = 80

    def can_handle(self, source: ProgramPoint, candidate: VulnerabilityCandidate) -> bool:
        return "open(" in source.expression or "read_text(" in source.expression

    def generate_setup(self, source: ProgramPoint, sentinel: str, is_exploit: bool, candidate: VulnerabilityCandidate, payload: str) -> str:
        return f"""_SENTINEL_PATH = {payload!r}
with open(_SENTINEL_PATH, 'w') as _f:
    _f.write({sentinel!r})
"""

    def generate_invocation(self, source: ProgramPoint, sentinel: str, is_exploit: bool, candidate: VulnerabilityCandidate, payload: str) -> str:
        return f"import {candidate.source_module}\nresult = {candidate.source_module}.{candidate.source_function}({payload!r})"


class UserInputAdapter:
    """Adapter for builtins.input()."""

    kind = "user_input"
    priority = 80

    def can_handle(self, source: ProgramPoint, candidate: VulnerabilityCandidate) -> bool:
        return "input(" in source.expression

    def generate_setup(self, source: ProgramPoint, sentinel: str, is_exploit: bool, candidate: VulnerabilityCandidate, payload: str) -> str:
        return f"import builtins\nbuiltins.input = lambda *args, **kwargs: {payload!r}"

    def generate_invocation(self, source: ProgramPoint, sentinel: str, is_exploit: bool, candidate: VulnerabilityCandidate, payload: str) -> str:
        return f"import {candidate.source_module}\nresult = {candidate.source_module}.{candidate.source_function}()"


ADAPTERS: list[SourceAdapter] = [
    FlaskRequestParamAdapter(),
    FlaskRequestBodyAdapter(),
    FunctionParamRequestAdapter(),
    CLIArgAdapter(),
    EnvVarAdapter(),
    FileReadAdapter(),
    UserInputAdapter(),
    GenericFunctionParamAdapter(),
]


def select_adapter(candidate: VulnerabilityCandidate) -> SourceAdapter | None:
    """Select the highest-priority adapter that can handle the candidate's source."""
    matches = [a for a in ADAPTERS if a.can_handle(candidate.source, candidate)]
    if not matches:
        return None
    matches.sort(key=lambda a: a.priority, reverse=True)
    return matches[0]
