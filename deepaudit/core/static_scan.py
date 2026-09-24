from __future__ import annotations
"""Stage 1b: secret-pattern detection that bypasses convergence/proof."""

import re
import uuid
from pathlib import Path
from typing import Any
from deepaudit.models.finding import ProvenFinding, StaticProof
from deepaudit.models.taint import ProgramPoint


PATTERNS = [
    ("aws_access_key_id", r"AKIA[0-9A-Z]{16}"),
    ("aws_secret_access_key", r"(aws_secret_access_key|aws_secret)\s*[=:]\s*['\"'][A-Za-z0-9/+=]{40}['\"']"),
    ("google_api_key", r"AIza[0-9A-Za-z\-_]{35}"),
    ("github_token", r"gh[ps]_[A-Za-z0-9]{36}"),
    ("generic_api_key", r"(api_key|apikey|api-key)\s*[=:]\s*['\"'][^'\"]{20,}['\"']"),
    ("database_url", r"(postgres|postgresql|mysql|mongodb)://[^:\s]+:[^@\s]+@"),
    ("private_key", r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----"),
]

EXCLUDE_DIRS = {"tests", "test", "examples", "docs"}
EXCLUDE_VAR_NAMES = {"test", "example", "dummy", "fake", "sample"}


def _find_variable_name(line: str, match_start: int) -> str | None:
    before = line[:match_start]
    m = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*[=:]\s*$", before)
    return m.group(1) if m else None


def _severity_for_match(file_rel: Path, var_name: str | None) -> str:
    if any(part in EXCLUDE_DIRS for part in file_rel.parts):
        return "low"
    if var_name and any(ex in var_name.lower() for ex in EXCLUDE_VAR_NAMES):
        return "low"
    return "medium"


def scan_repository(repo_path: Path, exclude_dirs: set[str] | None = None, exclude_var_names: set[str] | None = None) -> list[ProvenFinding]:
    """Scan Python files for hardcoded secrets."""
    repo_path = Path(repo_path)
    exclude_dirs = set(EXCLUDE_DIRS) if exclude_dirs is None else exclude_dirs
    exclude_var_names = set(EXCLUDE_VAR_NAMES) if exclude_var_names is None else exclude_var_names
    findings: list[ProvenFinding] = []

    for path in sorted(repo_path.rglob("*.py")):
        rel_parts = path.relative_to(repo_path).parts
        if any(part in exclude_dirs or part in {"__pycache__", ".git", ".venv", "venv", "env"} for part in rel_parts):
            continue
        rel = path.relative_to(repo_path)
        try:
            text = path.read_text(encoding="utf-8")
            lines = text.splitlines()
        except Exception:
            continue
        for line_no, line in enumerate(lines, start=1):
            for pattern_id, regex in PATTERNS:
                for match in re.finditer(regex, line):
                    var_name = _find_variable_name(line, match.start())
                    if var_name and any(ex in var_name.lower() for ex in exclude_var_names):
                        continue
                    point = ProgramPoint(
                        file=str(rel),
                        line=line_no,
                        column=match.start(),
                        expression=match.group(0),
                        function="<module>",
                    )
                    severity = _severity_for_match(rel, var_name)
                    findings.append(
                        ProvenFinding(
                            finding_id=uuid.uuid4().hex,
                            exploit_class="secrets_in_code",
                            severity=severity,
                            source=point,
                            sink=point,
                            cross_file_path=[point],
                            sanitizers_on_path=[],
                            cross_file=False,
                            convergence=None,
                            reproduction=StaticProof(
                                evidence_description=f"Hardcoded secret matched pattern {pattern_id}",
                                evidence_location=point,
                                pattern_matched=match.group(0),
                                pattern_id=pattern_id,
                            ),
                            fix_suggestion="Move secret to an environment variable or secret manager.",
                            provenance={},
                        )
                    )

    return findings
