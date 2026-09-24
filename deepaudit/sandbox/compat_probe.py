#!/usr/bin/env python3
from __future__ import annotations
"""Compatibility shims for sandboxed execution."""

from pathlib import Path


def compatibility_pre_imports(target_dir: Path) -> str:
    """Return any pre-import compatibility code needed in the harness."""
    return ""
