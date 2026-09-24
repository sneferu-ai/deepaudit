#!/usr/bin/env python3
from __future__ import annotations
"""Probe the sandbox environment for capabilities."""

import importlib.util
import os
from dataclasses import dataclass, field


@dataclass
class EnvironmentProbe:
    has_sqlite: bool = True
    has_docker: bool = False
    has_jinja2: bool = False
    writable_tmp: bool = True
    writable_paths: list[str] = field(default_factory=list)
    installed_packages: set[str] = field(default_factory=set)


def probe_current_environment() -> EnvironmentProbe:
    """Return the capabilities of the current Python environment."""
    has_sqlite = importlib.util.find_spec("sqlite3") is not None
    has_jinja2 = importlib.util.find_spec("jinja2") is not None
    has_docker = False
    try:
        import subprocess

        subprocess.run(["docker", "--version"], capture_output=True, check=True)
        has_docker = True
    except Exception:
        pass
    installed: set[str] = set()
    for pkg in ("sqlite3", "jinja2", "flask"):
        if importlib.util.find_spec(pkg) is not None:
            installed.add(pkg)
    writable_paths: list[str] = []
    if os.access("/tmp", os.W_OK):
        writable_paths.append("/tmp")
    return EnvironmentProbe(
        has_sqlite=has_sqlite,
        has_docker=has_docker,
        has_jinja2=has_jinja2,
        writable_tmp=os.access("/tmp", os.W_OK),
        writable_paths=writable_paths,
        installed_packages=installed,
    )
