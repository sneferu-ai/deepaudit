"""Canonical module-name derivation — ONE source of truth.

Before this, repo_map used a full dotted path (``flask.json``) while the frontend,
sources, sinks, and sanitizers each rolled their own ``Path(filename).stem``
(``__init__``). They agreed on FLAT fixtures (one dir) but diverged on any nested
package, so qualified names didn't match and ``build_repo_model`` crashed on real
code (KeyError ``__init__.dumps`` scanning flask/json/__init__.py). All five now
call this.
"""
from __future__ import annotations

from pathlib import Path


def module_name_from_path(filename: str) -> str:
    """Dotted module name from a repo-relative path.

    ``flask/json/__init__.py`` -> ``flask.json`` (a package's ``__init__`` IS the
    package); ``flask/app.py`` -> ``flask.app``; ``app.py`` -> ``app`` (flat layout,
    byte-identical to the old ``.stem`` so fixtures are unaffected).
    """
    parts = Path(filename).with_suffix("").parts
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)
