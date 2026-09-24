#!/usr/bin/env python3
from __future__ import annotations
"""Sentinel generation and observation logic."""

import hashlib
import re
import secrets
from pathlib import Path


SENTINEL_RE = re.compile(r"DA-[a-f0-9]{64}")


def make_sentinel() -> str:
    """Generate a cryptographically random 64-character hex sentinel string."""
    return "DA-" + secrets.token_hex(32)


def hash_sentinel(sentinel: str) -> str:
    """Return the full SHA-256 hash of a sentinel."""
    return hashlib.sha256(sentinel.encode()).hexdigest()


def sentinel_in_source(source_code: str, sentinel_hash: str) -> bool:
    """Return True if any sentinel embedded in *source_code* matches *sentinel_hash*."""
    for candidate in set(SENTINEL_RE.findall(source_code)):
        if hash_sentinel(candidate) == sentinel_hash:
            return True
    return False


def check_sentinel(stdout: str, sentinel: str, channels: list[str], stderr: str = "") -> bool:
    """Check whether the sentinel was observed on any declared channel."""
    for channel in channels:
        if channel == "stdout":
            if sentinel in stdout:
                return True
        elif channel.startswith("file:"):
            path = Path(channel.split(":", 1)[1])
            try:
                if path.exists() and sentinel in path.read_text(errors="ignore"):
                    return True
            except Exception:
                pass
        elif channel.startswith("stderr"):
            if sentinel in stderr:
                return True
    return False
