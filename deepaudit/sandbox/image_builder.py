#!/usr/bin/env python3
from __future__ import annotations
"""Minimal image-builder stub for the Docker sandbox."""

from pathlib import Path


class ImageBuilder:
    """Build a Docker image containing the target repository."""

    def __init__(self, repo_path: Path, base_image: str = "python:3.11-slim"):
        self.repo_path = Path(repo_path)
        self.base_image = base_image

    def build(self) -> str:
        """Return the image digest; raise if Docker is unavailable."""
        raise NotImplementedError("Docker sandbox image builder is not implemented in v1.")
