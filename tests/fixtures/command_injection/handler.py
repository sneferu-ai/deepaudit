#!/usr/bin/env python3
from __future__ import annotations
import os


def run_command(cmd):
    return os.system(f"echo {cmd}")
