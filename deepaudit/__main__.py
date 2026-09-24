#!/usr/bin/env python3
from __future__ import annotations
"""Allow `python -m deepaudit`."""

import sys
from deepaudit.cli.main import main

sys.exit(main())
