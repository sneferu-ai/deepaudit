#!/usr/bin/env python3
from __future__ import annotations
import handler


def handle_command(request):
    cmd = request.args.get('cmd', '')
    return handler.run_command(cmd)
