#!/usr/bin/env python3
from __future__ import annotations
import handler


def handle_code(request):
    code = request.args.get('code', '')
    return handler.run_code(code)
