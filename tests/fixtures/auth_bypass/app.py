#!/usr/bin/env python3
from __future__ import annotations
import handler


def handle_auth(request):
    token = request.args.get('token', '')
    return handler.check_auth(token)
