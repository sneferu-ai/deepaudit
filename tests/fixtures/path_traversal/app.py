#!/usr/bin/env python3
from __future__ import annotations
import reader


def handle_file(request):
    path = request.args.get('file', '')
    return reader.read_file(path)
