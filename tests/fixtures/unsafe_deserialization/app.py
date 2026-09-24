#!/usr/bin/env python3
from __future__ import annotations
import handler


def handle_upload(request):
    file_path = request.args.get('file', '')
    return handler.load_data(file_path)
