#!/usr/bin/env python3
from __future__ import annotations
import db


def handle_search(request):
    query = request.args.get('q', '')
    return db.search_raw(query)
