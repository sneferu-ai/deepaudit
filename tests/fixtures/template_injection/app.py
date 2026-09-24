#!/usr/bin/env python3
from __future__ import annotations
import handler


def handle_template(request):
    template_str = request.args.get('template', '')
    return handler.render_template(template_str)
