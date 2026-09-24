#!/usr/bin/env python3
from __future__ import annotations
import jinja2


def render_template(template_str):
    return jinja2.Template(template_str).render()
