#!/usr/bin/env python3
from __future__ import annotations
from deepaudit.templates.sql_injection_read import SQLInjectionReadTemplate
from deepaudit.templates.command_injection_echo import CommandInjectionEchoTemplate
from deepaudit.templates.code_injection_exec import CodeInjectionExecTemplate
from deepaudit.templates.path_traversal_read import PathTraversalReadTemplate
from deepaudit.templates.unsafe_deserialization_pickle import UnsafeDeserializationPickleTemplate
from deepaudit.templates.template_injection_jinja2 import TemplateInjectionJinja2Template
from deepaudit.templates.auth_bypass_direct import AuthBypassDirectTemplate

ALL_TEMPLATES = [
    SQLInjectionReadTemplate(),
    CommandInjectionEchoTemplate(),
    CodeInjectionExecTemplate(),
    PathTraversalReadTemplate(),
    UnsafeDeserializationPickleTemplate(),
    TemplateInjectionJinja2Template(),
    AuthBypassDirectTemplate(),
]
