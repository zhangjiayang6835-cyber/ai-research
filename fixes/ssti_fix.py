"""
Fix for Issue #13 — SSTI in Error Page
=======================================

Vulnerability
-------------
Error page renders user-supplied ``msg`` parameter directly into a
Jinja2 template via ``render_template_string()``, allowing server-side
template injection attacks.

Fix Strategy
------------
1. Never use ``render_template_string()`` with user input.
2. Use proper template escaping with ``Markup()`` or ``escape()``.
3. Pre-define templates outside the request handler.
"""

from __future__ import annotations

from markupsafe import escape


def safe_error_message(msg: str) -> str:
    """
    Safely escape user input for display in HTML.
    
    Args:
        msg: Raw user-supplied message string.
    
    Returns:
        HTML-escaped string safe for display.
    """
    return escape(msg)
