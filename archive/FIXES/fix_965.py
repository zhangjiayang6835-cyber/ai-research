"""
Fix for Issue #965 — SSTI in Email Template Engine → Sandbox Escape
======================================================================

Vulnerability
-------------
Email template engine uses user input directly: Hello {{user_input}}.
Server uses Jinja2 Sandbox. Attacker can escape sandbox via
__class__.__mro__[1].__subclasses__() chain to achieve RCE.

Fix Strategy
------------
1. Do not expose template engine to users — use precompiled templates.
2. Replace variables only, never render user input as templates.
3. Disable dangerous Jinja2 sandbox escape paths.
"""

from __future__ import annotations

import re
from typing import Any, Final

# Jinja2 sandbox escape patterns to block
SANDBOX_ESCAPE_PATTERNS: Final[list[re.Pattern]] = [
    re.compile(r"__class__"),
    re.compile(r"__mro__"),
    re.compile(r"__subclasses__"),
    re.compile(r"__globals__"),
    re.compile(r"__builtins__"),
    re.compile(r"__init__"),
    re.compile(r"__base__"),
    re.compile(r"__bases__"),
    re.compile(r"__dict__"),
    re.compile(r"_TemplateReference__context"),
    re.compile(r"cycler\.__init__"),
    re.compile(r"joiner\.__init__"),
    re.compile(r"namespace\.__init__"),
    re.compile(r"lipsum\.__init__"),
    re.compile(r"range\.__init__"),
    re.compile(r"\bself\b"),
]


def has_sandbox_escape_pattern(template: str) -> bool:
    """Check if a template contains sandbox escape patterns."""
    for pattern in SANDBOX_ESCAPE_PATTERNS:
        if pattern.search(template):
            return True
    return False


class SafeEmailTemplate:
    """
    Safe email template renderer using precompiled templates with
    variable substitution only — no user-supplied template code.
    """

    def __init__(self, template_text: str):
        """
        Initialize with a precompiled template.

        The template should contain only {{variable}} placeholders.
        No template logic (if/for/filter) is allowed.
        """
        self._validate_template(template_text)
        self._template = template_text
        self._placeholders = re.findall(r"\{\{(\w+)\}\}", template_text)

    def _validate_template(self, template: str) -> None:
        """Validate that the template contains no dangerous constructs."""
        if has_sandbox_escape_pattern(template):
            raise ValueError("Template contains sandbox escape patterns")

        # Block Jinja2 control structures
        if re.search(r"{%\s*(if|for|block|macro|set|include|import|extends)", template):
            raise ValueError("Template contains control structures (not allowed)")

    def render(self, **kwargs: Any) -> str:
        """
        Render the template by replacing {{variables}} with provided values.

        This is safe because it uses simple string replacement, NOT
        Jinja2 template rendering.
        """
        result = self._template
        for key, value in kwargs.items():
            result = result.replace("{{" + key + "}}", str(value))
        return result


def render_email_template(template_text: str, **variables: Any) -> str:
    """
    Render an email template safely.

    Parameters
    ----------
    template_text : str
        Precompiled template with {{variable}} placeholders only.
    **variables : any
        Values to substitute into the template.

    Returns
    -------
    str
        Rendered email body.
    """
    engine = SafeEmailTemplate(template_text)
    return engine.render(**variables)


# ---------------------------------------------------------------------------
# Usage example
# ---------------------------------------------------------------------------

# SAFE: Precompiled template with variable substitution
WELCOME_TEMPLATE = """
Hello {{username}},

Welcome to our platform! Your account has been created.

Best regards,
The Team
"""

# render_email_template(WELCOME_TEMPLATE, username="Alice")
