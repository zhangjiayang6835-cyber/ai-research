"""
Fix for Issue #1345 — SSTI in Email Template Engine → Sandbox Escape
=====================================================================

Vulnerability
-------------
The email template engine renders user-supplied content using Jinja2's
``render_template_string`` or ``Template(string)`` without proper
sandboxing. An attacker who controls email template content can inject
Jinja2 expressions to achieve Server-Side Template Injection (SSTI)
and potentially escape the sandbox to execute arbitrary Python code.

SSTI → RCE example:
    {{ config.__class__.__init__.__globals__['os'].popen('id').read() }}

Fix Strategy
------------
1. Use Jinja2's ``ImmutableSandboxedEnvironment`` for template rendering.
2. Strip / escape Jinja2 template syntax from user-controlled inputs.
3. Clear all dangerous builtins, globals, and filters in the sandbox.
4. Remove access to ``__class__``, ``__base__``, ``__subclasses__``,
   ``__globals__``, ``__builtins__`` from template context.
5. Provide a safe ``render_email_template`` wrapper.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Optional

from jinja2 import (
    BaseLoader,
    Environment,
    ImmutableSandboxedEnvironment,
    TemplateError,
    UndefinedError,
)


# ── Configuration ─────────────────────────────────────────────────────

# Regex to detect Jinja2 template syntax
_TEMPLATE_SYNTAX_RE = re.compile(r"\{\{.*?\}\}|\{%.*?%\}|\{#.*?#\}")

# Keys/attributes that are dangerous in SSTI context
_DANGEROUS_ATTRS = frozenset({
    "__class__",
    "__base__",
    "__subclasses__",
    "__globals__",
    "__builtins__",
    "__init__",
    "__mro__",
    "__bases__",
})

# Builtins that are dangerous in template context
_DANGEROUS_BUILTINS = frozenset({
    "eval",
    "exec",
    "open",
    "compile",
    "__import__",
    "getattr",
    "setattr",
    "delattr",
})

# Modules that should not be accessible from templates
_DANGEROUS_MODULES = frozenset({
    "os",
    "subprocess",
    "sys",
    "shutil",
    "socket",
    "requests",
    "importlib",
})


class SSTISecurityError(Exception):
    """Raised when SSTI attempt is detected or blocked."""


class SandboxEscapeError(Exception):
    """Raised when a potential sandbox escape is detected."""


# ── Template Syntax Detection ────────────────────────────────────────

def contains_template_syntax(text: str) -> bool:
    """Check if text contains Jinja2 template syntax.

    Args:
        text: The text to check.

    Returns:
        True if template syntax is detected.
    """
    return bool(_TEMPLATE_SYNTAX_RE.search(text))


# ── Sandboxed Environment Factory ────────────────────────────────────

def create_sandboxed_env() -> ImmutableSandboxedEnvironment:
    """Create a Jinja2 sandboxed environment with all dangerous
    builtins and attributes removed.

    Returns:
        A configured ``ImmutableSandboxedEnvironment`` instance.
    """
    env = ImmutableSandboxedEnvironment(
        loader=BaseLoader(),
        autoescape=True,
    )

    # Clear all builtins to prevent access to dangerous functions
    env.globals.clear()
    env.filters.clear()
    env.tests.clear()

    # Add only safe builtins
    env.globals["range"] = range
    env.globals["lipsum"] = __import__("jinja2").utils.generate_lorem_ipsum
    env.globals["dict"] = dict
    env.globals["list"] = list
    env.globals["tuple"] = tuple
    env.globals["true"] = True
    env.globals["false"] = False
    env.globals["none"] = None

    # Add only safe filters
    env.filters["upper"] = str.upper
    env.filters["lower"] = str.lower
    env.filters["capitalize"] = str.capitalize
    env.filters["title"] = str.title
    env.filters["trim"] = str.strip
    env.filters["escape"] = __import__("markupsafe").escape
    env.filters["e"] = __import__("markupsafe").escape

    return env


# ── Template Sandbox Query Check ─────────────────────────────────────

def _check_template_for_sandbox_escape(template_source: str) -> None:
    """Check a template source for known sandbox escape patterns.

    Args:
        template_source: The raw template string.

    Raises:
        SandboxEscapeError: If an escape pattern is detected.
    """
    # Check for dangerous attribute access
    for attr in _DANGEROUS_ATTRS:
        if attr in template_source.lower():
            raise SandboxEscapeError(
                f"Potential sandbox escape detected: "
                f"template references '{attr}'"
            )

    # Check for dangerous builtins
    for builtin in _DANGEROUS_BUILTINS:
        # Match builtin names that appear as function calls or lookups
        pattern = rf"['\"']?{builtin}['\"']?\s*[\(\[\]]"
        if re.search(pattern, template_source):
            raise SandboxEscapeError(
                f"Potential sandbox escape detected: "
                f"template references '{builtin}'"
            )

    # Check for dangerous module references
    for module in _DANGEROUS_MODULES:
        if module in template_source.lower():
            raise SandboxEscapeError(
                f"Potential sandbox escape detected: "
                f"template references module '{module}'"
            )


# ── Safe Template Rendering ──────────────────────────────────────────

# Pre-created sandbox environment (singleton)
_SANDBOX_ENV = create_sandboxed_env()


def render_email_template(
    template_body: str,
    context: Optional[Dict[str, Any]] = None,
    sandbox_check: bool = True,
) -> str:
    """Safely render an email template with sandbox protection.

    This is the PRIMARY entry point for all email template rendering.
    It uses a hardened Jinja2 sandbox with all dangerous features
    removed.

    Args:
        template_body: The Jinja2 template string.
        context: Optional template variables dict.
        sandbox_check: If True (default), perform pre-render
            sandbox escape detection.

    Returns:
        The rendered template string.

    Raises:
        SSTISecurityError: If an SSTI attempt is detected.
        SandboxEscapeError: If a sandbox escape pattern is found.
        TemplateError: If the template has syntax errors.
    """
    if context is None:
        context = {}

    # Pre-render sandbox escape check
    if sandbox_check:
        _check_template_for_sandbox_escape(template_body)

    try:
        template = _SANDBOX_ENV.from_string(template_body)
        result = template.render(**context)
        return result

    except UndefinedError as e:
        raise SSTISecurityError(
            f"Template references undefined variable: {e}"
        ) from e
    except TemplateError as e:
        raise SSTISecurityError(
            f"Template rendering error: {e}"
        ) from e


# ── User Input Escaping ──────────────────────────────────────────────

def escape_template_input(text: str) -> str:
    """Escape Jinja2 template syntax in user-controlled text.

    Replaces ``{{ }}``, ``{% %}``, and ``{# #}`` with HTML-escaped
    equivalents so they are rendered as literal text rather than
    executed as template expressions.

    Args:
        text: The user-controlled text to escape.

    Returns:
        Text with template syntax HTML-escaped.
    """
    def _escape_match(m: re.Match) -> str:
        match = m.group(0)
        # Escape the braces to HTML entities so Jinja2 renders them literally
        return match.replace("{", "&#123;").replace("}", "&#125;")

    return _TEMPLATE_SYNTAX_RE.sub(_escape_match, text)


# ── Unsafe Detection (for monitoring / alerting) ─────────────────────

def is_probable_ssti_probe(text: str) -> bool:
    """Check if text looks like an SSTI probe payload.

    Useful for monitoring and alerting on potential attacks.

    Args:
        text: The text to check.

    Returns:
        True if the text resembles an SSTI probe.
    """
    probes = [
        r"\{\{.*?config.*?\}\}",
        r"\{\{.*?class.*?\}\}",
        r"\{\{.*?mro.*?\}\}",
        r"\{\{.*?subclasses.*?\}\}",
        r"\{\{.*?popen.*?\}\}",
        r"\{\{.*?builtins.*?\}\}",
        r"\{\{.*?import.*?\}\}",
        r"\{\{.*?os\..*?\}\}",
        r"\{\{.*?eval\(.*?\}\}",
        r"\{\{.*?exec\(.*?\}\}",
        r"\{\{.*?open\(.*?\}\}",
    ]
    for pattern in probes:
        if re.search(pattern, text, re.IGNORECASE):
            return True
    return False
