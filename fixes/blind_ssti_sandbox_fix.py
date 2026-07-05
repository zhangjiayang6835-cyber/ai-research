"""
Fix for Issue #209: Blind RCE via SSTI in a sandboxed environment.

The safe pattern is to avoid evaluating user-controlled template expressions
at all.  A Jinja2 sandbox still parses expressions, filters, attribute access,
function calls, imports, loops, and include tags.  Blind RCE payloads often
produce no visible output, so output-only checks are not enough.

This module provides a small renderer for untrusted templates that supports
only allowlisted scalar placeholders:

    Hello {{ customer_name }}

Everything else is rejected before rendering.  Values are HTML-escaped by
default, callables and object instances are refused from the context, and
obfuscated SSTI tokens are checked after lightweight normalization.
"""

from __future__ import annotations

import html
import re
from dataclasses import dataclass
from typing import Any, Mapping


class SSTISecurityError(ValueError):
    """Raised when an untrusted template or context is unsafe."""


_PLACEHOLDER_RE = re.compile(r"{{\s*([A-Za-z][A-Za-z0-9_]*)\s*}}")
_ANY_MUSTACHE_RE = re.compile(r"{{(.*?)}}", re.DOTALL)
_IDENTIFIER_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$")

_BLOCKED_TEMPLATE_MARKERS = (
    "{%",
    "%}",
    "{#",
    "#}",
    "${",
    "#{",
)

_BLOCKED_STRUCTURAL_TOKENS = frozenset({"__", ".", "[", "]", "(", ")", "|", ";", "`", "\\"})

_BLOCKED_WORD_TOKENS = frozenset(
    {
        "attr",
        "class",
        "mro",
        "subclasses",
        "globals",
        "builtins",
        "import",
        "eval",
        "exec",
        "compile",
        "open",
        "popen",
        "system",
        "os",
        "subprocess",
        "request",
        "config",
        "cycler",
        "joiner",
        "namespace",
        "lipsum",
        "self",
        "application",
        "write",
        "read",
        "sleep",
    }
)

_BLOCKED_TOKENS = _BLOCKED_STRUCTURAL_TOKENS | _BLOCKED_WORD_TOKENS

_SAFE_SCALAR_TYPES = (str, int, float, bool, type(None))


@dataclass(frozen=True)
class RenderPolicy:
    """Controls the narrow syntax accepted for untrusted templates."""

    allowed_placeholders: frozenset[str]
    max_template_bytes: int = 4096
    max_value_bytes: int = 2048
    max_rendered_bytes: int = 8192
    escape_values: bool = True

    @classmethod
    def from_names(cls, names: set[str] | frozenset[str] | list[str] | tuple[str, ...]) -> "RenderPolicy":
        normalized = frozenset(_validate_placeholder_name(name) for name in names)
        if not normalized:
            raise ValueError("at least one placeholder name is required")
        return cls(allowed_placeholders=normalized)


def _validate_placeholder_name(name: str) -> str:
    if not isinstance(name, str) or not _IDENTIFIER_RE.fullmatch(name):
        raise ValueError(f"invalid placeholder name: {name!r}")
    lowered = name.lower()
    if lowered in _BLOCKED_WORD_TOKENS or lowered.startswith("_"):
        raise ValueError(f"unsafe placeholder name: {name!r}")
    return name


def _normalize_probe_text(value: str) -> str:
    """Normalize common SSTI obfuscation without executing anything."""
    text = html.unescape(value)
    text = text.replace("\\u005f", "_").replace("\\U0000005f", "_")
    text = text.replace("\\x5f", "_").replace("\\x5F", "_")
    return text.casefold()


def _contains_ssti_probe_token(value: str) -> bool:
    normalized = _normalize_probe_text(value)
    if any(token in normalized for token in _BLOCKED_STRUCTURAL_TOKENS):
        return True
    words = set(re.findall(r"[a-z_][a-z0-9_]*", normalized))
    return bool(words & _BLOCKED_WORD_TOKENS)


def _assert_safe_template(template: str, policy: RenderPolicy) -> None:
    if not isinstance(template, str):
        raise TypeError("template must be str")
    if len(template.encode("utf-8")) > policy.max_template_bytes:
        raise SSTISecurityError("template is too large")

    normalized = _normalize_probe_text(template)
    for marker in _BLOCKED_TEMPLATE_MARKERS:
        if marker in normalized:
            raise SSTISecurityError("template contains executable block syntax")

    for match in _ANY_MUSTACHE_RE.finditer(template):
        expression = match.group(1).strip()
        normalized_expression = _normalize_probe_text(expression)
        if not _IDENTIFIER_RE.fullmatch(expression):
            raise SSTISecurityError("template contains non-placeholder expression")
        if expression not in policy.allowed_placeholders:
            raise SSTISecurityError(f"placeholder not allowed: {expression}")
        if _contains_ssti_probe_token(normalized_expression):
            raise SSTISecurityError("template contains SSTI probe token")

    stripped = _ANY_MUSTACHE_RE.sub("", template)
    if "{{" in stripped or "}}" in stripped:
        raise SSTISecurityError("template contains malformed placeholder syntax")


def _coerce_context(policy: RenderPolicy, context: Mapping[str, Any]) -> dict[str, str]:
    if not isinstance(context, Mapping):
        raise TypeError("context must be a mapping")

    safe: dict[str, str] = {}
    for name in policy.allowed_placeholders:
        if name not in context:
            raise SSTISecurityError(f"missing placeholder value: {name}")

        value = context[name]
        if callable(value) or not isinstance(value, _SAFE_SCALAR_TYPES):
            raise SSTISecurityError(f"unsafe context value for: {name}")

        text = "" if value is None else str(value)
        if len(text.encode("utf-8")) > policy.max_value_bytes:
            raise SSTISecurityError(f"context value too large for: {name}")

        safe[name] = html.escape(text, quote=True) if policy.escape_values else text

    extra_names = set(context) - policy.allowed_placeholders
    if extra_names:
        raise SSTISecurityError("context contains non-allowlisted values")

    return safe


def render_untrusted_template(template: str, context: Mapping[str, Any], policy: RenderPolicy) -> str:
    """Render a user-controlled template with strict placeholder interpolation.

    This intentionally rejects Jinja2-like expressions.  It should be used at
    the boundary where user-authored text enters a server-rendered view, email,
    or notification.
    """
    _assert_safe_template(template, policy)
    safe_context = _coerce_context(policy, context)

    def replace(match: re.Match[str]) -> str:
        return safe_context[match.group(1)]

    rendered = _PLACEHOLDER_RE.sub(replace, template)
    if len(rendered.encode("utf-8")) > policy.max_rendered_bytes:
        raise SSTISecurityError("rendered output is too large")
    return rendered


def render_with_allowed_names(
    template: str,
    context: Mapping[str, Any],
    allowed_names: set[str] | frozenset[str] | list[str] | tuple[str, ...],
) -> str:
    """Convenience wrapper for one-shot rendering."""
    return render_untrusted_template(template, context, RenderPolicy.from_names(allowed_names))


def is_probable_ssti_probe(template: str) -> bool:
    """Return True for payloads that should never enter a sandbox renderer."""
    if not isinstance(template, str):
        return False
    normalized = _normalize_probe_text(template)
    if any(marker in normalized for marker in _BLOCKED_TEMPLATE_MARKERS):
        return True
    for match in _ANY_MUSTACHE_RE.finditer(template):
        expression = _normalize_probe_text(match.group(1))
        if _contains_ssti_probe_token(expression):
            return True
        if not _IDENTIFIER_RE.fullmatch(match.group(1).strip()):
            return True
    return False


def _demo() -> None:
    policy = RenderPolicy.from_names(["name", "plan"])
    rendered = render_untrusted_template(
        "Hello {{ name }}, your {{ plan }} plan is active.",
        {"name": "<Ada>", "plan": "Pro"},
        policy,
    )
    assert rendered == "Hello &lt;Ada&gt;, your Pro plan is active."

    blocked = "{{ ''.__class__.__mro__[1].__subclasses__() }}"
    assert is_probable_ssti_probe(blocked)
    try:
        render_untrusted_template(blocked, {"name": "Ada", "plan": "Pro"}, policy)
    except SSTISecurityError:
        return
    raise AssertionError("SSTI payload was not blocked")


if __name__ == "__main__":
    _demo()
