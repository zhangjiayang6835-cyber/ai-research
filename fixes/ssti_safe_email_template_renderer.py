"""
Fix for issue #63: Server-Side Template Injection in email templates.

The unsafe pattern is compiling attacker-controlled text as a template.  In
engines such as Jinja2, payloads like ``{{ config.__class__.__init__.__globals__ }}``
can turn a harmless email preview into object introspection and, in real web
apps, file read or RCE.

This module replaces that pattern with a small, dependency-free renderer:

* callers select a trusted template by stable template id;
* user values are accepted only as scalar data;
* every rendered value is HTML-escaped before insertion;
* template placeholders are limited to simple names such as ``{first_name}``;
* path traversal, dotted attribute access, item lookup, conversions, and format
  specs are rejected up front.

Because user input is never parsed as template code, SSTI payloads render as
literal escaped text instead of being evaluated.
"""

from __future__ import annotations

import datetime as _dt
import html
import string
from dataclasses import dataclass
from typing import Any, Mapping


class TemplateRenderError(ValueError):
    """Base class for safe-rendering policy errors."""


class UnknownTemplateError(TemplateRenderError):
    """Raised when a caller requests a template id that is not trusted."""


class UnsafeTemplateError(TemplateRenderError):
    """Raised when a trusted template contains an unsafe placeholder."""


class UnsafeContextError(TemplateRenderError):
    """Raised when caller-supplied data cannot be safely rendered."""


_ALLOWED_ID_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789_-")
_ALLOWED_VALUE_TYPES = (str, int, float, bool, type(None), _dt.date, _dt.datetime)


@dataclass(frozen=True)
class TrustedTemplate:
    """A static template owned by the application, not by the request."""

    template_id: str
    body_html: str


class _EscapedContext(dict[str, str]):
    def __missing__(self, key: str) -> str:
        raise UnsafeContextError(f"missing required template value: {key}") from None


def _validate_template_id(template_id: str) -> None:
    if not isinstance(template_id, str) or not template_id:
        raise UnknownTemplateError("template id must be a non-empty string")
    if len(template_id) > 64:
        raise UnknownTemplateError("template id is too long")
    if template_id.startswith(("-", "_")) or template_id.endswith(("-", "_")):
        raise UnknownTemplateError("template id has an invalid boundary character")
    if any(ch not in _ALLOWED_ID_CHARS for ch in template_id):
        raise UnknownTemplateError("template id contains unsafe characters")


def _is_simple_field_name(name: str) -> bool:
    if not name:
        return False
    if not (name[0].isalpha() or name[0] == "_"):
        return False
    return all(ch.isalnum() or ch == "_" for ch in name)


def _validate_template_source(source: str) -> tuple[str, ...]:
    formatter = string.Formatter()
    fields: list[str] = []
    for _literal, field_name, format_spec, conversion in formatter.parse(source):
        if field_name is None:
            continue
        if not _is_simple_field_name(field_name):
            raise UnsafeTemplateError(
                "template placeholders may only be simple names"
            )
        if conversion is not None or format_spec:
            raise UnsafeTemplateError(
                "template conversions and format specs are disabled"
            )
        fields.append(field_name)
    return tuple(dict.fromkeys(fields))


def _escape_context(context: Mapping[str, Any], required_fields: tuple[str, ...]) -> _EscapedContext:
    escaped = _EscapedContext()
    for key, value in context.items():
        if not isinstance(key, str) or not _is_simple_field_name(key):
            raise UnsafeContextError("context keys must be simple field names")
        if not isinstance(value, _ALLOWED_VALUE_TYPES):
            raise UnsafeContextError(
                f"context value for {key!r} must be scalar data"
            )
        escaped[key] = html.escape("" if value is None else str(value), quote=True)

    for field in required_fields:
        if field not in escaped:
            raise UnsafeContextError(f"missing required template value: {field}")
    return escaped


class SafeEmailTemplateRenderer:
    """Render trusted email templates with escaped user data only."""

    def __init__(self, templates: Mapping[str, str | TrustedTemplate]) -> None:
        if not templates:
            raise UnsafeTemplateError("at least one trusted template is required")

        self._templates: dict[str, TrustedTemplate] = {}
        self._required_fields: dict[str, tuple[str, ...]] = {}
        for template_id, template in templates.items():
            _validate_template_id(template_id)
            if isinstance(template, TrustedTemplate):
                if template.template_id != template_id:
                    raise UnsafeTemplateError("template id mismatch")
                body_html = template.body_html
            else:
                body_html = template
            if not isinstance(body_html, str) or not body_html:
                raise UnsafeTemplateError("template body must be non-empty text")

            self._templates[template_id] = TrustedTemplate(template_id, body_html)
            self._required_fields[template_id] = _validate_template_source(body_html)

    def render(self, template_id: str, context: Mapping[str, Any]) -> str:
        """Render a trusted template id with escaped scalar context values."""
        _validate_template_id(template_id)
        template = self._templates.get(template_id)
        if template is None:
            raise UnknownTemplateError(f"unknown template id: {template_id}")

        safe_context = _escape_context(context, self._required_fields[template_id])
        return template.body_html.format_map(safe_context)


DEFAULT_TEMPLATES = {
    "welcome": "<p>Hello {first_name}, welcome to {product_name}.</p>",
    "reset-password": (
        "<p>Hello {first_name}, use this one-time link to reset your password: "
        "<a href=\"{reset_url}\">Reset password</a></p>"
    ),
    "receipt": "<p>Receipt #{receipt_id}: {amount} paid for {description}.</p>",
}


def render_email(template_id: str, context: Mapping[str, Any]) -> str:
    """Convenience wrapper using the application-owned default templates."""
    return SafeEmailTemplateRenderer(DEFAULT_TEMPLATES).render(template_id, context)


def _selftest() -> None:  # pragma: no cover
    payload = "{{ config.__class__.__init__.__globals__['os'].system('id') }}"
    html_body = render_email(
        "welcome",
        {"first_name": payload, "product_name": "<Billing Portal>"},
    )
    assert "{{ config" in html_body
    assert "&lt;Billing Portal&gt;" in html_body
    assert "__globals__" in html_body

    try:
        SafeEmailTemplateRenderer({"bad": "{user.__class__}"})
    except UnsafeTemplateError:
        pass
    else:
        raise AssertionError("unsafe dotted placeholder was accepted")


if __name__ == "__main__":  # pragma: no cover
    _selftest()
    print("ssti_safe_email_template_renderer: self-check passed")
