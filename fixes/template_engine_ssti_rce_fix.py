"""Safe template rendering boundary for issue #109.

The vulnerable pattern is passing attacker-controlled strings into a template
engine, where syntax such as ``{{ config.__class__.__mro__ }}`` can become code
execution. This module keeps template source in a trusted server-side registry
and treats all user input as escaped scalar data for simple placeholders only.
"""

from __future__ import annotations

import html
import re
import string
from dataclasses import dataclass
from typing import Any, Mapping


TEMPLATE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
FIELD_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$")
MAX_VALUE_CHARS = 10_000


class TemplatePolicyError(ValueError):
    """Raised when a template or render context violates the safe policy."""


@dataclass(frozen=True)
class TrustedTemplate:
    source: str
    required_fields: frozenset[str]


class SafeTemplateRenderer:
    """Render only trusted templates with escaped scalar user data."""

    def __init__(self, templates: Mapping[str, str]) -> None:
        self._templates = {
            template_id: TrustedTemplate(source, _extract_required_fields(source))
            for template_id, source in templates.items()
            if _validate_template_id(template_id)
        }
        if len(self._templates) != len(templates):
            raise TemplatePolicyError("all template ids must be safe registry ids")

    def render(self, template_id: str, context: Mapping[str, Any]) -> str:
        if not _validate_template_id(template_id):
            raise TemplatePolicyError("template id must be a safe registry id")
        template = self._templates.get(template_id)
        if template is None:
            raise TemplatePolicyError("unknown template id")
        safe_context = _sanitize_context(context, template.required_fields)
        return template.source.format_map(safe_context)


def _extract_required_fields(source: str) -> frozenset[str]:
    if not isinstance(source, str) or not source:
        raise TemplatePolicyError("template source must be non-empty text")
    fields: set[str] = set()
    formatter = string.Formatter()
    for _literal, field_name, format_spec, conversion in formatter.parse(source):
        if field_name is None:
            continue
        if not FIELD_NAME_RE.fullmatch(field_name):
            raise TemplatePolicyError("template fields must be simple placeholder names")
        if conversion is not None or format_spec:
            raise TemplatePolicyError("conversions and format specs are not allowed")
        fields.add(field_name)
    return frozenset(fields)


def _sanitize_context(context: Mapping[str, Any], required_fields: frozenset[str]) -> dict[str, str]:
    if not isinstance(context, Mapping):
        raise TemplatePolicyError("context must be a mapping")
    supplied = set(context)
    invalid_keys = {key for key in supplied if not isinstance(key, str) or not FIELD_NAME_RE.fullmatch(key)}
    if invalid_keys:
        raise TemplatePolicyError("context keys must be simple placeholder names")
    missing = required_fields - supplied
    if missing:
        raise TemplatePolicyError("missing template context")
    unexpected = supplied - required_fields
    if unexpected:
        raise TemplatePolicyError("unexpected template context")
    return {key: _escape_scalar(context[key]) for key in required_fields}


def _escape_scalar(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        text = "true" if value else "false"
    elif isinstance(value, (str, int, float)):
        text = str(value)
    else:
        raise TemplatePolicyError("context values must be scalar data")
    if len(text) > MAX_VALUE_CHARS:
        raise TemplatePolicyError("context value is too large")
    return html.escape(text, quote=True)


def _validate_template_id(template_id: str) -> bool:
    return isinstance(template_id, str) and TEMPLATE_ID_RE.fullmatch(template_id) is not None


__all__ = ["SafeTemplateRenderer", "TemplatePolicyError", "TrustedTemplate"]
