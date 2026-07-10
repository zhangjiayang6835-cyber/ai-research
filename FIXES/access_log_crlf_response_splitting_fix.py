"""Access-log header CRLF injection mitigation.

Issue #791 describes code equivalent to:

    res.setHeader("X-Log", user_agent)

When attacker-controlled User-Agent text is copied directly into an HTTP
response header, CR/LF bytes can split the response and inject new headers.
This module provides a dependency-free replacement that rejects CRLF input by
default and percent-encodes safe values before they are written to X-Log.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import MutableMapping, Protocol
from urllib.parse import quote, unquote


_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_RAW_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_CRLF_RE = re.compile(r"[\r\n]")


class HeaderInjectionError(ValueError):
    """Raised when untrusted input cannot be represented as a safe header."""


class HeaderSetter(Protocol):
    def set_header(self, name: str, value: str) -> None:
        """Set a response header."""


@dataclass(frozen=True)
class AccessLogHeaderPolicy:
    """Policy for converting access-log text into a response header value."""

    header_name: str = "X-Log"
    reject_on_crlf: bool = True
    decode_rounds: int = 3
    safe_chars: str = "-_.!~*'()"
    replacement: str = " "
    blocked_header_names: tuple[str, ...] = field(default_factory=lambda: ("set-cookie",))


def _decode_variants(value: str, rounds: int) -> list[str]:
    """Return raw and repeatedly URL-decoded variants for CRLF detection."""

    variants = [value]
    current = value
    for _ in range(max(0, rounds)):
        decoded = unquote(current)
        if decoded == current:
            break
        variants.append(decoded)
        current = decoded
    return variants


def contains_crlf(value: object, *, decode_rounds: int = 3) -> bool:
    """Detect literal or URL-encoded CR/LF sequences."""

    text = "" if value is None else str(value)
    return any(_CRLF_RE.search(candidate) for candidate in _decode_variants(text, decode_rounds))


def validate_header_name(name: str) -> str:
    """Validate an HTTP field name before writing it to a response."""

    if not name or not _HEADER_NAME_RE.fullmatch(name):
        raise HeaderInjectionError(f"invalid header name: {name!r}")
    return name


def _strip_control_characters(value: str, *, policy: AccessLogHeaderPolicy) -> str:
    """Remove CR/LF and other controls from decoded input."""

    text = value
    for decoded in _decode_variants(value, policy.decode_rounds):
        text = decoded
    text = _RAW_CONTROL_RE.sub(policy.replacement, text)
    text = text.replace("\r", policy.replacement).replace("\n", policy.replacement)
    return " ".join(text.split())


def encode_header_component(value: object, *, policy: AccessLogHeaderPolicy | None = None) -> str:
    """Percent-encode a log fragment using encodeURIComponent-style rules."""

    policy = policy or AccessLogHeaderPolicy()
    text = "" if value is None else str(value)

    if policy.reject_on_crlf and contains_crlf(text, decode_rounds=policy.decode_rounds):
        raise HeaderInjectionError("CRLF detected in access-log header value")

    if contains_crlf(text, decode_rounds=policy.decode_rounds) or _RAW_CONTROL_RE.search(text):
        if policy.reject_on_crlf:
            raise HeaderInjectionError("control character detected in access-log header value")
        text = _strip_control_characters(text, policy=policy)

    encoded = quote(text, safe=policy.safe_chars)
    if contains_crlf(encoded, decode_rounds=0):
        raise HeaderInjectionError("encoded header value still contains CRLF")
    return encoded


def access_log_header_value(user_agent: object, *, policy: AccessLogHeaderPolicy | None = None) -> str:
    """Return the safe value to place in the X-Log response header."""

    return encode_header_component(user_agent, policy=policy)


def set_access_log_header(
    response: MutableMapping[str, str] | HeaderSetter,
    user_agent: object,
    *,
    policy: AccessLogHeaderPolicy | None = None,
) -> str:
    """Safely set the access-log header on a dict-like or set_header response."""

    policy = policy or AccessLogHeaderPolicy()
    header_name = validate_header_name(policy.header_name)
    lower_name = header_name.lower()
    if lower_name in policy.blocked_header_names:
        raise HeaderInjectionError(f"refusing to write sensitive log header: {header_name!r}")

    safe_value = access_log_header_value(user_agent, policy=policy)
    if hasattr(response, "set_header"):
        response.set_header(header_name, safe_value)
    else:
        response[header_name] = safe_value
    return safe_value


__all__ = [
    "AccessLogHeaderPolicy",
    "HeaderInjectionError",
    "access_log_header_value",
    "contains_crlf",
    "encode_header_component",
    "set_access_log_header",
    "validate_header_name",
]
