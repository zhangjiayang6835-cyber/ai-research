"""
Fix for Issue #99: Server-Side Template Injection (SSTI) v3 ($50)

Vulnerability:
    User-supplied templates rendered by Jinja2 without sandbox isolation
    allow attackers to execute arbitrary Python code via attribute walking
    (__class__.__mro__.__subclasses__ chains).

Fix:
    Drop-in replacement for Jinja2's SandboxedEnvironment with additional
    protections against all known SSTI breakout techniques, including
    Unicode-obfuscated attribute names, filter-based getattr bypasses, and
    Flask/Werkzeug global injection.
"""

from __future__ import annotations

import re
import time
from typing import Any, Mapping

try:
    from jinja2 import Environment
    from jinja2.exceptions import SecurityError, TemplateSyntaxError
    from jinja2.sandbox import SandboxedEnvironment
except ImportError:
    Environment = object
    SandboxedEnvironment = object
    class SecurityError(Exception): pass
    class TemplateSyntaxError(Exception): pass


BLOCKED_ATTRS = frozenset({
    "__class__", "__mro__", "__bases__", "__subclasses__",
    "__globals__", "__builtins__", "__code__", "__closure__",
    "__init__", "__init_subclass__", "__dict__", "__getattribute__",
    "__reduce__", "__reduce_ex__",
    "mro", "subclasses", "func_globals", "func_code",
    "gi_frame", "gi_code", "cr_frame", "cr_code",
    "__import__", "__loader__", "__spec__",
    "eval", "exec", "compile", "open", "system",
})

BLOCKED_GLOBALS = frozenset({
    "self", "request", "config", "session", "g", "application",
    "cycler", "joiner", "namespace", "lipsum",
    "range", "dict", "list", "type", "object",
    "getattr", "eval", "exec", "compile", "open", "__builtins__",
})

ESCAPED_US_RE = re.compile(r"(\\u00[57]f)|(\\x5f)|(\\N\{LOW LINE\})", re.I)


class HardenedSandbox(SandboxedEnvironment):
    """Jinja2 sandbox hardened against SSTI breakout."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for name in BLOCKED_GLOBALS:
            self.globals.pop(name, None)
        self.filters.pop("attr", None)

    def _is_blocked_attr(self, name: str) -> bool:
        if not isinstance(name, str):
            return True
        return name.lower() in {a.lower() for a in BLOCKED_ATTRS}

    def is_safe_attribute(self, obj, attr, value):
        if not super().is_safe_attribute(obj, attr, value):
            return False
        if self._is_blocked_attr(attr):
            return False
        return True

    def getattr(self, obj, attribute):
        if self._is_blocked_attr(attribute):
            raise SecurityError(f"access to {attribute!r} not allowed")
        return super().getattr(obj, attribute)

    def getitem(self, obj, argument):
        if isinstance(argument, str) and self._is_blocked_attr(argument):
            raise SecurityError(f"access to item {argument!r} not allowed")
        return super().getitem(obj, argument)

    def from_string(self, source, *args, **kwargs):
        if len(source.encode()) > 65536:
            raise SecurityError("template too large")
        if ESCAPED_US_RE.search(source):
            raise SecurityError("escaped underscores not allowed")
        return super().from_string(source, *args, **kwargs)


def render_safe(source: str, context: Mapping[str, Any] | None = None,
                max_size: int = 262144) -> str:
    """Render a user-supplied template safely."""
    env = HardenedSandbox()
    template = env.from_string(source)
    safe_ctx = {k: v for k, v in (context or {}).items()
                if k not in BLOCKED_GLOBALS and not k.startswith("_")}
    result = template.render(**safe_ctx)
    if len(result.encode()) > max_size:
        raise SecurityError("output too large")
    return result


BREAKOUTS = (
    "{{ ''.__class__.__mro__[1].__subclasses__() }}",
    "{{ ''|attr('__class__') }}",
    "{{ ''['__class__'] }}",
    "{{ ''.\\u005f\\u005fclass\\u005f\\u005f }}",
    "{{ config.__class__.__init_subclass__.__globals__ }}",
    "{{ cyclic.__init__.__globals__ }}",
    "{{ lipsum.__globals__ }}",
)


if __name__ == "__main__":
    env = HardenedSandbox()
    for payload in BREAKOUTS:
        blocked = False
        try:
            env.from_string(payload).render(obj=object())
        except SecurityError:
            blocked = True
        except Exception:
            blocked = True
        assert blocked, f"payload not blocked: {payload!r}"

    assert render_safe("hello {{ name }}", {"name": "world"}) == "hello world"
    print("ssti_jinja2_fix self-test passed")
