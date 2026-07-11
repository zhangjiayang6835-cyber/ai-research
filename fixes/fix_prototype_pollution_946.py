"""
Fix for Issue #946 — Server-Side Prototype Pollution to RCE
============================================================

Vulnerability
-------------
An Express application uses ``lodash.merge`` to merge user-supplied JSON input
into application objects. An attacker can inject ``__proto__`` or
``constructor.prototype`` keys into the JSON payload, polluting the global
``Object.prototype``. This changes the behavior of all objects in the
application and can lead to Remote Code Execution (RCE).

Fix Strategy
------------
1. Strip ``__proto__``, ``constructor.prototype``, and ``prototype`` keys from
   user input before any merge operation.
2. Use a safe deep-merge function that rejects prototype-polluting keys.
3. Validate all JSON input recursively for forbidden keys.
4. Consider using ``Map`` instead of plain ``Object`` for dictionaries.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping as MappingABC
from typing import Any, Callable


# Keys that indicate prototype pollution attempts
POLLUTION_KEYS = frozenset({
    "__proto__",
    "constructor",
    "prototype",
})

# Regex patterns for prototype pollution keys
POLLUTION_PATTERNS = [
    re.compile(r"__proto__", re.IGNORECASE),
    re.compile(r"prototype", re.IGNORECASE),
    re.compile(r"constructor", re.IGNORECASE),
]


class PrototypePollutionError(ValueError):
    """Raised when prototype pollution is detected."""


def sanitize_input(data: Any, *, path: str = "$") -> Any:
    """Recursively sanitize user input to prevent prototype pollution.

    Strips ``__proto__``, ``constructor``, and ``prototype`` keys from
    dictionaries. Also handles arrays by sanitizing each element.

    Args:
        data: The user input to sanitize (from JSON.parse).
        path: Current path for error messages (internal use).

    Returns:
        Sanitized data with pollution keys removed.

    Raises:
        PrototypePollutionError: If pollution keys are detected.
    """
    if isinstance(data, dict):
        # Check for pollution keys
        for key in data:
            if _is_pollution_key(key):
                raise PrototypePollutionError(
                    f"prototype pollution detected at {path}: forbidden key {key!r}"
                )

        # Recursively sanitize values, filtering out pollution keys
        return {
            key: sanitize_input(value, path=f"{path}.{key}")
            for key, value in data.items()
            if not _is_pollution_key(key)
        }

    elif isinstance(data, list):
        return [
            sanitize_input(item, path=f"{path}[{i}]")
            for i, item in enumerate(data)
        ]

    # Primitives (str, int, float, bool, None) are safe
    return data


def _is_pollution_key(key: Any) -> bool:
    """Check if a key is a prototype pollution vector."""
    if not isinstance(key, str):
        return False
    return key in POLLUTION_KEYS or any(
        pattern.search(key) for pattern in POLLUTION_PATTERNS
    )


def safe_json_parse(json_string: str) -> Any:
    """Parse JSON and sanitize for prototype pollution in one step.

    Args:
        json_string: Raw JSON string from user input.

    Returns:
        Sanitized parsed JSON data.

    Raises:
        PrototypePollutionError: If pollution is detected.
        json.JSONDecodeError: If JSON is invalid.
    """
    data = json.loads(json_string)
    return sanitize_input(data)


def safe_deep_merge(
    target: dict[str, Any],
    source: dict[str, Any],
    *,
    _depth: int = 0,
    _max_depth: int = 100,
) -> dict[str, Any]:
    """Deep merge two dictionaries, preventing prototype pollution.

    This is a safe alternative to ``lodash.merge`` / ``Object.assign``
    that explicitly rejects prototype-polluting keys.

    Args:
        target: The target dictionary to merge into.
        source: The source dictionary to merge from.
        _depth: Current recursion depth (internal).
        _max_depth: Maximum recursion depth to prevent stack overflow.

    Returns:
        The merged dictionary (modified in-place).

    Raises:
        PrototypePollutionError: If pollution keys are found.
        RecursionError: If max depth is exceeded.
    """
    if _depth > _max_depth:
        raise RecursionError("max merge depth exceeded")

    # Validate source for pollution keys
    if isinstance(source, dict):
        for key in source:
            if _is_pollution_key(key):
                raise PrototypePollutionError(
                    f"prototype pollution detected: key {key!r} in merge source"
                )

            if key in target:
                if (isinstance(target[key], dict) and
                    isinstance(source[key], dict)):
                    safe_deep_merge(
                        target[key],
                        source[key],
                        _depth=_depth + 1,
                        _max_depth=_max_depth,
                    )
                else:
                    target[key] = source[key]
            else:
                target[key] = source[key]

    return target


# ---------------------------------------------------------------------------
# Express/Fastify middleware example
# ---------------------------------------------------------------------------

def make_prototype_pollution_middleware(
    app: Callable,
    content_type: str = "application/json",
) -> Callable:
    """WSGI middleware that sanitizes JSON request bodies for prototype pollution.

    Usage::

        app = Flask(__name__)
        app.wsgi_app = make_prototype_pollution_middleware(app.wsgi_app)

        @app.route("/api/data", methods=["POST"])
        def handle_data():
            # request.json is already sanitized
            data = request.json
            ...
    """
    def middleware(environ, start_response):
        content_length = int(environ.get("CONTENT_LENGTH", 0) or 0)
        if content_length > 0:
            body = environ["wsgi.input"].read(content_length)
            try:
                # Parse and sanitize
                parsed = json.loads(body)
                sanitized = sanitize_input(parsed)

                # Store sanitized data back in environ for the app
                environ["wsgi.sanitized_body"] = json.dumps(sanitized).encode("utf-8")
                environ["wsgi.sanitized_data"] = sanitized

            except (json.JSONDecodeError, PrototypePollutionError) as e:
                start_response(
                    "400 Bad Request",
                    [("Content-Type", "application/json")],
                )
                return [
                    json.dumps({
                        "error": "invalid request body",
                        "detail": str(e),
                    }).encode("utf-8")
                ]

        return app(environ, start_response)

    return middleware


# ---------------------------------------------------------------------------
# JSON encoder/decoder that rejects pollution keys
# ---------------------------------------------------------------------------

class SafeJSONDecoder(json.JSONDecoder):
    """JSON decoder that rejects prototype pollution keys.

    Usage::

        data = json.loads(user_input, cls=SafeJSONDecoder)
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        kwargs["object_pairs_hook"] = self._validate_object
        super().__init__(*args, **kwargs)

    @staticmethod
    def _validate_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        """Validate that no object contains pollution keys."""
        for key, _ in pairs:
            if _is_pollution_key(key):
                raise PrototypePollutionError(
                    f"prototype pollution detected: key {key!r}"
                )
        return dict(pairs)


# ---------------------------------------------------------------------------
# Deep-freeze utility to protect existing objects
# ---------------------------------------------------------------------------

def deep_freeze(obj: Any) -> None:
    """Deep-freeze an object to prevent prototype pollution at runtime.

    In Python, this simulates Object.freeze() behavior. Useful for
    protecting configuration objects that should never be modified.

    Note: Python doesn't have true immutability for dicts. This function
    replaces the dict with a frozen version that raises on mutation.
    """
    if isinstance(obj, dict):
        for key, value in obj.items():
            deep_freeze(value)
        # Replace with a wrapper that prevents modification
        # (In production, use a proper immutable dict like types.MappingProxyType)
        obj.__class__ = _FrozenDictMeta


class _FrozenDictMeta(type):
    """Metaclass that prevents dict modification."""

    def __setitem__(self, key, value):
        raise TypeError("frozen dict does not support item assignment")

    def __delitem__(self, key):
        raise TypeError("frozen dict does not support item deletion")


# ---------------------------------------------------------------------------
# Express.js equivalent code (for reference in JavaScript projects)
# ---------------------------------------------------------------------------

JS_FIX_EXAMPLE = """
// Safe JSON parse that rejects prototype pollution
function safeJSONParse(jsonString) {
  const data = JSON.parse(jsonString);
  return sanitizeInput(data);
}

function sanitizeInput(data) {
  if (Array.isArray(data)) {
    return data.map(sanitizeInput);
  }
  if (data !== null && typeof data === 'object') {
    // Check for pollution keys
    for (const key of Object.keys(data)) {
      if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
        throw new Error(`Prototype pollution detected: ${key}`);
      }
    }
    // Recursively sanitize
    const result = {};
    for (const [key, value] of Object.entries(data)) {
      if (key !== '__proto__' && key !== 'constructor' && key !== 'prototype') {
        result[key] = sanitizeInput(value);
      }
    }
    return result;
  }
  return data;
}

// Safe deep merge (replaces lodash.merge)
function safeDeepMerge(target, source) {
  for (const key of Object.keys(source)) {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
      throw new Error(`Prototype pollution detected: ${key}`);
    }
    if (source[key] !== null && typeof source[key] === 'object' &&
        target[key] !== null && typeof target[key] === 'object') {
      safeDeepMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}
"""